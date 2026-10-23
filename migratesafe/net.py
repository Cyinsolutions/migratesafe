"""Read-only network helpers: DNS, HTTP and TLS. Nothing here changes remote state."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from . import __version__

USER_AGENT = f"MigrateSafe/{__version__} (+https://doi.org/10.5281/zenodo.23576774)"
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

OK, NXDOMAIN, NOANSWER, DNSERR = "OK", "NXDOMAIN", "NOANSWER", "ERROR"


class Dns:
    def __init__(self, timeout: float = 5.0, nameservers: Optional[List[str]] = None):
        self.timeout = timeout
        self.r = dns.resolver.Resolver(configure=False)
        self.r.nameservers = nameservers or PUBLIC_RESOLVERS
        self.r.lifetime = timeout
        self.r.timeout = timeout / 2
        self._cache: Dict[Tuple[str, str], Tuple[str, List[str]]] = {}

    def lookup(self, name: str, rtype: str) -> Tuple[str, List[str]]:
        key = (name.lower(), rtype)
        if key in self._cache:
            return self._cache[key]
        try:
            ans = self.r.resolve(name, rtype, raise_on_no_answer=False)
            res = (OK, [r.to_text() for r in ans.rrset]) if ans.rrset is not None else (NOANSWER, [])
        except dns.resolver.NXDOMAIN:
            res = (NXDOMAIN, [])
        except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.NoAnswer):
            res = (DNSERR, [])
        self._cache[key] = res
        return res

    def addresses(self, name: str) -> List[str]:
        out = []
        for t in ("A", "AAAA"):
            code, recs = self.lookup(name, t)
            if code == OK:
                out += recs
        return out

    def exists(self, name: str) -> bool:
        """True if the name resolves to anything (used for lookalike detection)."""
        for t in ("NS", "A"):
            code, _ = self.lookup(name, t)
            if code == OK:
                return True
        return False

    # -- direct queries to specific servers (delegation and DNSSEC checks)

    def ask(self, name: str, rtype: str, server: str, recursive: bool = False,
            dnssec: bool = False, ad: bool = False) -> Optional[dns.message.Message]:
        q = dns.message.make_query(name, rtype, want_dnssec=dnssec)
        if not recursive:
            q.flags &= ~dns.flags.RD
        if ad:
            q.flags |= dns.flags.AD
        try:
            resp = dns.query.udp(q, server, timeout=self.timeout)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(q, server, timeout=self.timeout)
            return resp
        except Exception:
            return None

    def first_ip(self, host: str) -> Optional[str]:
        code, recs = self.lookup(host, "A")
        return recs[0] if code == OK and recs else None

    def parent_zone(self, domain: str) -> str:
        parent = domain.split(".", 1)[1] if "." in domain else "."
        return dns.resolver.zone_for_name(parent, resolver=self.r).to_text()

    def parent_delegation(self, domain: str) -> Tuple[List[str], Optional[str]]:
        """NS set for `domain` as published by its parent zone. Returns (ns_list, error)."""
        try:
            pz = self.parent_zone(domain)
        except Exception as e:
            return [], f"cannot find parent zone: {e}"
        code, pns = self.lookup(pz, "NS")
        if code != OK:
            return [], f"cannot resolve NS of parent zone {pz}"
        for ns in pns:
            ip = self.first_ip(ns)
            if not ip:
                continue
            resp = self.ask(domain, "NS", ip)
            if resp is None:
                continue
            names = set()
            for rrset in list(resp.authority) + list(resp.answer):
                if rrset.rdtype == dns.rdatatype.NS and rrset.name.to_text().lower().rstrip(".") == domain:
                    names |= {r.to_text().lower() for r in rrset}
            if names:
                return sorted(names), None
            if resp.rcode() == dns.rcode.NXDOMAIN:
                return [], "parent zone says the domain does not exist"
        return [], "no parent server returned a delegation"

    def authoritative_soa(self, domain: str, ns: str) -> Tuple[bool, str]:
        ip = self.first_ip(ns)
        if not ip:
            return False, f"{ns} has no A record"
        resp = self.ask(domain, "SOA", ip)
        if resp is None:
            return False, f"{ns} ({ip}) did not answer"
        if resp.rcode() != dns.rcode.NOERROR:
            return False, f"{ns} answered {dns.rcode.to_text(resp.rcode())}"
        if not resp.flags & dns.flags.AA:
            return False, f"{ns} is not authoritative (lame delegation)"
        return True, f"{ns} authoritative"

    def dnssec_status(self, domain: str) -> Tuple[bool, bool, str]:
        """(has_ds, validates, note) using a validating public resolver."""
        has_ds = self.lookup(domain, "DS")[0] == OK
        resp = self.ask(domain, "SOA", PUBLIC_RESOLVERS[0], recursive=True, dnssec=True, ad=True)
        if resp is None:
            return has_ds, False, "validating resolver did not answer"
        if resp.rcode() == dns.rcode.SERVFAIL:
            return has_ds, False, "SERVFAIL from validating resolver (possibly bogus DNSSEC)"
        return has_ds, bool(resp.flags & dns.flags.AD), ""


@dataclass
class HttpResp:
    status: int = 0
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: str = ""
    error: Optional[str] = None

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def all(self, name: str) -> List[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]


def http_get(url: str, timeout: float = 10.0, headers: Optional[Dict[str, str]] = None,
             verify: bool = True, max_body: int = 200_000) -> HttpResp:
    """Single GET without following redirects."""
    u = urlsplit(url)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
        h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        h.update(headers or {})
        conn.request("GET", path, headers=h)
        r = conn.getresponse()
        body = r.read(max_body).decode("utf-8", "replace")
        resp = HttpResp(r.status, r.getheaders(), body)
        conn.close()
        return resp
    except Exception as e:
        return HttpResp(error=f"{type(e).__name__}: {e}")


def follow_redirects(url: str, timeout: float = 10.0, max_hops: int = 6,
                     headers: Optional[Dict[str, str]] = None) -> Tuple[List[Tuple[int, str]], HttpResp]:
    chain: List[Tuple[int, str]] = []
    current = url
    resp = HttpResp()
    for _ in range(max_hops):
        resp = http_get(current, timeout, headers=headers)
        if resp.error or resp.status not in (301, 302, 303, 307, 308):
            break
        loc = resp.header("Location") or ""
        if not loc:
            break
        if loc.startswith("/"):
            u = urlsplit(current)
            loc = f"{u.scheme}://{u.netloc}{loc}"
        chain.append((resp.status, loc))
        current = loc
        headers = None  # probe headers only on the first hop
    return chain, resp


@dataclass
class TlsResult:
    ok: bool
    version: Optional[str] = None
    cert: Dict = field(default_factory=dict)
    error: Optional[str] = None


def tls_connect(host: str, ip: Optional[str] = None, port: int = 443, timeout: float = 10.0,
                verify: bool = True, max_version: Optional[ssl.TLSVersion] = None) -> TlsResult:
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    if max_version is not None:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.maximum_version = max_version
    try:
        with socket.create_connection((ip or host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                return TlsResult(True, s.version(), s.getpeercert() or {})
    except Exception as e:
        return TlsResult(False, error=f"{type(e).__name__}: {e}")


def fetch_json(url: str, timeout: float = 30.0):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))
