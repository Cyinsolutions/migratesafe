"""A simulated Internet in which faults can be injected deterministically.

The checks in migratesafe.checks are run unchanged; only their data sources (DNS resolver,
HTTP client, TLS client, crt.sh and RDAP) are replaced by this in-memory world.
"""

from __future__ import annotations

import contextlib
import copy
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from unittest import mock
from urllib.parse import urlsplit

from migratesafe import checks, net
from migratesafe.model import Config, Context
from migratesafe.net import DNSERR, NOANSWER, NXDOMAIN, OK, HttpResp, TlsResult
from migratesafe.sources import CtCert, Registration

NOW = datetime.now(timezone.utc)


@dataclass
class World:
    new: str = "new.example"
    old: str = "old.example"
    records: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)
    parent_ns: Dict[str, List[str]] = field(default_factory=dict)
    lame: List[str] = field(default_factory=list)  # nameservers that are not authoritative
    dnssec: Dict[str, Tuple[bool, bool]] = field(default_factory=dict)  # domain -> (has_ds, validates)
    certs: Dict[str, List[CtCert]] = field(default_factory=dict)
    registrations: Dict[str, Registration] = field(default_factory=dict)
    files: Dict[str, str] = field(default_factory=dict)  # project path -> content
    # web behaviour
    hsts: Dict[str, Optional[str]] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    redirect_status: int = 301
    redirect_preserve_path: bool = True
    old_redirects: bool = True
    open_redirect_xfh: bool = False
    takeover_bodies: Dict[str, str] = field(default_factory=dict)  # host -> body served
    # TLS behaviour
    tls_valid: bool = True
    tls_days_left: int = 60
    accepts_tls11: bool = False
    old_host_serves_valid: bool = False
    config: Config = field(default_factory=Config)
    phase: str = "P4"

    def clone(self) -> "World":
        return copy.deepcopy(self)

    def set(self, name: str, rtype: str, values: List[str]) -> None:
        self.records[(name.lower(), rtype)] = values

    def drop(self, name: str, rtype: str) -> None:
        self.records.pop((name.lower(), rtype), None)


class FakeDns(net.Dns):
    def __init__(self, world: World):  # noqa: D401 - no real resolver
        self.w = world
        self.timeout = 1.0
        self._cache = {}

    def _known(self, name: str) -> bool:
        return any(n == name for n, _ in self.w.records)

    def lookup(self, name: str, rtype: str):
        name = name.lower().rstrip(".")
        recs = self.w.records.get((name, rtype))
        if recs is not None:
            return OK, list(recs)
        cname = self.w.records.get((name, "CNAME"))
        if cname and rtype != "CNAME":
            return self.lookup(cname[0], rtype)
        if self._known(name):
            return NOANSWER, []
        return NXDOMAIN, []

    def parent_delegation(self, domain: str):
        ns = self.w.parent_ns.get(domain)
        return (sorted(ns), None) if ns else ([], "parent zone says the domain does not exist")

    def authoritative_soa(self, domain: str, ns: str):
        if ns.rstrip(".") in self.w.lame:
            return False, f"{ns} is not authoritative (lame delegation)"
        return True, f"{ns} authoritative"

    def dnssec_status(self, domain: str):
        has_ds, ok = self.w.dnssec.get(domain, (False, False))
        return has_ds, ok, "" if ok or not has_ds else "SERVFAIL from validating resolver"


def _cert_dict(world: World) -> dict:
    exp = NOW + timedelta(days=world.tls_days_left)
    return {"subjectAltName": (("DNS", world.new), ("DNS", "www." + world.new)),
            "notAfter": exp.strftime("%b %d %H:%M:%S %Y GMT")}


def fake_tls(world: World):
    def tls_connect(host, ip=None, port=443, timeout=10.0, verify=True, max_version=None):
        if ip is not None:  # connecting to the former host (C8)
            if world.old_host_serves_valid:
                return TlsResult(True, "TLSv1.2", {})
            return TlsResult(False, error="SSLCertVerificationError: certificate verify failed")
        if max_version is not None:
            if world.accepts_tls11:
                return TlsResult(True, "TLSv1.1", {})
            return TlsResult(False, error="SSLError: [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version")
        if not world.tls_valid:
            return TlsResult(False, error="SSLCertVerificationError: certificate has expired")
        return TlsResult(True, "TLSv1.3", _cert_dict(world))
    return tls_connect


def fake_http(world: World):
    def http_get(url, timeout=10.0, headers=None, verify=True, max_body=200_000):
        u = urlsplit(url)
        host = (u.hostname or "").lower()
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        base_host = host[4:] if host.startswith("www.") else host
        if host in world.takeover_bodies:
            return HttpResp(404, [], world.takeover_bodies[host])
        hdrs: List[Tuple[str, str]] = []
        h = world.hsts.get(base_host)
        if h and u.scheme == "https":
            hdrs.append(("Strict-Transport-Security", h))
        if base_host == world.old:
            if u.scheme == "http":
                return HttpResp(301, [("Location", f"https://{host}{path}")])
            if not world.old_redirects:
                return HttpResp(200, hdrs, "legacy site")
            xfh = (headers or {}).get("X-Forwarded-Host")
            target_host = xfh if (xfh and world.open_redirect_xfh) else world.new
            target_path = path if world.redirect_preserve_path else "/"
            return HttpResp(world.redirect_status, hdrs + [("Location", f"https://{target_host}{target_path}")])
        if base_host == world.new:
            if u.scheme == "http":
                return HttpResp(301, [("Location", f"https://{host}{path}")])
            return HttpResp(200, hdrs + [("Set-Cookie", c) for c in world.cookies], "app")
        return HttpResp(error="ConnectionRefusedError: [Errno 61] Connection refused")
    return http_get


@contextlib.contextmanager
def simulated(world: World):
    """Patch every data source used by migratesafe.checks with the simulated world."""
    tmp = tempfile.TemporaryDirectory()
    for rel, content in world.files.items():
        path = os.path.join(tmp.name, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    http_get = fake_http(world)

    def rdap(domain, timeout=20.0):
        if domain not in world.registrations:
            raise LookupError("no RDAP data")
        return world.registrations[domain]

    patches = [
        mock.patch.object(checks, "http_get", http_get),
        mock.patch.object(net, "http_get", http_get),  # used by net.follow_redirects
        mock.patch.object(checks, "tls_connect", fake_tls(world)),
        mock.patch.object(checks, "ct_certificates", lambda d, timeout=60.0: list(world.certs.get(d, []))),
        mock.patch.object(checks, "rdap_domain", rdap),
    ]
    for p in patches:
        p.start()
    try:
        ctx = Context(new=world.new, old=world.old, phase=world.phase, project=tmp.name,
                      since_days=30, timeout=1.0, config=copy.deepcopy(world.config))
        ctx.cache["dns"] = FakeDns(world)
        yield ctx
    finally:
        for p in reversed(patches):
            p.stop()
        tmp.cleanup()


def cert(names: List[str], issuer: str, days_ago: int, cid: int) -> CtCert:
    nb = NOW - timedelta(days=days_ago)
    return CtCert(cid, names, issuer, nb, nb + timedelta(days=90))
