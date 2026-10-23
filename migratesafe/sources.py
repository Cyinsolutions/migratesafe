"""Public data sources: Certificate Transparency (crt.sh) and RDAP."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import quote

from .net import fetch_json


@dataclass
class CtCert:
    id: int
    names: List[str]
    issuer: str
    not_before: datetime
    not_after: datetime


def _parse_ts(s: str) -> datetime:
    s = (s or "").replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.fromtimestamp(0, timezone.utc)


def ct_certificates(domain: str, timeout: float = 60.0) -> List[CtCert]:
    """All certificates logged in CT for the domain and its subdomains (via crt.sh)."""
    seen: Dict[int, CtCert] = {}
    for q in (domain, "%." + domain):
        url = f"https://crt.sh/?q={quote(q)}&output=json"
        data = None
        for attempt in range(2):
            try:
                data = fetch_json(url, timeout=timeout)
                break
            except Exception:
                if attempt == 1:
                    raise
                time.sleep(3)
        for row in data or []:
            cid = int(row.get("id", 0))
            if cid in seen:
                continue
            names = sorted({n.strip().lower() for n in str(row.get("name_value", "")).split("\n") if n.strip()})
            seen[cid] = CtCert(cid, names, row.get("issuer_name", ""),
                               _parse_ts(row.get("not_before", "")), _parse_ts(row.get("not_after", "")))
    return list(seen.values())


def ct_hostnames(certs: List[CtCert], domain: str) -> List[str]:
    out = set()
    for c in certs:
        for n in c.names:
            n = n.lstrip("*.").rstrip(".")
            if n == domain or n.endswith("." + domain):
                out.add(n)
    return sorted(out)


@dataclass
class Registration:
    expires: Optional[datetime]
    statuses: List[str]
    registrar: Optional[str]


def rdap_domain(domain: str, timeout: float = 20.0) -> Registration:
    data = fetch_json(f"https://rdap.org/domain/{domain}", timeout=timeout)
    expires = None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "expiration":
            expires = _parse_ts(ev.get("eventDate", "")[:19])
    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    return Registration(expires, [s.lower() for s in data.get("status", [])], registrar)
