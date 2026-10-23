"""Baseline (correctly migrated) world and a catalogue of injected faults.

Each fault is mapped to the threat class it instantiates (paper Table I) and to the check that is
expected to detect it (paper Table II). A fault counts as detected when the expected check reports
FAIL or WARN in the faulty world but not in the baseline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List

from migratesafe.model import Config
from migratesafe.sources import Registration

from .world import NOW, World, cert

from datetime import timedelta

NEW, OLD = "new.example", "old.example"
NS = ["ns1.dnsprov.example.", "ns2.dnsprov.example."]
LE = "C=US, O=Let's Encrypt, CN=R11"


def baseline() -> World:
    w = World(new=NEW, old=OLD)
    for d, ip in ((NEW, "192.0.2.10"), (OLD, "192.0.2.11")):
        w.set(d, "A", [ip])
        w.set("www." + d, "A", [ip])
        w.set(d, "NS", list(NS))
        w.set(d, "CAA", ['0 issue "letsencrypt.org"', f'0 iodef "mailto:security@{NEW}"'])
        w.parent_ns[d] = [n.lower() for n in NS]
        w.dnssec[d] = (True, True)
        w.hsts[d] = "max-age=31536000; includeSubDomains"
        w.registrations[d] = Registration(NOW + timedelta(days=400), ["client transfer prohibited"], "Example Registrar")
    for i, n in enumerate(NS):
        w.set(n.rstrip("."), "A", [f"192.0.2.{53 + i}"])
    # mail: new name sends mail, old name is retired (phase P4)
    w.set(NEW, "MX", [f"10 mx.{NEW}."])
    w.set("mx." + NEW, "A", ["192.0.2.20"])
    w.set(NEW, "TXT", ['"v=spf1 mx -all"'])
    w.set("_dmarc." + NEW, "TXT", [f'"v=DMARC1; p=reject; rua=mailto:dmarc@{NEW}"'])
    w.set("default._domainkey." + NEW, "TXT", ['"v=DKIM1; k=rsa; p=MIIBIjANBgkqh"'])
    w.set(OLD, "MX", ["0 ."])
    w.set(OLD, "TXT", ['"v=spf1 -all"'])
    w.set("_dmarc." + OLD, "TXT", ['"v=DMARC1; p=reject"'])
    # certificates in CT
    w.certs[NEW] = [cert([NEW, "www." + NEW], LE, 10, 1)]
    w.certs[OLD] = [cert([OLD, "www." + OLD], LE, 120, 2)]
    # application with session cookie and Laravel configuration
    w.cookies = ["__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"]
    w.files = {
        ".env": f"APP_URL=https://{NEW}\nSESSION_DOMAIN=\nSESSION_SECURE_COOKIE=true\nAPP_KEY=base64:secret\n",
        "config/cors.php": f"<?php return ['allowed_origins' => ['https://{NEW}']];\n",
    }
    w.config = Config(
        inventory={h: "migrate" for h in (NEW, "www." + NEW)} | {h: "redirect" for h in (OLD, "www." + OLD)},
        allowed_issuers=["Let's Encrypt"], old_host_ip="198.51.100.7", old_domain_mail="retired",
    )
    return w


@dataclass
class Fault:
    fid: str
    threat: str
    expected: str  # check expected to detect it
    description: str
    apply: Callable[[World], None]


def _f(fid, threat, expected, description):
    def deco(fn):
        FAULTS.append(Fault(fid, threat, expected, description, fn))
        return fn
    return deco


FAULTS: List[Fault] = []


@_f("F01", "T1", "C2", "CNAME left in zone points to a de-provisioned host (NXDOMAIN target)")
def _(w):
    w.set("status." + OLD, "CNAME", ["status-page.saas.example."])
    w.config.inventory["status." + OLD] = "delete"


@_f("F02", "T1", "C2", "CNAME to an unclaimed GitHub Pages site (takeover fingerprint)")
def _(w):
    w.set("docs." + NEW, "CNAME", ["acme.github.io."])
    w.set("acme.github.io", "A", ["185.199.108.153"])
    w.takeover_bodies["docs." + NEW] = "<h1>There isn't a GitHub Pages site here.</h1>"
    w.config.inventory["docs." + NEW] = "migrate"


@_f("F03", "T1", "C2", "MX record points to a mail host that no longer exists")
def _(w):
    w.set(NEW, "MX", [f"10 mx.{NEW}.", "20 backup-mx.oldhost.example."])


@_f("F04", "T1", "C1", "Hostname visible only in CT logs is missing from the inventory")
def _(w):
    w.certs[NEW].append(cert(["api." + NEW], LE, 5, 3))
    w.set("api." + NEW, "A", ["192.0.2.30"])


@_f("F05", "T3", "C3", "Registrar still lists the former provider's nameserver (parent != zone NS)")
def _(w):
    w.parent_ns[NEW] = [n.lower() for n in NS] + ["ns1.oldprovider.example."]
    w.set("ns1.oldprovider.example", "A", ["203.0.113.53"])


@_f("F06", "T3", "C3", "Delegated nameserver no longer serves the zone (lame delegation)")
def _(w):
    w.lame.append("ns2.dnsprov.example")


@_f("F07", "T3", "C4", "Stale DS record after DNS-provider change (DNSSEC bogus)")
def _(w):
    w.dnssec[NEW] = (True, False)


@_f("F08", "T4", "C5", "No CAA record on the new name")
def _(w):
    w.drop(NEW, "CAA")


@_f("F09", "T4", "C5", "CAA present but without an iodef contact")
def _(w):
    w.set(NEW, "CAA", ['0 issue "letsencrypt.org"'])


@_f("F10", "T4", "C6", "Certificate issued by an unexpected CA appears in CT")
def _(w):
    w.certs[NEW].append(cert(["pay." + NEW], "C=US, O=Example Rogue CA, CN=DV", 3, 4))
    w.config.inventory["pay." + NEW] = "migrate"


@_f("F11", "T4", "C7", "New origin serves an expired or untrusted certificate")
def _(w):
    w.tls_valid = False


@_f("F12", "T5", "C7", "New origin still accepts TLS 1.1")
def _(w):
    w.accepts_tls11 = True


@_f("F13", "T4", "C8", "Former hosting provider still serves a valid certificate for the names")
def _(w):
    w.old_host_serves_valid = True


@_f("F14", "T5", "C9", "No HSTS header on the new name")
def _(w):
    w.hsts[NEW] = None


@_f("F15", "T5", "C9", "HSTS max-age too short after stabilization")
def _(w):
    w.hsts[NEW] = "max-age=300"


@_f("F16", "T2", "C10", "Old name keeps serving the legacy site instead of redirecting")
def _(w):
    w.old_redirects = False


@_f("F17", "T5", "C10", "Old name uses a temporary redirect and drops the path")
def _(w):
    w.redirect_status = 302
    w.redirect_preserve_path = False


@_f("F18", "T8", "C10", "Legacy redirect builds its target from X-Forwarded-Host (open redirect)")
def _(w):
    w.open_redirect_xfh = True


@_f("F19", "T1", "C11", "Session cookie scoped to the parent domain (Domain attribute)")
def _(w):
    w.cookies = [f"laravel_session=abc; Domain=.{NEW}; Path=/; Secure; HttpOnly; SameSite=Lax"]


@_f("F20", "T5", "C11", "Session cookie without HttpOnly")
def _(w):
    w.cookies = ["laravel_session=abc; Path=/; Secure; SameSite=Lax"]


@_f("F21", "T8", "C12", "APP_URL still points to the old name")
def _(w):
    w.files[".env"] = w.files[".env"].replace(f"APP_URL=https://{NEW}", f"APP_URL=https://{OLD}")


@_f("F22", "T8", "C12", "CORS allow-list still contains the old origin")
def _(w):
    w.files["config/cors.php"] = f"<?php return ['allowed_origins' => ['https://{NEW}', 'https://{OLD}']];\n"


@_f("F23", "T6", "C13", "SPF on the new name ends in ~all")
def _(w):
    w.set(NEW, "TXT", ['"v=spf1 mx ~all"'])


@_f("F24", "T6", "C13", "No DMARC record on the new name")
def _(w):
    w.drop("_dmarc." + NEW, "TXT")


@_f("F25", "T6", "C13", "Retired old name has no DMARC policy (spoofable)")
def _(w):
    w.drop("_dmarc." + OLD, "TXT")


@_f("F26", "T2", "C14", "Old name registration expires in 20 days")
def _(w):
    w.registrations[OLD] = Registration(NOW + timedelta(days=20), ["client transfer prohibited"], "Example Registrar")


@_f("F27", "T2", "C14", "Old name has no transfer lock")
def _(w):
    w.registrations[OLD] = Registration(NOW + timedelta(days=400), [], "Example Registrar")


@_f("F28", "T7", "C14", "A lookalike of the new name is registered")
def _(w):
    w.set("new.net", "A", ["203.0.113.66"])
