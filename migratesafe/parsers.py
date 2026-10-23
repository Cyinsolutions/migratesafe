"""Pure parsing and evaluation helpers (no network), so they can be unit tested."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# ---------------------------------------------------------------- HSTS (C9)


@dataclass
class Hsts:
    max_age: int
    include_subdomains: bool
    preload: bool


def parse_hsts(value: Optional[str]) -> Optional[Hsts]:
    if not value:
        return None
    max_age = None
    inc = pre = False
    for part in value.split(";"):
        part = part.strip()
        low = part.lower()
        if low.startswith("max-age"):
            m = re.match(r'max-age\s*=\s*"?(\d+)"?', low)
            if m:
                max_age = int(m.group(1))
        elif low == "includesubdomains":
            inc = True
        elif low == "preload":
            pre = True
    if max_age is None:
        return None
    return Hsts(max_age, inc, pre)


# ---------------------------------------------------------------- SPF / DMARC / MX (C13)


def find_spf(txt_records: List[str]) -> List[str]:
    out = []
    for rec in txt_records:
        joined = join_txt(rec)
        if joined.lower().startswith("v=spf1"):
            out.append(joined)
    return out


def join_txt(rdata_text: str) -> str:
    """dnspython renders TXT as '"part1" "part2"'; join the quoted strings."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', rdata_text)
    return "".join(parts) if parts else rdata_text.strip('"')


def spf_all_qualifier(spf: str) -> Optional[str]:
    """Return the qualifier of the terminal 'all' mechanism ('-', '~', '?', '+') or None."""
    for term in spf.split()[1:]:
        m = re.fullmatch(r"([+\-~?]?)all", term.lower())
        if m:
            return m.group(1) or "+"
    return None


def is_null_spf(spf: str) -> bool:
    return [t.lower() for t in spf.split()] == ["v=spf1", "-all"]


def parse_tags(record: str) -> Dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def parse_dmarc(txt_records: List[str]) -> Optional[Dict[str, str]]:
    for rec in txt_records:
        joined = join_txt(rec)
        if joined.lower().startswith("v=dmarc1"):
            return parse_tags(joined)
    return None


def is_null_mx(mx_records: List[str]) -> bool:
    """RFC 7505: a single MX with preference 0 and target '.'"""
    return len(mx_records) == 1 and mx_records[0].split()[-1] == "."


# ---------------------------------------------------------------- CAA (C5)


@dataclass
class Caa:
    flags: int
    tag: str
    value: str


def parse_caa(records: List[str]) -> List[Caa]:
    out = []
    for rec in records:
        m = re.match(r'(\d+)\s+(\S+)\s+"?(.*?)"?$', rec.strip())
        if m:
            out.append(Caa(int(m.group(1)), m.group(2).lower(), m.group(3)))
    return out


# Maps CA organisation names (as seen in CT issuer DNs) to their CAA identifiers.
ISSUER_TO_CAA = {
    "let's encrypt": "letsencrypt.org",
    "google trust services": "pki.goog",
    "sectigo": "sectigo.com",
    "zerossl": "sectigo.com",
    "comodo": "sectigo.com",
    "digicert": "digicert.com",
    "globalsign": "globalsign.com",
    "godaddy": "godaddy.com",
    "starfield": "godaddy.com",
    "amazon": "amazon.com",
    "ssl.com": "ssl.com",
    "entrust": "entrust.net",
    "buypass": "buypass.com",
    "microsoft": "microsoft.com",
}


def issuer_org(issuer_dn: str) -> str:
    m = re.search(r"O=([^,]+)", issuer_dn or "")
    if m:
        return m.group(1).strip().strip('"')
    m = re.search(r"CN=([^,]+)", issuer_dn or "")
    return m.group(1).strip() if m else (issuer_dn or "unknown")


def issuer_caa_id(org: str) -> Optional[str]:
    low = org.lower()
    for key, caa in ISSUER_TO_CAA.items():
        if key in low:
            return caa
    return None


# ---------------------------------------------------------------- Cookies (C11)

SESSION_RE = re.compile(r"(sess|sid|auth|token|jwt|remember|login|laravel|connect\.sid|identity)", re.I)
CSRF_RE = re.compile(r"(xsrf|csrf)", re.I)
INFRA_RE = re.compile(r"^(__cf_bm|_cfuvid|cf_clearance|__cflb|awsalb\w*|awselb\w*|ak_bmsc|bm_\w+|_ga\w*|_gid|_fbp)$", re.I)


@dataclass
class Cookie:
    name: str
    attrs: Dict[str, str] = field(default_factory=dict)  # lower-case attribute -> value ("" for flags)

    @property
    def secure(self) -> bool:
        return "secure" in self.attrs

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attrs

    @property
    def samesite(self) -> Optional[str]:
        return self.attrs.get("samesite")

    @property
    def domain(self) -> Optional[str]:
        return self.attrs.get("domain")


def parse_set_cookie(header: str) -> Cookie:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        if not p:
            continue
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.lower()] = ""
    return Cookie(name, attrs)


def cookie_kind(name: str) -> str:
    if INFRA_RE.match(name):
        return "infra"
    if CSRF_RE.search(name):
        return "csrf"
    if SESSION_RE.search(name):
        return "session"
    return "other"


def evaluate_cookie(c: Cookie) -> List[Tuple[str, str]]:
    """Return (status, message) pairs for one cookie. Status strings match model.py."""
    kind = cookie_kind(c.name)
    out: List[Tuple[str, str]] = []
    if kind == "infra":
        return [("INFO", f"{c.name}: CDN/analytics cookie, not evaluated")]
    critical = kind in ("session", "csrf")
    if not c.secure:
        out.append(("FAIL" if critical else "WARN", f"{c.name}: missing Secure"))
    if kind == "session" and not c.httponly:
        out.append(("FAIL", f"{c.name}: session cookie missing HttpOnly"))
    if not c.samesite:
        out.append(("WARN", f"{c.name}: missing SameSite"))
    elif c.samesite.lower() == "none" and critical:
        out.append(("WARN", f"{c.name}: SameSite=None on a {kind} cookie"))
    if c.domain:
        out.append(("FAIL" if critical else "WARN",
                    f"{c.name}: Domain={c.domain} shares the cookie with every subdomain (use host-only)"))
    if not out:
        prefix = " (__Host- prefix)" if c.name.startswith("__Host-") else ""
        out.append(("PASS", f"{c.name}: Secure/HttpOnly/SameSite/host-only OK{prefix}"))
    return out


# ---------------------------------------------------------------- Redirects (C10)


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def evaluate_redirect_chain(chain: List[Tuple[int, str]], new: str, probe_path: str) -> List[Tuple[str, str]]:
    """chain = [(status, location), ...] for each hop that was a redirect, final hop last."""
    if not chain:
        return [("FAIL", "old name does not redirect")]
    out = []
    final_status, final_loc = chain[-1]
    final = urlsplit(final_loc)
    if (final.hostname or "").lower().rstrip(".") not in (new, "www." + new):
        out.append(("FAIL", f"final redirect target is {final.hostname!r}, expected {new}"))
    if final.scheme != "https":
        out.append(("FAIL", f"final redirect uses {final.scheme}://, expected https"))
    path_q = final.path + ("?" + final.query if final.query else "")
    if not path_q.startswith(probe_path):
        out.append(("WARN", f"path/query not preserved (got {path_q!r})"))
    perm = [s for s, _ in chain if s in (301, 308)]
    if len(perm) != len(chain):
        out.append(("WARN", "non-permanent redirect status in chain: " + ", ".join(str(s) for s, _ in chain)))
    if not out:
        out.append(("PASS", f"{len(chain)} hop(s), permanent, path preserved, ends at https://{final.hostname}"))
    return out


# ---------------------------------------------------------------- Takeover fingerprints (C2)

# Indicative fingerprints for services whose de-provisioned resources can be re-claimed.
# Inspired by the public "can-i-take-over-xyz" community list. A match is strong evidence,
# not proof.
TAKEOVER_FINGERPRINTS = [
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "no-such-app"),
    ("herokudns.com", "no-such-app"),
    ("amazonaws.com", "NoSuchBucket"),
    ("myshopify.com", "Sorry, this shop is currently unavailable"),
    ("readthedocs.io", "unknown to Read the Docs"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("pantheonsite.io", "The gods are wise"),
    ("zendesk.com", "Help Center Closed"),
    ("fastly.net", "Fastly error: unknown domain"),
]

TAKEOVER_SUFFIXES = sorted({s for s, _ in TAKEOVER_FINGERPRINTS} | {
    "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
    "blob.core.windows.net", "azureedge.net", "netlify.app", "vercel.app", "ghost.io",
    "wordpress.com", "webflow.io", "unbouncepages.com", "helpscoutdocs.com",
})


def takeover_suffix(target: str) -> Optional[str]:
    t = target.lower().rstrip(".")
    for s in TAKEOVER_SUFFIXES:
        if t == s or t.endswith("." + s):
            return s
    return None


def takeover_fingerprint(target: str, body: str) -> Optional[str]:
    t = target.lower().rstrip(".")
    for suffix, needle in TAKEOVER_FINGERPRINTS:
        if (t == suffix or t.endswith("." + suffix)) and needle.lower() in body.lower():
            return needle
    return None


# ---------------------------------------------------------------- Lookalikes (C14)

ALT_TLDS = ["com", "net", "org", "in", "co", "io", "co.in", "app", "info", "xyz"]


def split_domain(domain: str) -> Tuple[str, str]:
    """Naive split into (label, suffix); handles common two-level suffixes."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in ("co.in", "co.uk", "com.au", "org.in", "net.in", "com.br"):
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def lookalike_candidates(domain: str, limit: int = 40) -> List[str]:
    label, suffix = split_domain(domain)
    out: List[str] = []

    def add(cand: str) -> None:
        if cand != domain and cand not in out:
            out.append(cand)

    for tld in ALT_TLDS:
        if tld != suffix:
            add(f"{label}.{tld}")
    for i in range(len(label)):  # omission
        if len(label) > 3:
            add(f"{label[:i]}{label[i + 1:]}.{suffix}")
    for i in range(len(label) - 1):  # adjacent swap
        sw = label[:i] + label[i + 1] + label[i] + label[i + 2:]
        add(f"{sw}.{suffix}")
    for i in range(len(label)):  # duplication
        add(f"{label[:i + 1]}{label[i]}{label[i + 1:]}.{suffix}")
    for word in ("login", "secure", "app", "official"):
        add(f"{label}-{word}.{suffix}")
    return out[:limit]


# ---------------------------------------------------------------- Config scanning (C12)

SECRET_KEY_RE = re.compile(r"(key|secret|password|passwd|token|salt|private)", re.I)


def mask_env_line(line: str) -> str:
    if "=" not in line:
        return line
    k, v = line.split("=", 1)
    if SECRET_KEY_RE.search(k):
        return f"{k}=****"
    return f"{k}={v}"


def parse_env(text: str) -> Dict[str, str]:
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.startswith("export "):
            k = k[len("export "):]
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def evaluate_laravel_env(env: Dict[str, str], new: str, old: Optional[str]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if "APP_URL" in env:
        h = host_of(env["APP_URL"]) if "://" in env["APP_URL"] else env["APP_URL"].lower()
        if h not in (new, "www." + new):
            out.append(("FAIL", f"APP_URL host is {h!r}, expected {new}"))
        elif not env["APP_URL"].startswith("https://"):
            out.append(("WARN", "APP_URL is not https://"))
        else:
            out.append(("PASS", "APP_URL points to the new name over https"))
    sd = env.get("SESSION_DOMAIN", "")
    if sd and sd.lower() not in ("null", ""):
        out.append(("FAIL", f"SESSION_DOMAIN={sd} makes session cookies visible to subdomains; leave it empty"))
    if "SESSION_SECURE_COOKIE" in env and env["SESSION_SECURE_COOKIE"].lower() != "true":
        out.append(("FAIL", "SESSION_SECURE_COOKIE is not true"))
    stateful = env.get("SANCTUM_STATEFUL_DOMAINS", "")
    if old and old in stateful.lower():
        out.append(("FAIL", "SANCTUM_STATEFUL_DOMAINS still lists the old name"))
    return out
