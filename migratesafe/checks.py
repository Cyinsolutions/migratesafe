"""Verification checks C1-C14 (paper Table II). Every check is read-only."""

from __future__ import annotations

import os
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

from . import parsers as P
from .model import ERROR, FAIL, INFO, MANUAL, PASS, SKIP, WARN, Context, Result
from .net import NXDOMAIN, OK, Dns, follow_redirects, http_get, tls_connect
from .sources import CtCert, ct_certificates, ct_hostnames, rdap_domain

COMMON_PREFIXES = ["www", "mail", "webmail", "api", "app", "admin", "panel", "cpanel", "status", "dev",
                   "staging", "test", "m", "cdn", "static", "ws", "blog", "docs", "support", "help",
                   "pay", "wallet", "auth", "login", "ftp", "smtp", "autodiscover"]

PROBE_HOST = "migratesafe-probe.invalid"  # RFC 2606 reserved: never resolves


# ---------------------------------------------------------------- shared lookups


def dns_of(ctx: Context) -> Dns:
    if "dns" not in ctx.cache:
        ctx.cache["dns"] = Dns(timeout=ctx.timeout / 2)
    return ctx.cache["dns"]


def ct_of(ctx: Context, domain: str) -> List[CtCert]:
    key = "ct:" + domain
    if key not in ctx.cache:
        try:
            ctx.cache[key] = ct_certificates(domain, timeout=max(30.0, ctx.timeout * 4))
        except Exception as e:
            ctx.cache[key] = e
    val = ctx.cache[key]
    if isinstance(val, Exception):
        raise RuntimeError(f"crt.sh unavailable for {domain}: {val}")
    return val


def hostnames_of(ctx: Context, domain: str) -> Dict[str, str]:
    """hostname -> source ('ct', 'probe', 'apex'). CT failure is tolerated."""
    key = "hosts:" + domain
    if key in ctx.cache:
        return ctx.cache[key]
    d = dns_of(ctx)
    hosts: Dict[str, str] = {domain: "apex"}
    try:
        for h in ct_hostnames(ct_of(ctx, domain), domain):
            hosts.setdefault(h, "ct")
    except RuntimeError as e:
        ctx.cache["ct_error:" + domain] = str(e)
    cands = [f"{p}.{domain}" for p in COMMON_PREFIXES]
    with ThreadPoolExecutor(8) as ex:
        found = list(ex.map(lambda h: (h, d.lookup(h, "A")[0] == OK or d.lookup(h, "CNAME")[0] == OK), cands))
    for h, ok in found:
        if ok:
            hosts.setdefault(h, "probe")
    ctx.cache[key] = hosts
    return hosts


# ---------------------------------------------------------------- C1 inventory


def c1_inventory(ctx: Context) -> Result:
    r = Result("C1", "Zone inventory", "T1, T2",
               fix="List every hostname of both names in the config 'inventory' with a fate: "
                   "migrate, redirect or delete. Include names that appear only in CT logs.")
    inv = {k.lower().rstrip("."): v for k, v in ctx.config.inventory.items()}
    for domain in ctx.domains:
        hosts = hostnames_of(ctx, domain)
        if ("ct_error:" + domain) in ctx.cache:
            r.add(WARN, domain, ctx.cache["ct_error:" + domain] + " (inventory based on DNS probing only)")
        n_ct = sum(1 for s in hosts.values() if s == "ct")
        r.add(INFO, domain, f"{len(hosts)} hostnames discovered ({n_ct} from CT logs): "
                            + ", ".join(sorted(hosts)[:25]) + (" ..." if len(hosts) > 25 else ""))
        if not inv:
            continue
        missing = [h for h in hosts if h not in inv]
        if missing:
            r.add(FAIL, domain, f"{len(missing)} hostnames have no owner/fate: " + ", ".join(sorted(missing)[:20]))
        else:
            r.add(PASS, domain, "every discovered hostname has a fate in the inventory")
    if not inv:
        r.add(WARN, "config", "no inventory supplied; cannot confirm that every hostname has an owner and fate")
    else:
        bad = [h for h, f in inv.items() if str(f).lower() not in ("migrate", "redirect", "delete", "keep")]
        if bad:
            r.add(WARN, "config", "inventory entries with an unknown fate: " + ", ".join(bad))
    return r


# ---------------------------------------------------------------- C2 dangling targets


def _check_host_dangling(ctx: Context, host: str, source: str):
    d = dns_of(ctx)
    out = []
    ccode, cnames = d.lookup(host, "CNAME")
    acode, _ = d.lookup(host, "A")
    if ccode == OK and cnames:
        target = cnames[0].rstrip(".")
        if acode == NXDOMAIN:
            out.append((FAIL, host, f"CNAME -> {target} does not resolve (dangling, takeover risk)"))
            return out
        suffix = P.takeover_suffix(target)
        if suffix:
            body = ""
            for scheme in ("https", "http"):
                resp = http_get(f"{scheme}://{host}/", timeout=ctx.timeout, verify=False)
                if not resp.error:
                    body = resp.body
                    break
            fp = P.takeover_fingerprint(target, body)
            if fp:
                out.append((FAIL, host, f"CNAME -> {target}: service reports '{fp}' (unclaimed resource)"))
            else:
                out.append((WARN, host, f"CNAME -> {target} ({suffix}): confirm the resource is still yours"))
    elif acode == NXDOMAIN and source == "ct":
        out.append((INFO, host, "appears in CT logs but no longer exists in DNS"))
    return out


def c2_dangling(ctx: Context) -> Result:
    r = Result("C2", "Dangling targets", "T1",
               fix="Delete or repoint records whose targets no longer exist or are no longer yours, "
                   "before the old hosting is released.")
    d = dns_of(ctx)
    for domain in ctx.domains:
        hosts = hostnames_of(ctx, domain)
        with ThreadPoolExecutor(8) as ex:
            for res in ex.map(lambda hs: _check_host_dangling(ctx, *hs), hosts.items()):
                for st, tgt, msg in res:
                    r.add(st, tgt, msg)
        code, mx = d.lookup(domain, "MX")
        for rec in mx if code == OK else []:
            target = rec.split()[-1].rstrip(".")
            if target and target != "." and not d.addresses(target):
                r.add(FAIL, domain, f"MX target {target} does not resolve")
        code, ns = d.lookup(domain, "NS")
        for n in ns if code == OK else []:
            if not d.addresses(n.rstrip(".")):
                r.add(FAIL, domain, f"NS target {n} does not resolve")
    if not any(f.status in (FAIL, WARN) for f in r.findings):
        r.add(PASS, ", ".join(ctx.domains), "no dangling CNAME, MX or NS targets found")
    return r


# ---------------------------------------------------------------- C3 delegation


def c3_delegation(ctx: Context) -> Result:
    r = Result("C3", "Delegation", "T3",
               fix="Make the NS set at the registrar identical to the NS records in the zone, and remove "
                   "the former DNS provider once it no longer answers authoritatively.")
    d = dns_of(ctx)
    for domain in ctx.domains:
        parent, err = d.parent_delegation(domain)
        if err:
            r.add(ERROR, domain, err)
            continue
        code, child = d.lookup(domain, "NS")
        child_set = {c.lower() for c in child} if code == OK else set()
        if child_set and set(parent) != child_set:
            r.add(FAIL, domain, f"parent NS {sorted(parent)} != zone NS {sorted(child_set)}")
        lame = []
        for ns in sorted(set(parent) | child_set):
            ok, note = d.authoritative_soa(domain, ns.rstrip("."))
            if not ok:
                lame.append(note)
        for note in lame:
            r.add(FAIL, domain, note)
        if not lame and (not child_set or set(parent) == child_set):
            r.add(PASS, domain, f"{len(parent)} nameservers, consistent and authoritative: " + ", ".join(parent))
    return r


# ---------------------------------------------------------------- C4 DNSSEC


def c4_dnssec(ctx: Context) -> Result:
    r = Result("C4", "DNSSEC", "T3",
               fix="Either sign the zone at the new DNS provider and publish a matching DS at the registrar, "
                   "or record an explicit exception (config 'dnssec_exception': true). Remove a stale DS "
                   "before changing DNS provider.")
    d = dns_of(ctx)
    for domain in ctx.domains:
        has_ds, validates, note = d.dnssec_status(domain)
        if has_ds and validates:
            r.add(PASS, domain, "DS published at parent and responses validate")
        elif has_ds and not validates:
            r.add(FAIL, domain, "DS published but validation fails " + (f"({note})" if note else "") +
                  " - a stale DS after a provider change makes the domain unreachable for validating resolvers")
        elif ctx.config.dnssec_exception:
            r.add(PASS, domain, "unsigned, documented exception")
        else:
            r.add(WARN, domain, "zone is not DNSSEC-signed (no DS at parent)")
    return r


# ---------------------------------------------------------------- C5 CAA


def c5_caa(ctx: Context) -> Result:
    r = Result("C5", "CAA records", "T4",
               fix='Publish CAA on both names, e.g. 0 issue "letsencrypt.org" and 0 iodef "mailto:security@<domain>".')
    d = dns_of(ctx)
    for domain in ctx.domains:
        code, recs = d.lookup(domain, "CAA")
        caa = P.parse_caa(recs) if code == OK else []
        issue = [c.value for c in caa if c.tag in ("issue", "issuewild")]
        iodef = [c.value for c in caa if c.tag == "iodef"]
        if not issue:
            r.add(FAIL, domain, "no CAA issue records: any public CA may issue for this name")
        elif not iodef:
            r.add(WARN, domain, f"CAA restricts issuance to {sorted(set(issue))} but has no iodef contact")
        else:
            r.add(PASS, domain, f"CAA restricts issuance to {sorted(set(issue))}; iodef {iodef[0]}")
        ctx.cache["caa:" + domain] = {v.split(";")[0].strip().lower() for v in issue}
    return r


# ---------------------------------------------------------------- C6 CT audit


def c6_ct_audit(ctx: Context) -> Result:
    r = Result("C6", "Certificate Transparency audit", "T1, T4",
               fix="Investigate any certificate you did not request; revoke it and fix the DNS record "
                   "that allowed it. Set 'allowed_issuers' in the config to make this check strict.")
    since = datetime.now(timezone.utc) - timedelta(days=ctx.since_days)
    allowed = [a.lower() for a in ctx.config.allowed_issuers]
    for domain in ctx.domains:
        try:
            certs = [c for c in ct_of(ctx, domain) if c.not_before >= since]
        except RuntimeError as e:
            r.add(ERROR, domain, str(e))
            continue
        if not certs:
            r.add(INFO, domain, f"no certificates logged in the last {ctx.since_days} days")
            continue
        by_org: Dict[str, List[CtCert]] = {}
        for c in certs:
            by_org.setdefault(P.issuer_org(c.issuer), []).append(c)
        summary = ", ".join(f"{org} x{len(cs)}" for org, cs in sorted(by_org.items()))
        r.add(INFO, domain, f"{len(certs)} certificates in the last {ctx.since_days} days: {summary}")
        caa = ctx.cache.get("caa:" + domain)
        for org, cs in by_org.items():
            names = sorted({n for c in cs for n in c.names})[:6]
            if allowed:
                if not any(a in org.lower() for a in allowed):
                    r.add(FAIL, domain, f"certificate(s) from unexpected issuer {org}: {', '.join(names)}")
            elif caa:
                cid = P.issuer_caa_id(org)
                if cid and cid not in caa:
                    r.add(WARN, domain, f"{org} issued for {', '.join(names)} but is not permitted by current CAA")
        if allowed and not any(f.status == FAIL and f.target == domain for f in r.findings):
            r.add(PASS, domain, "all recent certificates come from allowed issuers")
    return r


# ---------------------------------------------------------------- C7 TLS on the new origin


def c7_tls(ctx: Context) -> Result:
    r = Result("C7", "New-origin TLS", "T4, T5",
               fix="Serve a valid certificate covering exactly the required names, and disable TLS 1.0/1.1.")
    for host in (ctx.new, "www." + ctx.new):
        if not dns_of(ctx).addresses(host):
            continue
        t = tls_connect(host, timeout=ctx.timeout)
        if not t.ok:
            r.add(FAIL, host, f"TLS handshake/verification failed: {t.error}")
            continue
        sans = [v for k, v in t.cert.get("subjectAltName", []) if k == "DNS"]
        exp = datetime.strptime(t.cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        st = WARN if days < 14 else PASS
        r.add(st, host, f"{t.version}, valid chain, expires in {days} days, SAN: {', '.join(sans[:8])}")
        foreign = [s for s in sans if not (s.lstrip("*.") == ctx.new or s.lstrip("*.").endswith("." + ctx.new))]
        if foreign:
            r.add(INFO, host, "certificate also covers other names (shared/CDN certificate): " + ", ".join(foreign[:5]))
        old = tls_connect(host, timeout=ctx.timeout, max_version=ssl.TLSVersion.TLSv1_1)
        verdict = P.classify_legacy_tls(old.ok, old.error)
        if verdict == "accepted":
            r.add(FAIL, host, f"server still accepts {old.version}")
        elif verdict == "refused":
            r.add(PASS, host, "TLS 1.0/1.1 refused by server")
        else:
            r.add(INFO, host, f"could not test TLS 1.0/1.1 from this client ({old.error})")
    if not r.findings:
        r.add(FAIL, ctx.new, "new name does not resolve")
    return r


# ---------------------------------------------------------------- C8 former host keys


def c8_old_host(ctx: Context) -> Result:
    r = Result("C8", "Former-host keys", "T4",
               fix="Detach the names from the former hosting account, delete stored keys and close the account; "
                   "revoke certificates whose keys remain with the former provider.")
    ip = ctx.config.old_host_ip
    if not ip:
        r.add(MANUAL, "config", "set 'old_host_ip' to test whether the former host still serves valid "
                                "certificates for your names; otherwise confirm account closure manually")
        return r
    for name in ctx.domains:
        t = tls_connect(name, ip=ip, timeout=ctx.timeout)
        if t.ok:
            r.add(FAIL, name, f"former host {ip} still serves a valid certificate for {name}")
        else:
            r.add(PASS, name, f"former host {ip} does not serve a trusted certificate for {name}")
    return r


# ---------------------------------------------------------------- C9 HSTS


def c9_hsts(ctx: Context) -> Result:
    strict = ctx.phase_at_least("P3")
    r = Result("C9", "HSTS", "T5",
               fix="Send Strict-Transport-Security: max-age=31536000; includeSubDomains on both names "
                   "(short max-age is fine before phase P3).")
    for domain in ctx.domains:
        resp = http_get(f"https://{domain}/", timeout=ctx.timeout)
        if resp.error:
            r.add(ERROR, domain, resp.error)
            continue
        h = P.parse_hsts(resp.header("Strict-Transport-Security"))
        if not h:
            r.add(FAIL, domain, "no Strict-Transport-Security header")
        elif strict and (h.max_age < 31536000 or not h.include_subdomains):
            r.add(WARN, domain, f"HSTS max-age={h.max_age}, includeSubDomains={h.include_subdomains} "
                                "(expected >= 31536000 with includeSubDomains)")
        else:
            r.add(PASS, domain, f"HSTS max-age={h.max_age}, includeSubDomains={h.include_subdomains}, preload={h.preload}")
    return r


# ---------------------------------------------------------------- C10 redirect


def c10_redirect(ctx: Context) -> Result:
    r = Result("C10", "Legacy redirect", "T5, T8",
               fix="Redirect the old name with 301/308 to a fixed https:// host, preserving path and query, "
                   "and never build the target from request input.")
    if not ctx.old:
        r.add(SKIP, "-", "no --old domain given")
        return r
    probe = "/migratesafe-probe/path?q=1"
    for scheme in ("http", "https"):
        chain, last = follow_redirects(f"{scheme}://{ctx.old}{probe}", timeout=ctx.timeout)
        if last.error and not chain:
            r.add(ERROR, f"{scheme}://{ctx.old}", last.error)
            continue
        for st, msg in P.evaluate_redirect_chain(chain, ctx.new, probe):
            r.add(st, f"{scheme}://{ctx.old}", msg)
    for label, url, hdrs in (
        ("path", f"https://{ctx.old}//{PROBE_HOST}/", None),
        ("X-Forwarded-Host", f"https://{ctx.old}/", {"X-Forwarded-Host": PROBE_HOST}),
        ("Host header", f"https://{ctx.old}/", {"X-Host": PROBE_HOST, "Forwarded": f"host={PROBE_HOST}"}),
    ):
        resp = http_get(url, timeout=ctx.timeout, headers=hdrs)
        loc = resp.header("Location") or ""
        if PROBE_HOST in P.host_of(loc) or loc.startswith("//" + PROBE_HOST):
            r.add(FAIL, ctx.old, f"open redirect via {label}: Location: {loc}")
    if not any(f.status == FAIL and "open redirect" in f.message for f in r.findings):
        r.add(PASS, ctx.old, "no open redirect via path or forwarded-host headers")
    return r


# ---------------------------------------------------------------- C11 cookies


def c11_cookies(ctx: Context) -> Result:
    r = Result("C11", "Session cookies", "T1, T5",
               fix="Make session cookies host-only (no Domain attribute; Laravel: SESSION_DOMAIN empty), "
                   "Secure, HttpOnly and SameSite=Lax/Strict; revoke all sessions at cutover.")
    seen = 0
    for path in ctx.config.session_paths or ["/"]:
        resp = http_get(f"https://{ctx.new}{path}", timeout=ctx.timeout)
        if resp.error:
            r.add(ERROR, f"https://{ctx.new}{path}", resp.error)
            continue
        for raw in resp.all("Set-Cookie"):
            seen += 1
            c = P.parse_set_cookie(raw)
            for st, msg in P.evaluate_cookie(c):
                r.add(st, f"https://{ctx.new}{path}", msg)
    if seen == 0 and not r.findings:
        r.add(INFO, ctx.new, "no cookies set on the tested paths; add a login path to 'session_paths'")
    if ctx.phase_at_least("P2"):
        r.add(MANUAL, ctx.new, "confirm that all sessions and API tokens issued before cutover were revoked")
    return r


# ---------------------------------------------------------------- C12 allow-lists / config drift

TEXT_EXT = {".env", ".php", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml", ".toml",
            ".ini", ".conf", ".xml", ".py", ".rb", ".go", ".java", ".kt", ".cs", ".html", ".vue", ".svelte",
            ".htaccess", ".txt", ".md", ".sh", ".tf", ".properties"}
SKIP_DIRS = {".git", "node_modules", "vendor", "storage", "dist", "build", ".next", ".nuxt", "__pycache__",
             ".venv", "venv", "coverage", "public/build"}


def scan_project(root: str, needle: str, ignore: List[str], limit: int = 50) -> List[str]:
    hits = []
    needle = needle.lower()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            ext = os.path.splitext(fn)[1].lower() or ("." + fn.lstrip(".") if fn.startswith(".") else "")
            if ext not in TEXT_EXT and not fn.startswith(".env"):
                continue
            if any(i in rel for i in ignore):
                continue
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for n, line in enumerate(f, 1):
                        if needle in line.lower():
                            shown = P.mask_env_line(line.strip()) if fn.startswith(".env") else line.strip()
                            hits.append(f"{rel}:{n}: {shown[:140]}")
                            if len(hits) >= limit:
                                return hits
            except OSError:
                continue
    return hits


def c12_config(ctx: Context) -> Result:
    strict = ctx.phase_at_least("P3")
    r = Result("C12", "Allow-lists and configuration", "T2, T8",
               fix="Replace remaining references to the old name (base URLs, CORS origins, OAuth redirect URIs, "
                   "webhook/callback URLs, API allow-lists). Rebuild config caches (php artisan config:cache).")
    if ctx.project:
        if ctx.old:
            hits = scan_project(ctx.project, ctx.old, ctx.config.config_ignore)
            for h in hits:
                r.add(FAIL if strict else WARN, ctx.project, "old name referenced: " + h)
            if not hits:
                r.add(PASS, ctx.project, f"no reference to {ctx.old} in project text files")
        env_path = os.path.join(ctx.project, ".env")
        if os.path.exists(env_path):
            with open(env_path, encoding="utf-8", errors="ignore") as f:
                env = P.parse_env(f.read())
            for st, msg in P.evaluate_laravel_env(env, ctx.new, ctx.old):
                r.add(st, ".env", msg)
    else:
        r.add(MANUAL, "project", "pass --project <path> to scan the application configuration")
    r.add(MANUAL, "providers", "check external dashboards: payment/custody webhooks, OAuth redirect URIs, "
                               "exchange API IP allow-lists, analytics and e-mail providers")
    return r


# ---------------------------------------------------------------- C13 e-mail authentication


def _mail_new(ctx: Context, r: Result, domain: str) -> None:
    d = dns_of(ctx)
    _, txt = d.lookup(domain, "TXT")
    spfs = P.find_spf(txt)
    if len(spfs) > 1:
        r.add(FAIL, domain, f"{len(spfs)} SPF records (must be exactly one)")
    elif not spfs:
        r.add(FAIL, domain, "no SPF record")
    else:
        q = P.spf_all_qualifier(spfs[0])
        if q == "-":
            r.add(PASS, domain, f"SPF ends in -all: {spfs[0][:90]}")
        elif q == "~":
            r.add(WARN, domain, "SPF ends in ~all (softfail); prefer -all once all senders are listed")
        else:
            r.add(FAIL, domain, f"SPF does not reject unauthorised senders ({q or 'no'} all)")
    _, dtxt = d.lookup("_dmarc." + domain, "TXT")
    dm = P.parse_dmarc(dtxt)
    if not dm:
        r.add(FAIL, domain, "no DMARC record")
    else:
        p = dm.get("p", "none").lower()
        st = PASS if p == "reject" else WARN if p == "quarantine" else FAIL
        r.add(st, domain, f"DMARC p={p}" + ("" if "rua" in dm else " (no rua reporting address)"))
    selectors = ctx.config.dkim_selectors or ["default", "google", "selector1", "selector2", "k1", "k2",
                                              "s1", "s2", "mail", "dkim", "zoho", "mxvault", "hostingermail-a"]
    found = []
    for s in selectors:
        code, recs = d.lookup(f"{s}._domainkey.{domain}", "TXT")
        if code == OK and any("p=" in P.join_txt(x) for x in recs):
            found.append(s)
    if found:
        r.add(PASS, domain, "DKIM key found for selector(s): " + ", ".join(found))
    else:
        r.add(WARN, domain, "no DKIM key at common selectors (set 'dkim_selectors' in the config)")


def _mail_retired(ctx: Context, r: Result, domain: str) -> None:
    d = dns_of(ctx)
    _, mx = d.lookup(domain, "MX")
    _, txt = d.lookup(domain, "TXT")
    spfs = P.find_spf(txt)
    dm = P.parse_dmarc(d.lookup("_dmarc." + domain, "TXT")[1])
    ok = True
    if not (mx and P.is_null_mx(mx)):
        ok = False
        r.add(WARN, domain, "retired name still has MX records" if mx else "no Null MX (RFC 7505)")
    if not (spfs and P.is_null_spf(spfs[0])):
        ok = False
        r.add(WARN, domain, "retired name should publish SPF 'v=spf1 -all'")
    if not (dm and dm.get("p", "").lower() == "reject"):
        ok = False
        r.add(FAIL, domain, "retired name has no DMARC p=reject: it can be spoofed in phishing")
    if ok:
        r.add(PASS, domain, "non-mail domain: Null MX, SPF -all, DMARC reject")


def c13_email(ctx: Context) -> Result:
    r = Result("C13", "E-mail authentication", "T2, T6",
               fix="New name: one SPF ending in -all, DKIM, DMARC p=reject. Retired name: Null MX, "
                   "'v=spf1 -all', DMARC p=reject.")
    _mail_new(ctx, r, ctx.new)
    if ctx.old:
        if ctx.config.old_domain_mail == "active" or not ctx.phase_at_least("P4"):
            _mail_new(ctx, r, ctx.old)
        else:
            _mail_retired(ctx, r, ctx.old)
    return r


# ---------------------------------------------------------------- C14 retention and lookalikes


def c14_retention(ctx: Context) -> Result:
    r = Result("C14", "Retention and lookalikes", "T2, T7",
               fix="Keep the old name on auto-renew with registrar/transfer lock and MFA; monitor or "
                   "defensively register obvious lookalikes.")
    for domain in ctx.domains:
        try:
            reg = rdap_domain(domain, timeout=max(15.0, ctx.timeout * 2))
        except Exception as e:
            r.add(INFO, domain, f"RDAP lookup unavailable ({type(e).__name__}); check expiry at the registrar")
            continue
        if reg.expires:
            days = (reg.expires - datetime.now(timezone.utc)).days
            st = FAIL if days < 30 else WARN if days < 180 else PASS
            r.add(st, domain, f"registration expires in {days} days ({reg.expires.date()})"
                              + (f", registrar {reg.registrar}" if reg.registrar else ""))
        else:
            r.add(INFO, domain, "registry does not publish an expiry date via RDAP")
        if any("transfer prohibited" in s for s in reg.statuses):
            r.add(PASS, domain, "transfer lock enabled")
        else:
            r.add(WARN, domain, "no transfer lock (clientTransferProhibited) in registry status")
    d = dns_of(ctx)
    cands = P.lookalike_candidates(ctx.new)
    with ThreadPoolExecutor(12) as ex:
        live = [c for c, ok in zip(cands, ex.map(d.exists, cands)) if ok]
    if live:
        r.add(INFO, ctx.new, f"{len(live)}/{len(cands)} lookalike names are registered: " + ", ".join(live[:15]))
    else:
        r.add(PASS, ctx.new, f"none of {len(cands)} common lookalikes resolve")
    r.add(MANUAL, "registrar", "confirm MFA is enabled on every registrar and DNS-provider account")
    return r


# ---------------------------------------------------------------- registry

CHECKS: Dict[str, Callable[[Context], Result]] = {
    "C1": c1_inventory, "C2": c2_dangling, "C3": c3_delegation, "C4": c4_dnssec, "C5": c5_caa,
    "C6": c6_ct_audit, "C7": c7_tls, "C8": c8_old_host, "C9": c9_hsts, "C10": c10_redirect,
    "C11": c11_cookies, "C12": c12_config, "C13": c13_email, "C14": c14_retention,
}

# Checks that become meaningful in each phase (cumulative), following Fig. 1 of the paper.
PHASE_CHECKS = {
    "P0": ["C1", "C2", "C5", "C13", "C14"],
    "P1": ["C7", "C9", "C11", "C12"],
    "P2": ["C3", "C4", "C10"],
    "P3": ["C6", "C8"],
    "P4": [],
}


def checks_for_phase(phase: str) -> List[str]:
    out: List[str] = []
    for p in ("P0", "P1", "P2", "P3", "P4"):
        out += PHASE_CHECKS[p]
        if p == phase:
            break
    return sorted(out, key=lambda c: int(c[1:]))


def run_check(check_id: str, ctx: Context) -> Result:
    fn = CHECKS[check_id]
    try:
        return fn(ctx)
    except Exception as e:  # a failing data source must not abort the whole audit
        r = Result(check_id, fn.__name__, "")
        r.add(ERROR, "-", f"{type(e).__name__}: {e}")
        return r
