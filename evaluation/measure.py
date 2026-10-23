"""Passive, read-only measurement of migration-readiness controls across many domains.

    python3 -m evaluation.measure domains.txt --out evaluation/measurement

Runs only the checks that need no operator input and send no probes beyond ordinary
DNS queries, one HTTPS GET of the home page, and TLS handshakes:
C3 delegation, C4 DNSSEC, C5 CAA, C7 TLS, C9 HSTS, C13 e-mail authentication.
Results are reported in aggregate; per-domain rows stay local unless anonymized.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

from migratesafe import __version__
from migratesafe.checks import run_check
from migratesafe.model import ERROR, FAIL, PASS, Context

CHECKS = ["C3", "C4", "C5", "C7", "C9", "C13"]


def features(domain: str, timeout: float) -> Dict[str, object]:
    ctx = Context(new=domain, old=None, phase="P3", timeout=timeout)
    res = {cid: run_check(cid, ctx) for cid in CHECKS}
    msgs = {cid: " | ".join(f"{f.status}:{f.message}" for f in r.findings) for cid, r in res.items()}
    c13 = msgs["C13"]
    m = re.search(r"DMARC p=(\w+)", c13)
    dmarc = m.group(1).lower() if m else ("missing" if "no DMARC record" in c13 else "unknown")
    if "no SPF record" in c13:
        spf = "missing"
    elif "SPF ends in -all" in c13:
        spf = "-all"
    elif "~all" in c13:
        spf = "~all"
    elif "SPF records (must be exactly one)" in c13:
        spf = "multiple"
    else:
        spf = "weak"
    tls_ok = "valid chain" in msgs["C7"]  # at least one verified handshake from this vantage point
    return {
        "domain": domain,
        "tls_ok": tls_ok,
        "http_ok": res["C9"].status != ERROR,
        "ns_consistent": res["C3"].status == PASS,
        "dnssec": res["C4"].status == PASS,
        "dnssec_bogus": "validation fails" in msgs["C4"],
        "caa": res["C5"].status != FAIL and res["C5"].status != ERROR,
        "caa_iodef": res["C5"].status == PASS,
        "legacy_tls_accepted": "still accepts" in msgs["C7"],
        "hsts": res["C9"].status not in (FAIL, ERROR),
        "hsts_strong": res["C9"].status == PASS,
        "hsts_error": res["C9"].status == ERROR,
        "spf": spf,
        "dmarc": dmarc,
        "dkim_found": "DKIM key found" in c13,
        "statuses": {cid: r.status for cid, r in res.items()},
        "findings": {cid: [[f.status, f.target, f.message] for f in r.findings] for cid, r in res.items()},
    }


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100.0 * n / d:.1f}%)" if d else "0/0"


def summarize(rows: List[Dict[str, object]]) -> Dict[str, object]:
    n = len(rows)
    tls = [r for r in rows if r["tls_ok"]]
    http = [r for r in rows if r["http_ok"]]
    s = {
        "domains": n,
        "tls_handshake_ok_from_vantage": len(tls),
        "https_response_from_vantage": len(http),
        "ns_consistent": pct(sum(r["ns_consistent"] for r in rows), n),
        "dnssec_signed_and_valid": pct(sum(r["dnssec"] for r in rows), n),
        "dnssec_bogus": pct(sum(r["dnssec_bogus"] for r in rows), n),
        "caa_present": pct(sum(r["caa"] for r in rows), n),
        "caa_with_iodef": pct(sum(r["caa_iodef"] for r in rows), n),
        "hsts_present": pct(sum(r["hsts"] for r in http), len(http)),
        "hsts_1y_includeSubDomains": pct(sum(r["hsts_strong"] for r in http), len(http)),
        "legacy_tls_accepted": pct(sum(r["legacy_tls_accepted"] for r in tls), len(tls)),
        "spf": dict(Counter(r["spf"] for r in rows)),
        "dmarc": dict(Counter(r["dmarc"] for r in rows)),
        "dmarc_enforcing(reject|quarantine)": pct(sum(r["dmarc"] in ("reject", "quarantine") for r in rows), n),
        "dkim_found_common_selectors": pct(sum(r["dkim_found"] for r in rows), n),
        "caa_and_hsts_and_dmarc_enforcing": pct(sum(r["caa"] and r["hsts"] and r["dmarc"] in ("reject", "quarantine")
                                                    for r in http), len(http)),
    }
    return s


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("domains")
    ap.add_argument("--out", default="evaluation/measurement")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=8.0)
    a = ap.parse_args()
    domains = [l.strip().lower() for l in open(a.domains) if l.strip() and not l.startswith("#")]
    t0 = time.time()
    rows: List[Dict[str, object]] = []
    with ThreadPoolExecutor(a.workers) as ex:
        for i, row in enumerate(ex.map(lambda d: features(d, a.timeout), domains), 1):
            rows.append(row)
            if i % 25 == 0:
                print(f"{i}/{len(domains)} done", flush=True)
    summary = summarize(rows)
    summary.update({"tool_version": __version__, "seconds": round(time.time() - t0),
                    "measured_utc": time.strftime("%Y-%m-%d %H:%M", time.gmtime())})
    with open(a.out + "_rows.json", "w") as f:
        json.dump(rows, f, indent=1)
    with open(a.out + "_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
