"""Passive audit of publicly announced exchange domain migrations (third-party, read-only).

    python3 -m evaluation.public_migrations --out /path/prefix

Open-redirect probes are deliberately NOT sent to third parties; for C10 only the ordinary
redirect chain of a probe path on the legacy name is followed.
"""

from __future__ import annotations

import argparse
import json
import time

from migratesafe import parsers as P
from migratesafe.checks import run_check
from migratesafe.model import Context
from migratesafe.net import follow_redirects

MIGRATIONS = [  # (legacy name, new name, year of public announcement)
    ("okex.com", "okx.com", 2022),
    ("huobi.com", "htx.com", 2023),
    ("gate.io", "gate.com", 2025),
]
CHECKS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C9", "C13", "C14"]


def audit(old: str, new: str) -> dict:
    ctx = Context(new=new, old=old, phase="P4", timeout=12, since_days=90)
    out = {}
    for cid in CHECKS:
        r = run_check(cid, ctx)
        out[cid] = {"status": r.status, "findings": [[f.status, f.target, f.message] for f in r.findings]}
    probe = "/migratesafe-probe/path?q=1"
    c10 = []
    for scheme in ("http", "https"):
        chain, last = follow_redirects(f"{scheme}://{old}{probe}", timeout=12)
        if last.error and not chain:
            c10.append(["ERROR", f"{scheme}://{old}", last.error])
            continue
        c10 += [[st, f"{scheme}://{old}", msg] for st, msg in P.evaluate_redirect_chain(chain, new, probe)]
        c10.append(["INFO", f"{scheme}://{old}", "chain: " + " -> ".join(f"{s} {l}" for s, l in chain)])
    out["C10-chain"] = {"findings": c10}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    res = {"measured_utc": time.strftime("%Y-%m-%d %H:%M", time.gmtime()), "migrations": {}}
    for old, new, year in MIGRATIONS:
        print(f"auditing {old} -> {new}", flush=True)
        res["migrations"][f"{old}->{new}"] = {"year": year, "results": audit(old, new)}
    with open(a.out + ".json", "w") as f:
        json.dump(res, f, indent=1)
    print("done")


if __name__ == "__main__":
    main()
