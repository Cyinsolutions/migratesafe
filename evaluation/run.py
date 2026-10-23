"""Run the fault-injection evaluation and write results.md / results.json.

    python3 -m evaluation.run [--out evaluation/results]
"""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from typing import Dict, List

from migratesafe import __version__
from migratesafe.checks import CHECKS, checks_for_phase, run_check
from migratesafe.model import ERROR, FAIL, INFO, PHASES, WARN

from .scenarios import FAULTS, baseline
from .world import simulated

FLAGGED = (FAIL, WARN, ERROR)


def audit(world) -> Dict[str, object]:
    with simulated(world) as ctx:
        return {cid: run_check(cid, ctx) for cid in CHECKS}


def first_phase(check_id: str) -> str:
    return next(p for p in PHASES if check_id in checks_for_phase(p))


def evaluate() -> Dict[str, object]:
    t0 = time.perf_counter()
    base = audit(baseline())
    base_status = {cid: r.status for cid, r in base.items()}
    false_positives = [cid for cid, st in base_status.items() if st in FLAGGED]

    rows: List[Dict[str, object]] = []
    for f in FAULTS:
        w = baseline()
        f.apply(w)
        res = audit(w)
        changed = {cid: r.status for cid, r in res.items() if r.status != base_status[cid]}
        flagged_by = sorted((c for c, st in changed.items() if st in FLAGGED), key=lambda c: int(c[1:]))
        exp = res[f.expected]
        reported = not flagged_by and any(fi.status == INFO for fi in exp.findings)
        rows.append({
            "fault": f.fid, "threat": f.threat, "description": f.description,
            "expected_check": f.expected, "expected_status": exp.status,
            "detected": f.expected in flagged_by,
            "reported_only": f.expected not in flagged_by and reported and exp.status == base_status[f.expected],
            "flagged_by": flagged_by, "earliest_phase": first_phase(f.expected),
        })
    elapsed = time.perf_counter() - t0

    by_threat = defaultdict(lambda: [0, 0])
    for r in rows:
        by_threat[r["threat"]][1] += 1
        by_threat[r["threat"]][0] += int(r["detected"])
    detected = sum(int(r["detected"]) for r in rows)
    return {
        "tool_version": __version__,
        "faults": len(rows), "detected": detected,
        "detection_rate": round(detected / len(rows), 3),
        "baseline_status": base_status, "baseline_false_positives": false_positives,
        "by_threat": {t: {"detected": d, "total": n} for t, (d, n) in sorted(by_threat.items())},
        "audits": len(rows) + 1, "seconds": round(elapsed, 2),
        "rows": rows,
    }


def to_markdown(r: Dict[str, object]) -> str:
    out = [
        "# MigrateSafe fault-injection evaluation (simulated)",
        "",
        f"Tool version {r['tool_version']}. All 14 checks were run unchanged against an in-memory world "
        "(DNS, HTTP, TLS, CT and RDAP are simulated); see `evaluation/world.py` and `evaluation/scenarios.py`.",
        "",
        f"- Injected faults: **{r['faults']}**; detected (expected check reports FAIL/WARN): "
        f"**{r['detected']}** ({r['detection_rate']:.0%})",
        f"- False positives on the correctly migrated baseline: **{len(r['baseline_false_positives'])}** "
        f"({', '.join(r['baseline_false_positives']) or 'none'})",
        f"- {r['audits']} full audits in {r['seconds']} s",
        "",
        "| Threat | Detected / injected |",
        "|---|---|",
    ]
    out += [f"| {t} | {v['detected']} / {v['total']} |" for t, v in r["by_threat"].items()]
    out += ["", "| Fault | Threat | Description | Expected check | Result | Flagged by | Detectable from |",
            "|---|---|---|---|---|---|---|"]
    for row in r["rows"]:
        result = (f"detected ({row['expected_status']})" if row["detected"]
                  else "reported as INFO only" if row["reported_only"] else "missed")
        out.append(f"| {row['fault']} | {row['threat']} | {row['description']} | {row['expected_check']} | "
                   f"{result} | {', '.join(row['flagged_by']) or '-'} | {row['earliest_phase']} |")
    out += ["", "Baseline status per check: " +
            ", ".join(f"{c} {s}" for c, s in r["baseline_status"].items()), "",
            "## Limitations", "",
            "- The faults were written by the tool's author from the threat model, so this measures whether the "
            "implementation covers the specified threats, not how often such faults occur in practice.",
            "- Network behaviour is simulated. Real deployments add noise (CDN behaviour, crt.sh lag, registries "
            "without RDAP expiry data) that this experiment does not capture.",
            "- Registered lookalike domains are deliberately reported as INFO, not WARN, because many are "
            "unrelated legitimate sites; F28 is therefore listed as reported, not flagged.", ""]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evaluation/results")
    a = ap.parse_args()
    r = evaluate()
    with open(a.out + ".json", "w", encoding="utf-8") as f:
        json.dump(r, f, indent=2)
    md = to_markdown(r)
    with open(a.out + ".md", "w", encoding="utf-8") as f:
        f.write(md)
    print(md)


if __name__ == "__main__":
    main()
