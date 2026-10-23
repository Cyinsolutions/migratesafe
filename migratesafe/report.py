from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional

from . import PAPER_DOI, __version__
from .model import ERROR, FAIL, INFO, MANUAL, PASS, SKIP, WARN, Context, Result

COLORS = {PASS: "32", WARN: "33", FAIL: "31", ERROR: "35", INFO: "36", MANUAL: "34", SKIP: "90"}


def _c(status: str, text: str, color: bool) -> str:
    return f"\033[{COLORS[status]}m{text}\033[0m" if color else text


def render_text(ctx: Context, results: List[Result], color: bool = True, verbose: bool = False) -> str:
    lines = [
        f"MigrateSafe {__version__} - domain migration audit",
        f"new: {ctx.new}   old: {ctx.old or '-'}   phase: {ctx.phase}   "
        f"time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]
    for r in results:
        st = r.status
        lines.append(f"{_c(st, f'[{st:^6}]', color)} {r.check_id:<4} {r.title}  ({r.threats})")
        for f in r.findings:
            if verbose or f.status not in (PASS, INFO, SKIP) or st in (PASS, INFO, SKIP):
                lines.append(f"           {_c(f.status, f'{f.status[:4]:<4}', color)}  {f.target}: {f.message}")
        if st in (FAIL, WARN, ERROR) and r.fix:
            lines.append(f"           fix: {r.fix}")
    counts = {s: sum(1 for r in results if r.status == s) for s in (PASS, WARN, FAIL, ERROR, MANUAL, INFO, SKIP)}
    lines += ["", "summary: " + "  ".join(f"{_c(s, s, color)}={n}" for s, n in counts.items() if n),
              f"method: doi:{PAPER_DOI}"]
    return "\n".join(lines)


def render_json(ctx: Context, results: List[Result]) -> str:
    return json.dumps({
        "tool": "migratesafe", "version": __version__, "paper_doi": PAPER_DOI,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "new": ctx.new, "old": ctx.old, "phase": ctx.phase,
        "results": [r.to_dict() for r in results],
    }, indent=2)


def exit_code(results: List[Result]) -> int:
    statuses = {r.status for r in results}
    if FAIL in statuses:
        return 2
    if WARN in statuses or ERROR in statuses:
        return 1
    return 0


def write_file(path: Optional[str], text: str) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
