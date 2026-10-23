from __future__ import annotations

import argparse
import json
import ssl
import sys
from typing import List, Optional

from . import PAPER_DOI, __version__
from .checks import CHECKS, checks_for_phase, run_check
from .model import PHASES, Config, Context
from .report import exit_code, render_json, render_text, write_file

TITLES = {
    "C1": "Zone inventory", "C2": "Dangling targets", "C3": "Delegation", "C4": "DNSSEC",
    "C5": "CAA records", "C6": "Certificate Transparency audit", "C7": "New-origin TLS",
    "C8": "Former-host keys", "C9": "HSTS", "C10": "Legacy redirect", "C11": "Session cookies",
    "C12": "Allow-lists and configuration", "C13": "E-mail authentication", "C14": "Retention and lookalikes",
}


def _domain(value: str) -> str:
    v = value.strip().lower()
    for prefix in ("https://", "http://"):
        if v.startswith(prefix):
            v = v[len(prefix):]
    v = v.split("/")[0].rstrip(".")
    if "." not in v:
        raise argparse.ArgumentTypeError(f"not a domain name: {value}")
    return v


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="migratesafe",
        description="Read-only security audit for domain migrations "
                    f"(MigrateSafe checks C1-C14, doi:{PAPER_DOI}). Only audit domains you own or are "
                    "authorised to test.")
    p.add_argument("--version", action="version", version=f"migratesafe {__version__}")
    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("audit", help="run the checks")
    a.add_argument("--new", required=True, type=_domain, help="new primary domain")
    a.add_argument("--old", type=_domain, help="old (legacy) domain, if migrating")
    a.add_argument("--phase", choices=PHASES, default="P3",
                   help="migration phase; runs the checks relevant up to this phase (default P3)")
    a.add_argument("--checks", help="comma-separated subset, e.g. C2,C5,C13 (overrides --phase)")
    a.add_argument("--config", help="JSON file with inventory, allowed_issuers, dkim_selectors, old_host_ip, ...")
    a.add_argument("--project", help="path to the application source to scan for the old name (C12)")
    a.add_argument("--since-days", type=int, default=30, help="CT look-back window for C6 (default 30)")
    a.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds")
    a.add_argument("--json", metavar="FILE", help="also write a JSON report")
    a.add_argument("-v", "--verbose", action="store_true", help="show PASS/INFO details for every check")
    a.add_argument("--no-color", action="store_true")

    sub.add_parser("list", help="list the checks")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "list":
        for cid in CHECKS:
            phase = next(ph for ph in PHASES if cid in checks_for_phase(ph))
            print(f"{cid:<4} {TITLES[cid]:<32} from {phase}")
        return 0
    if args.cmd != "audit":
        build_parser().print_help()
        return 0

    config = Config()
    if args.config:
        with open(args.config, encoding="utf-8") as f:
            config = Config.from_dict(json.load(f))
    ctx = Context(new=args.new, old=args.old, phase=args.phase, project=args.project,
                  since_days=args.since_days, timeout=args.timeout, config=config)

    if args.checks:
        ids = [c.strip().upper() for c in args.checks.split(",") if c.strip()]
        unknown = [c for c in ids if c not in CHECKS]
        if unknown:
            print("unknown check(s): " + ", ".join(unknown), file=sys.stderr)
            return 64
    else:
        ids = checks_for_phase(args.phase)

    if not ssl.HAS_TLSv1_3:
        print(f"warning: this Python's TLS library ({ssl.OPENSSL_VERSION}) does not support TLS 1.3; "
              "servers that only accept TLS 1.3 will appear unreachable. Use a Python built with "
              "OpenSSL 1.1.1 or later.", file=sys.stderr)

    results = []
    for cid in ids:
        print(f"running {cid} {TITLES[cid]} ...", file=sys.stderr)
        results.append(run_check(cid, ctx))

    color = sys.stdout.isatty() and not args.no_color
    print(render_text(ctx, results, color=color, verbose=args.verbose))
    write_file(args.json, render_json(ctx, results))
    return exit_code(results)
