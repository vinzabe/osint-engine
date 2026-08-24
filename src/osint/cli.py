"""CLI: sweep a target across the demo sources. Exit 0 always (informational);
non-zero only on error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys

from . import __version__
from .engine import Engine
from .sources import demo_sources

EXIT_OK, EXIT_ERROR = 0, 1


def _today() -> dt.date:
    return dt.datetime.now(dt.UTC).date()


def cmd_sweep(a: argparse.Namespace) -> int:
    now = dt.date.fromisoformat(a.now) if a.now else _today()
    engine = Engine(sources=demo_sources(now))
    results = engine.sweep(a.target, now=now, include_pii=a.include_pii,
                           retention_days=a.retention,
                           merge_confidence=a.merge_confidence)
    if a.json:
        print(json.dumps([{
            "type": r.finding.type.value, "value": r.finding.value,
            "confidence": r.finding.confidence, "sources": list(r.sources),
            "corroborated": r.corroborated,
            "collected": r.finding.collected.isoformat()}
            for r in results], indent=2))
    else:
        print(f"OSINT sweep for {a.target} "
              f"({'PII included' if a.include_pii else 'PII minimised'}):\n")
        for r in results:
            mark = "✓✓" if r.corroborated else "· "
            print(f"  {mark} [{r.finding.confidence:.2f}] "
                  f"{r.finding.type.value}: {r.finding.value}")
            print(f"        sources: {', '.join(r.sources)}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="osint", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sweep", help="collect OSINT across sources")
    s.add_argument("target")
    s.add_argument("--include-pii", action="store_true",
                   help="include raw PII (default: minimised/redacted)")
    s.add_argument("--retention", type=int, default=365,
                   help="drop findings older than this many days")
    s.add_argument("--merge-confidence", type=float, default=0.0,
                   help="min confidence to keep a PII datum")
    s.add_argument("--now", help="reference date YYYY-MM-DD")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_sweep)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
