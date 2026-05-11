"""osint command-line tool: correlate | summarise."""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from osint.engine import CorrelationEngine  # noqa: E402
from osint.sources import load_all_fixtures  # noqa: E402
from osint.resolver import EntityResolver  # noqa: E402
from osint.pivot import PivotEngine  # noqa: E402


def _engine(args):
    sources = load_all_fixtures(args.fixture_dir)
    res = EntityResolver(min_edge_weight=args.min_edge_weight)
    piv = PivotEngine(top_k=args.top_k)
    return CorrelationEngine(sources, resolver=res, pivot_engine=piv)


def cmd_correlate(args):
    engine = _engine(args)
    seeds = args.seed if args.seed else []
    result = engine.correlate(seeds)
    out = result.to_dict()
    if args.compact:
        # Drop the full graph for legibility
        del out["graph"]
    print(json.dumps(out, indent=2))


def cmd_summarise(args):
    from llm_client import LLMClient
    from osint.summariser import LLMIntelSummariser
    engine = _engine(args)
    seeds = args.seed if args.seed else []
    result = engine.correlate(seeds)
    summariser = LLMIntelSummariser(LLMClient(timeout=180), model=args.llm_model)
    report = summariser.summarise(
        pivots=result.pivots, clusters=result.clusters,
        source_coverage=result.source_coverage,
        seed_query=", ".join(seeds),
    )
    print(json.dumps({
        "result": result.to_dict(),
        "report": report.to_dict(),
    }, indent=2, default=str))


def main(argv=None):
    p = argparse.ArgumentParser(prog="osint")
    p.add_argument("--fixture-dir", default="fixtures")
    p.add_argument("--min-edge-weight", type=float, default=1.0)
    p.add_argument("--top-k", type=int, default=10)
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("correlate", help="run correlation, dump JSON")
    pc.add_argument("--seed", action="append", required=True,
                       help="seed query (domain/email/username/ip)")
    pc.add_argument("--compact", action="store_true",
                       help="omit full node/edge dump")
    pc.set_defaults(func=cmd_correlate)

    ps = sub.add_parser("summarise", help="LLM intel summary")
    ps.add_argument("--seed", action="append", required=True)
    ps.add_argument("--llm-model", default="glm-5.1")
    ps.set_defaults(func=cmd_summarise)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
