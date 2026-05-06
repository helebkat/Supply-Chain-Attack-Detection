"""
Command-line entry point.

Usage:
    python -m src.cli express
    python -m src.cli express --max-depth 4 --output reports/express.json
    python -m src.cli react --include-dev
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict

from .analyzer import analyze


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="supply-chain-detector",
        description="npm transitive dependency security analyzer",
    )
    p.add_argument(
        "seed",
        help="seed npm package name (e.g. 'express')",
    )
    p.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="how deep to crawl the dependency tree (default: 5)",
    )
    p.add_argument(
        "--include-dev",
        action="store_true",
        help="also include devDependencies (much larger graph)",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write the full JSON report to this path",
    )
    return p


def _print_human_summary(report: Dict[str, Any]) -> None:
    s = report["stats"]
    print()
    print(
        f"{report['seed']}: {s['nodes']} nodes, {s['edges']} edges, "
        f"max depth {s['max_depth']}, {s['cycle_count']} cycles"
    )

    top = report.get("top_in_degree", [])[:5]
    if top:
        print("\nTop in-degree (highest blast radius):")
        for entry in top:
            print(f"  {entry['name']:<32}  in-degree={entry['in_degree']}")

    flagged = report.get("flagged", [])
    if not flagged:
        print("\nNo suspicious packages detected.")
        return

    print(f"\nFlagged ({len(flagged)} package(s)):\n")
    for f in flagged:
        version = f.get("version") or "?"
        depth = f.get("depth")
        depth_str = "?" if depth is None else str(depth)
        print(f"  [{f['total']:.2f}] {f['name']}@{version}  depth={depth_str}")
        path = f.get("path") or []
        if path:
            print(f"     path: {' -> '.join(path)}")
        for reason in f.get("reasons", []):
            print(f"     - {reason}")
        print()


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        report = analyze(
            seed=args.seed,
            max_depth=args.max_depth,
            include_dev=args.include_dev,
            output=args.output,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    _print_human_summary(report)

    if args.output is not None:
        print(f"\nFull JSON report written to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
