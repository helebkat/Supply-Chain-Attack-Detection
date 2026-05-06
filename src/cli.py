"""
Command-line entry point.

Usage (once the pipeline is implemented):
    python -m src.cli express
    python -m src.cli express --max-depth 4 --output reports/express.json
    python -m src.cli react --include-dev

OWNER: Yaxita Amin
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze


def _build_parser() -> argparse.ArgumentParser:
    # TODO (Yaxita):
    #   p = argparse.ArgumentParser(prog="supply-chain-detector",
    #       description="npm transitive dependency security analyzer")
    #   p.add_argument("seed", help="seed npm package name (e.g. 'express')")
    #   p.add_argument("--max-depth", type=int, default=5)
    #   p.add_argument("--include-dev", action="store_true",
    #                  help="include devDependencies (much larger graph)")
    #   p.add_argument("--output", type=Path, default=None,
    #                  help="write the full JSON report here")
    #   return p
    raise NotImplementedError


def _print_human_summary(report: dict) -> None:
    """Pretty stdout for the `flagged` section.

    TODO (Yaxita):
      - print stats line: "<seed>: N nodes, M edges, depth D, C cycles"
      - if no flagged: print 'No suspicious packages detected.'; return
      - else for each flagged item, print:
            f"[{i.total:.2f}] {i.name}@{i.version}  depth={i.depth}"
            f"   path: {' -> '.join(i.path)}"
            for r in i.reasons: f"   - {r}"
    """
    raise NotImplementedError


def main() -> None:
    # TODO (Yaxita):
    #   args = _build_parser().parse_args()
    #   report = analyze(args.seed, max_depth=args.max_depth,
    #                    include_dev=args.include_dev, output=args.output)
    #   _print_human_summary(report)
    raise NotImplementedError


if __name__ == "__main__":
    main()
