"""
End-to-end pipeline: seed package -> JSON suspicion report.

This module wires together everyone else's work:
   crawler (Helen)  ->  graph (Helen)  ->  osv (Yaxita)  ->  scoring (Yaxita)
                                                          ->  report

OWNER: Yaxita Amin (consumes Helen's graph + crawler)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .crawler import NpmCrawler
from .graph import DiGraph
from .osv_client import OsvClient
from .scoring import Scorer


def analyze(
    seed: str,
    max_depth: int = 5,
    include_dev: bool = False,
    output: Optional[Path] = None,
) -> dict:
    """Run the full pipeline, return the report dict, and optionally write it.

    Report shape (target):
        {
          "seed": "express",
          "stats": {"nodes": int, "edges": int, "max_depth": int,
                    "cycle_count": int},
          "cycles": [["a", "b", "a"], ...],
          "top_in_degree": [
              {"name": "ms", "in_degree": 12}, ...   # top 10
          ],
          "flagged": [
              {
                "name": "event-stream",
                "version": "3.3.6",
                "depth": 4,
                "total": 0.86,
                "signals": {"osv": 1.0, "downloads": 0.7, ...},
                "osv_ids": ["GHSA-mh6f-8j2x-4483"],
                "path": ["express", "body-parser", "qs", "...", "event-stream"],
                "reasons": ["OSV: [GHSA-...]", "anomalously low downloads"]
              },
              ...
          ]
        }

    TODO (Yaxita):
      1. crawler = NpmCrawler(max_depth=max_depth, include_dev=include_dev)
         graph: DiGraph = crawler.crawl(seed)
      2. graph.bfs(seed)                       # populates Node.depth
      3. cycles = graph.find_cycles()
      4. order, in_degrees = graph.topological_sort()
      5. osv_hits = OsvClient().annotate_graph(graph)
      6. scorer = Scorer(popular_names=_load_popular_names())
         scores = scorer.score_graph(graph, osv_hits, in_degrees)
      7. Build the report dict above. For each flagged node, call
         graph.dfs_paths(seed, node.name, max_paths=1) to attach provenance.
      8. If `output`: output.parent.mkdir(parents=True, exist_ok=True)
                     output.write_text(json.dumps(report, indent=2))
      9. Return report.
    """
    raise NotImplementedError


def _load_popular_names() -> list[str]:
    """Top-N npm package names by weekly downloads, used for typosquat distance.

    TODO (Yaxita):
      - For v0 you can hard-code a small whitelist:
          ["express", "react", "lodash", "axios", "moment", ...]
      - Stretch goal: pull from
          https://api.npmjs.org/downloads/range/last-week  (with a fixed list)
        or commit a static `data/popular.txt` and read from disk.
    """
    raise NotImplementedError
