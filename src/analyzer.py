"""
End-to-end pipeline: seed package -> JSON suspicion report.

Wires the four other modules together:

    crawler   ->   graph   ->   osv_client   ->   scoring   ->   report dict

The returned dict is the public API for any presentation layer (CLI, web UI,
notebook). It's intentionally JSON-serializable so a UI can ``json.dumps``
it directly to its frontend.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .crawler import NpmCrawler
from .graph import DiGraph
from .osv_client import OsvClient
from .scoring import Scorer


# A small whitelist of high-traffic npm packages used as the typosquat
# reference set. Hand-curated for v0; could be replaced by a live download
# ranking pull in a future iteration.
POPULAR_NPM_PACKAGES: List[str] = [
    "express", "react", "react-dom", "lodash", "axios", "moment",
    "vue", "angular", "jquery", "webpack", "typescript", "eslint",
    "prettier", "request", "underscore", "async", "chalk", "commander",
    "debug", "fs-extra", "uuid", "yargs", "bluebird", "minimist",
    "rimraf", "glob", "mkdirp", "semver", "ws", "redux", "next",
    "vue-router", "react-redux", "body-parser", "cookie-parser",
    "morgan", "cors", "helmet", "dotenv", "node-fetch", "got",
    "ramda", "rxjs", "leftpad", "left-pad", "is-odd", "is-even",
    "qs", "minimatch", "ms",
]


def analyze(
    seed: str,
    max_depth: int = 5,
    include_dev: bool = False,
    output: Optional[Path] = None,
    crawler: Optional[NpmCrawler] = None,
    osv_client: Optional[OsvClient] = None,
    scorer: Optional[Scorer] = None,
) -> Dict[str, Any]:
    """Run the full pipeline and return a JSON-serializable report.

    The optional ``crawler``/``osv_client``/``scorer`` parameters exist so
    tests, notebooks, and a future UI can inject their own caches or
    custom-tuned scorers without rebuilding the whole pipeline.
    """
    crawler = crawler or NpmCrawler(
        max_depth=max_depth, include_dev=include_dev
    )
    osv_client = osv_client or OsvClient()
    scorer = scorer or Scorer(popular_names=POPULAR_NPM_PACKAGES)

    # crawler.crawl is BFS internally and writes Node.depth as it goes,
    # so every fetched node already carries its correct depth.
    graph: DiGraph = crawler.crawl(seed)

    cycles = graph.find_cycles()
    _, in_degrees = graph.topological_sort()
    osv_hits = osv_client.annotate_graph(graph)
    scores = scorer.score_graph(graph, osv_hits, in_degrees)

    max_depth_observed = max(
        (n.depth for n in graph.nodes() if n.depth is not None),
        default=0,
    )

    top_in_degree = sorted(
        in_degrees.items(), key=lambda kv: kv[1], reverse=True
    )[:10]

    flagged: List[Dict[str, Any]] = []
    for s in scores:
        if not s.flagged:
            continue
        node = graph.get_node(s.name)
        paths = graph.dfs_paths(seed, s.name, max_paths=1)
        flagged.append({
            "name": s.name,
            "version": node.version,
            "depth": node.depth,
            "total": round(s.total, 4),
            "signals": {
                "osv": round(s.osv, 4),
                "downloads": round(s.downloads, 4),
                "ownership": round(s.ownership, 4),
                "typosquat": round(s.typosquat, 4),
                "in_degree": round(s.in_degree, 4),
            },
            "osv_ids": list(node.osv_ids),
            "weekly_downloads": node.weekly_downloads,
            "path": paths[0] if paths else [s.name],
            "reasons": list(s.reasons),
        })

    report: Dict[str, Any] = {
        "seed": seed,
        "stats": {
            "nodes": len(graph),
            "edges": graph.edge_count(),
            "max_depth": max_depth_observed,
            "cycle_count": len(cycles),
        },
        "cycles": cycles,
        "top_in_degree": [
            {"name": n, "in_degree": d} for n, d in top_in_degree
        ],
        "flagged": flagged,
    }

    if output is not None:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2))

    return report
