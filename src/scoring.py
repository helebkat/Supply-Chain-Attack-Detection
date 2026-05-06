"""
Suspicion scoring heuristic.

Combines five signals into a single 0..1 score per package:

  Signal              Weight   What it captures
  ------------------  ------   --------------------------------------------
  OSV hit             0.50     hard ground-truth label
  Low downloads       0.15     near-zero downloads under a popular parent
  Recent ownership    0.15     maintainer transfer < N days ago
  Typosquatting       0.10     Levenshtein <= 2 to a top-1k package name
  High in-degree      0.10     amplifier: many packages depend on this node

OWNER: Yaxita Amin
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .graph import DiGraph, Node
from .osv_client import Vulnerability


# Tuned during evaluation -- import this constant elsewhere, do not
# hard-code 0.30 in callers.
DEFAULT_THRESHOLD = 0.30


@dataclass
class Score:
    name: str
    total: float
    osv: float = 0.0
    downloads: float = 0.0
    ownership: float = 0.0
    typosquat: float = 0.0
    in_degree: float = 0.0
    flagged: bool = False
    reasons: List[str] = field(default_factory=list)   # human-readable bullets


class Scorer:
    WEIGHTS = {
        "osv":       0.50,
        "downloads": 0.15,
        "ownership": 0.15,
        "typosquat": 0.10,
        "in_degree": 0.10,
    }

    def __init__(
        self,
        popular_names: Optional[List[str]] = None,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        # TODO (Yaxita):
        #   - self.popular = [n.lower() for n in (popular_names or [])]
        #   - self.threshold = threshold
        raise NotImplementedError

    # --- individual signals (each returns a float in [0, 1]) ----------------
    def _osv_signal(self, vulns: List[Vulnerability]) -> float:
        """1.0 if any CRITICAL or HIGH; 0.6 MODERATE; 0.3 LOW; 0.0 otherwise.
        TODO (Yaxita): pick max severity across vulns and map.
        """
        raise NotImplementedError

    def _downloads_signal(
        self, node: Node, parent_downloads: Optional[int]
    ) -> float:
        """Anomaly when a node has near-zero downloads under a popular parent.

        TODO (Yaxita):
          - If node.weekly_downloads is None, return 0 (no signal).
          - If node.weekly_downloads < 50 AND parent_downloads and
            parent_downloads > 100_000  -> return 1.0 (very suspicious).
          - Else, smooth ramp:
                ratio = (node.weekly_downloads + 1) / (parent_downloads + 1)
                return max(0.0, 1.0 - min(1.0, ratio * 1000))
            (calibrate during evaluation; this is a starting point.)
        """
        raise NotImplementedError

    def _ownership_signal(self, node: Node) -> float:
        """Recent maintainer transfer is suspicious.

        TODO (Yaxita):
          - The crawler doesn't currently stash 'days_since_owner_change'.
            Either:
              (a) extend Node with that field and have Helen populate it
                  from manifest['time'] history, OR
              (b) for v0, return 0.0 here and add it as a stretch goal.
          - When implemented:
              < 30 days -> 1.0
              < 90 days -> 0.6
              < 180 days -> 0.3
              else -> 0.0
        """
        raise NotImplementedError

    def _typosquat_signal(self, name: str) -> float:
        """Levenshtein <= 2 to a popular name.

        TODO (Yaxita):
          - If self.popular is empty, return 0.0.
          - Compute min Levenshtein distance between name.lower() and any
            element of self.popular. Hand-write the standard DP (two-row
            table); do NOT add a dependency just for this.
          - Distance 0 -> 0.0 (exact = legit, not a typosquat).
          - Distance 1 -> 1.0
          - Distance 2 -> 0.5
          - Else -> 0.0
        """
        raise NotImplementedError

    def _in_degree_signal(self, in_degree: int, max_in_degree: int) -> float:
        """Normalize in-degree to [0,1]; amplifies the other signals.
        TODO (Yaxita): in_degree / max(max_in_degree, 1).
        """
        raise NotImplementedError

    # --- public API ---------------------------------------------------------
    def score_graph(
        self,
        graph: DiGraph,
        osv_hits: Dict[str, List[Vulnerability]],
        in_degrees: Dict[str, int],
    ) -> List[Score]:
        """Compute a Score per node, sorted descending by total.

        TODO (Yaxita):
          1. max_in = max(in_degrees.values(), default=1)
          2. results = []
          3. For each node in graph.nodes():
                 vulns = osv_hits.get(node.name, [])
                 # parent downloads = max over node's parents (popular parent
                 # is what makes a low-download child suspicious)
                 parents = graph.parents(node.name)
                 parent_dl = max(
                     (graph.get_node(p).weekly_downloads or 0 for p in parents),
                     default=0,
                 )
                 osv = self._osv_signal(vulns)
                 dl  = self._downloads_signal(node, parent_dl)
                 own = self._ownership_signal(node)
                 typ = self._typosquat_signal(node.name)
                 ind = self._in_degree_signal(
                           in_degrees.get(node.name, 0), max_in)
                 total = (self.WEIGHTS["osv"]       * osv
                        + self.WEIGHTS["downloads"] * dl
                        + self.WEIGHTS["ownership"] * own
                        + self.WEIGHTS["typosquat"] * typ
                        + self.WEIGHTS["in_degree"] * ind)
                 reasons = []
                 if osv > 0:  reasons.append(f"OSV: {[v.osv_id for v in vulns]}")
                 if dl  > 0.5: reasons.append("anomalously low downloads")
                 if own > 0.5: reasons.append("recent maintainer change")
                 if typ > 0.5: reasons.append("typosquat candidate")
                 results.append(Score(
                     name=node.name, total=total,
                     osv=osv, downloads=dl, ownership=own,
                     typosquat=typ, in_degree=ind,
                     flagged=total >= self.threshold,
                     reasons=reasons,
                 ))
          4. Return sorted(results, key=lambda s: s.total, reverse=True)
        """
        raise NotImplementedError
