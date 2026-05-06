"""
Suspicion scoring heuristic.

Combines five signals into a single 0..1 score per package:

  Signal              Weight   What it captures
  ------------------  ------   --------------------------------------------
  OSV hit             0.50     hard ground-truth label
  Low downloads       0.15     near-zero downloads under a popular parent
  Recent ownership    0.15     latest publish was within the last N days
  Typosquatting       0.10     Levenshtein <= 2 to a top-1k package name
  High in-degree      0.10     amplifier: many packages depend on this node
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    reasons: List[str] = field(default_factory=list)


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
        self.popular: List[str] = [
            n.lower() for n in (popular_names or []) if isinstance(n, str)
        ]
        self.threshold = threshold

    # --- individual signals (each returns a float in [0, 1]) ----------------
    def _osv_signal(self, vulns: List[Vulnerability]) -> float:
        """Map the worst severity across a node's vulns to a signal value.

        CRITICAL/HIGH -> 1.0, MODERATE -> 0.6, LOW -> 0.3, otherwise 0.0.
        Any OSV match at all is at least 0.4 (so a known vuln with no
        recorded severity still contributes meaningfully).
        """
        if not vulns:
            return 0.0
        levels = {
            "CRITICAL": 1.0,
            "HIGH":     1.0,
            "MODERATE": 0.6,
            "MEDIUM":   0.6,
            "LOW":      0.3,
        }
        best = 0.0
        for v in vulns:
            sev = (v.severity or "").upper()
            best = max(best, levels.get(sev, 0.4))
        return best

    def _downloads_signal(
        self, node: Node, parent_downloads: Optional[int]
    ) -> float:
        """Anomaly when a node has near-zero downloads under a popular parent.

        Two regimes:
          1. Hard rule: child < 50 weekly downloads AND parent > 100k -> 1.0
          2. Smooth ramp: 1 - min(1, child / parent * 1000), so a child with
             100x fewer downloads than its parent picks up ~0.9.
        """
        if node.weekly_downloads is None:
            return 0.0
        child = node.weekly_downloads
        parent = parent_downloads or 0

        if child < 50 and parent > 100_000:
            return 1.0
        if parent <= 0:
            return 0.0

        ratio = (child + 1) / (parent + 1)
        signal = 1.0 - min(1.0, ratio * 1000.0)
        return max(0.0, signal)

    def _ownership_signal(self, node: Node) -> float:
        """Recent publishes are a (rough) proxy for recent ownership change.

        The crawler stashes ``published_at`` (the ISO timestamp of the
        version we picked); we measure age in days and bucket it.
        """
        if not node.published_at:
            return 0.0
        try:
            published = datetime.fromisoformat(
                node.published_at.replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return 0.0

        age_days = (datetime.now(timezone.utc) - published).days
        if age_days < 30:
            return 1.0
        if age_days < 90:
            return 0.6
        if age_days < 180:
            return 0.3
        return 0.0

    def _typosquat_signal(self, name: str) -> float:
        """Levenshtein distance to a popular package name.

        Distance 0 (exact match) is intentionally NOT flagged -- that's a
        legitimate use of the popular package.
        """
        if not self.popular:
            return 0.0
        name_l = name.lower()
        if name_l in self.popular:
            return 0.0
        best = min(_levenshtein(name_l, p) for p in self.popular)
        if best == 1:
            return 1.0
        if best == 2:
            return 0.5
        return 0.0

    def _in_degree_signal(self, in_degree: int, max_in_degree: int) -> float:
        """Normalize in-degree to [0,1]; amplifies the other signals."""
        return in_degree / max(max_in_degree, 1)

    # --- public API ---------------------------------------------------------
    def score_graph(
        self,
        graph: DiGraph,
        osv_hits: Dict[str, List[Vulnerability]],
        in_degrees: Dict[str, int],
    ) -> List[Score]:
        """Compute a Score per node, sorted descending by total."""
        max_in = max(in_degrees.values(), default=1)
        results: List[Score] = []

        for node in graph.nodes():
            vulns = osv_hits.get(node.name, [])

            parent_dl = max(
                (graph.get_node(p).weekly_downloads or 0
                 for p in graph.parents(node.name)),
                default=0,
            )

            osv = self._osv_signal(vulns)
            dl = self._downloads_signal(node, parent_dl)
            own = self._ownership_signal(node)
            typ = self._typosquat_signal(node.name)
            ind = self._in_degree_signal(
                in_degrees.get(node.name, 0), max_in
            )

            total = (
                self.WEIGHTS["osv"]       * osv
                + self.WEIGHTS["downloads"] * dl
                + self.WEIGHTS["ownership"] * own
                + self.WEIGHTS["typosquat"] * typ
                + self.WEIGHTS["in_degree"] * ind
            )

            reasons: List[str] = []
            if vulns:
                ids = ", ".join(v.osv_id for v in vulns)
                reasons.append(f"OSV: {ids}")
            if dl >= 0.5:
                reasons.append(
                    f"low downloads ({node.weekly_downloads}/wk under "
                    f"popular parent)"
                )
            if own >= 0.5:
                reasons.append("very recent publish (possible takeover)")
            if typ >= 0.5:
                reasons.append("typosquat candidate")
            if ind >= 0.5:
                reasons.append(
                    f"high in-degree (depended on by many other packages)"
                )

            results.append(
                Score(
                    name=node.name,
                    total=total,
                    osv=osv,
                    downloads=dl,
                    ownership=own,
                    typosquat=typ,
                    in_degree=ind,
                    flagged=total >= self.threshold,
                    reasons=reasons,
                )
            )

        return sorted(results, key=lambda s: s.total, reverse=True)


# -----------------------------------------------------------------------------
# private helpers
# -----------------------------------------------------------------------------
def _levenshtein(a: str, b: str) -> int:
    """Standard two-row DP. Hand-rolled to avoid pulling in another dep just
    for one helper."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j - 1] + 1,    # insert
                prev[j] + 1,        # delete
                prev[j - 1] + cost, # substitute
            ))
        prev = curr
    return prev[-1]
