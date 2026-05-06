"""
OSV (Open Source Vulnerability) database client.

Looks up every package in the crawled graph against https://osv.dev to
determine which packages have a known vulnerability for the resolved
version we picked.

OWNER: Yaxita Amin

Reference
---------
POST https://api.osv.dev/v1/query
body: {"package": {"ecosystem": "npm", "name": "<package>"}}

Sample response shape:
{
  "vulns": [
    {
      "id": "GHSA-mh6f-8j2x-4483",
      "summary": "...",
      "severity": [{"type": "CVSS_V3", "score": "..."}],
      "database_specific": {"severity": "CRITICAL"},
      "affected": [
        {
          "package": {"name": "event-stream", "ecosystem": "npm"},
          "ranges": [
            {"type": "SEMVER",
             "events": [{"introduced": "3.3.6"}, {"fixed": "4.0.0"}]}
          ],
          "versions": ["3.3.6"]
        }
      ]
    }
  ]
}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


@dataclass
class Vulnerability:
    osv_id: str                     # e.g. "GHSA-mh6f-8j2x-4483"
    summary: str
    severity: Optional[str]         # "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | None
    affected_ranges: List[dict] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)


def _safe_filename(package: str) -> str:
    """`@scope/name` -> `@scope__name`. Mirrors crawler._safe_filename.
    TODO (Yaxita): trivial; replace '/' with '__'.
    """
    raise NotImplementedError


class OsvClient:
    def __init__(
        self,
        cache_dir: Path = Path("data/cache/osv"),
        timeout_s: float = 10.0,
    ) -> None:
        # TODO (Yaxita): mkdir on cache_dir, store kwargs.
        raise NotImplementedError

    # --- HTTP-with-cache primitive ------------------------------------------
    def query(self, package: str) -> List[Vulnerability]:
        """POST {ecosystem: npm, name: <package>} to OSV; return parsed list.

        TODO (Yaxita):
          1. cache_path = self.cache_dir / f"{_safe_filename(package)}.json"
             If exists, json.load it and skip the network.
          2. Else requests.post(OSV_QUERY_URL,
                                json={"package": {"ecosystem": "npm",
                                                  "name": package}},
                                timeout=self.timeout_s)
             cache_path.write_text(response.text) regardless of empty result
             (so we don't re-hit OSV for clean packages every run).
          3. data = json.loads(...). If "vulns" missing, return [].
          4. For each entry in data["vulns"]:
               - id = entry["id"]
               - summary = entry.get("summary", "")
               - severity = entry.get("database_specific", {}).get("severity")
               - For the affected[] entry whose package.name == package:
                   ranges = that entry.get("ranges", [])
                   versions = that entry.get("versions", [])
               -> Vulnerability(...)
          5. Return the list.
        """
        raise NotImplementedError

    # --- pure helper, easy unit-testable -------------------------------------
    @staticmethod
    def version_in_range(version: str, ranges: List[dict],
                         versions: Optional[List[str]] = None) -> bool:
        """Return True if `version` is matched by any range in `ranges`
        (or, as a fallback, is exactly listed in `versions`).

        OSV ranges look like:
            {"type": "SEMVER",
             "events": [{"introduced": "3.3.6"}, {"fixed": "4.0.0"}]}

        Semantics:
          - "introduced" flips an "in-range" flag ON.
          - "fixed" flips it OFF (fixed is EXCLUSIVE).
          - "last_affected" flips it OFF inclusively (rarely used in npm).
          - Multiple introduced/fixed pairs can chain in one events[] list.

        TODO (Yaxita):
          - If `version` is None, return False.
          - Walk events left-to-right with an `inside` boolean.
          - Compare with packaging.version.Version. If parsing throws, fall
            back to string equality.
          - If no `ranges` matched but `versions` is non-empty, return
            (version in versions).
        """
        raise NotImplementedError

    # --- bulk operation over a graph ----------------------------------------
    def annotate_graph(self, graph) -> Dict[str, List[Vulnerability]]:
        """Run query() for every node in `graph`, attach matching OSV ids
        directly onto each Node, and return the full hit map for the scorer.

        TODO (Yaxita):
          1. result: dict[str, list[Vulnerability]] = {}
          2. For each node in graph.nodes():
                 hits = self.query(node.name)
                 hits = [v for v in hits
                         if self.version_in_range(node.version,
                                                  v.affected_ranges,
                                                  v.affected_versions)]
                 node.osv_ids = [v.osv_id for v in hits]
                 if hits:
                     result[node.name] = hits
          3. Return result.

        Note: graph is typed loosely on purpose to avoid a circular import
        with src.graph; treat it as duck-typed (must expose .nodes()).
        """
        raise NotImplementedError
