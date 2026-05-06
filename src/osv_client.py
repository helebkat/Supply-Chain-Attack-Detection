"""
OSV (Open Source Vulnerability) database client.

Looks up every package in the crawled graph against https://osv.dev to
determine which packages have a known vulnerability for the resolved
version we picked.

Reference
---------
POST https://api.osv.dev/v1/query
body: {"package": {"ecosystem": "npm", "name": "<package>"}}

Response excerpt (the famous event-stream supply-chain attack):

    {
      "vulns": [
        {
          "id": "GHSA-mh6f-8j2x-4483",
          "summary": "Critical severity vulnerability ...",
          "database_specific": {"severity": "CRITICAL"},
          "affected": [
            {
              "package": {"name": "event-stream", "ecosystem": "npm"},
              "ranges": [
                {"type": "SEMVER",
                 "events": [{"introduced": "3.3.6"},
                            {"fixed": "4.0.0"}]}
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
from typing import Any, Dict, List, Optional

import requests
from packaging.version import InvalidVersion, Version


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
USER_AGENT = "MSML606-SupplyChainProject/0.1 (+student-research)"


@dataclass
class Vulnerability:
    osv_id: str
    summary: str
    severity: Optional[str]
    affected_ranges: List[dict] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)


def _safe_filename(package: str) -> str:
    """Mirror crawler._safe_filename: scoped names like ``@scope/name`` need
    their slash sanitized before we use them as filenames."""
    return package.replace("/", "__")


class OsvClient:
    def __init__(
        self,
        cache_dir: Path = Path("data/cache/osv"),
        timeout_s: float = 10.0,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_s = timeout_s

    # --- HTTP-with-cache primitive ------------------------------------------
    def query(self, package: str) -> List[Vulnerability]:
        """POST ``{ecosystem: npm, name: package}`` to OSV.

        Cache the raw response (including empty results) so a clean package
        doesn't re-hit OSV on every analyzer run.
        """
        cache_path = self.cache_dir / f"{_safe_filename(package)}.json"

        if cache_path.exists():
            data = json.loads(cache_path.read_text())
        else:
            try:
                response = requests.post(
                    OSV_QUERY_URL,
                    json={"package": {"ecosystem": "npm", "name": package}},
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout_s,
                )
                if response.status_code == 200:
                    data = response.json()
                else:
                    data = {"vulns": []}
            except requests.RequestException:
                data = {"vulns": []}
            cache_path.write_text(json.dumps(data))

        return _parse_vulns(data, package)

    # --- pure helper, easy unit-testable -------------------------------------
    @staticmethod
    def version_in_range(
        version: Optional[str],
        ranges: List[dict],
        versions: Optional[List[str]] = None,
    ) -> bool:
        """Return True if ``version`` is matched by any OSV range entry, with
        an exact-membership fallback against ``versions``.

        Walks each range's events left-to-right, flipping an ``inside``
        boolean on ``introduced`` / ``fixed`` / ``last_affected``.
        ``introduced: "0"`` is the OSV idiom for "all versions affected".
        """
        if version is None:
            return False

        try:
            v = Version(version)
        except (InvalidVersion, TypeError):
            v = None

        if ranges and v is not None:
            for r in ranges:
                if _version_matches_events(v, r.get("events") or []):
                    return True

        if versions:
            return version in versions

        return False

    # --- bulk operation over a graph ----------------------------------------
    def annotate_graph(self, graph) -> Dict[str, List[Vulnerability]]:
        """Run ``query()`` for every node, attach matching OSV ids onto each
        Node, and return the full hit map for the scorer."""
        result: Dict[str, List[Vulnerability]] = {}
        for node in graph.nodes():
            vulns = self.query(node.name)
            hits = [
                v for v in vulns
                if self.version_in_range(
                    node.version, v.affected_ranges, v.affected_versions
                )
            ]
            node.osv_ids = [v.osv_id for v in hits]
            if hits:
                result[node.name] = hits
        return result


# -----------------------------------------------------------------------------
# private helpers
# -----------------------------------------------------------------------------
def _parse_vulns(data: Any, package: str) -> List[Vulnerability]:
    """Convert a raw OSV response dict into a list of Vulnerability objects,
    keeping only the affected[] entries that actually target ``package``."""
    if not isinstance(data, dict):
        return []
    raw = data.get("vulns") or []
    if not isinstance(raw, list):
        return []

    out: List[Vulnerability] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        osv_id = entry.get("id")
        if not isinstance(osv_id, str) or not osv_id:
            continue

        summary = entry.get("summary", "") or ""
        severity = (entry.get("database_specific") or {}).get("severity")

        affected_ranges: List[dict] = []
        affected_versions: List[str] = []
        for aff in entry.get("affected") or []:
            pkg = (aff or {}).get("package") or {}
            if pkg.get("name") != package:
                continue
            for r in aff.get("ranges") or []:
                if isinstance(r, dict):
                    affected_ranges.append(r)
            for v in aff.get("versions") or []:
                if isinstance(v, str):
                    affected_versions.append(v)

        out.append(
            Vulnerability(
                osv_id=osv_id,
                summary=summary,
                severity=severity if isinstance(severity, str) else None,
                affected_ranges=affected_ranges,
                affected_versions=affected_versions,
            )
        )
    return out


def _version_matches_events(v: Version, events: List[dict]) -> bool:
    """State-machine walk over a single OSV range's events list."""
    inside = False
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            intro = ev["introduced"]
            if intro == "0":
                inside = True
                continue
            try:
                if v >= Version(intro):
                    inside = True
            except (InvalidVersion, TypeError):
                continue
        elif "fixed" in ev:
            try:
                if v >= Version(ev["fixed"]):
                    inside = False
            except (InvalidVersion, TypeError):
                continue
        elif "last_affected" in ev:
            try:
                if v > Version(ev["last_affected"]):
                    inside = False
            except (InvalidVersion, TypeError):
                continue
    return inside
