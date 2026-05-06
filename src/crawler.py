"""
npm registry BFS crawler.

Walks the npm public registry from a seed package, materializing the
transitive dependency graph into a DiGraph. Every HTTP response is cached
on disk so subsequent runs and tests are deterministic and offline-capable.

OWNER: Helen Li
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from packaging.version import InvalidVersion, Version

from .graph import DiGraph, Node


REGISTRY_BASE = "https://registry.npmjs.org"
DOWNLOADS_BASE = "https://api.npmjs.org/downloads/point/last-week"
USER_AGENT = "MSML606-SupplyChainProject/0.1 (+student-research)"


def _safe_filename(package: str) -> str:
    """Sanitize a package name for use as a filename.

    npm allows scoped packages like ``@scope/name`` which would otherwise be
    interpreted as nested directories on disk.
    """
    return package.replace("/", "__")


def _coerce_maintainer(entry: Any) -> Optional[str]:
    """Extract a maintainer name from either dict or string form."""
    if isinstance(entry, dict):
        name = entry.get("name")
        return name if isinstance(name, str) and name else None
    if isinstance(entry, str) and entry:
        return entry
    return None


class NpmCrawler:
    def __init__(
        self,
        cache_dir: Path = Path("data/cache/registry"),
        downloads_cache_dir: Path = Path("data/cache/downloads"),
        max_depth: int = 5,
        include_dev: bool = False,
        max_workers: int = 8,
        timeout_s: float = 10.0,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.downloads_cache_dir = Path(downloads_cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.downloads_cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_depth = max_depth
        self.include_dev = include_dev
        self.max_workers = max_workers
        self.timeout_s = timeout_s

    # --- HTTP-with-cache primitives -----------------------------------------
    def fetch_manifest(self, package: str) -> dict:
        """GET ``REGISTRY_BASE/<package>`` with on-disk caching.

        404s are recorded as ``{"_missing": true}`` so a yanked or invented
        package name doesn't trigger a network call on every subsequent run.
        Network errors fail the same way -- the BFS loop should keep
        crawling siblings even when one package is unreachable.
        """
        cache_path = self.cache_dir / f"{_safe_filename(package)}.json"
        if cache_path.exists():
            return json.loads(cache_path.read_text())

        try:
            response = requests.get(
                f"{REGISTRY_BASE}/{package}",
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout_s,
            )
        except requests.RequestException:
            sentinel = {"_missing": True}
            cache_path.write_text(json.dumps(sentinel))
            return sentinel

        if response.status_code == 200:
            cache_path.write_text(response.text)
            return response.json()
        if response.status_code == 404:
            sentinel = {"_missing": True}
            cache_path.write_text(json.dumps(sentinel))
            return sentinel

        # Anything else (5xx, rate limiting, ...) -- record as missing so a
        # single transient failure doesn't sink the whole crawl.
        sentinel = {"_missing": True, "_status": response.status_code}
        cache_path.write_text(json.dumps(sentinel))
        return sentinel

    def fetch_weekly_downloads(self, package: str) -> Optional[int]:
        """Return last-week download count, or None if unavailable."""
        cache_path = (
            self.downloads_cache_dir / f"{_safe_filename(package)}.json"
        )
        if cache_path.exists():
            data = json.loads(cache_path.read_text())
        else:
            try:
                response = requests.get(
                    f"{DOWNLOADS_BASE}/{package}",
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout_s,
                )
                if response.status_code == 200:
                    data = response.json()
                else:
                    data = {"error": f"http {response.status_code}"}
            except requests.RequestException:
                data = {"error": "request_exception"}
            cache_path.write_text(json.dumps(data))

        downloads = data.get("downloads")
        if isinstance(downloads, int):
            return downloads
        return None

    # --- pure helpers --------------------------------------------------------
    def resolve_latest_version(self, manifest: dict) -> Optional[str]:
        """Pick the version this crawl will treat as canonical.

        Preference order:
          1. ``manifest['dist-tags']['latest']``
          2. ``max(versions.keys())`` ordered by ``packaging.version.Version``
          3. Lexicographic fallback when even that fails

        Returns ``None`` when the manifest is the ``{"_missing": True}``
        sentinel from a 404 cache hit, or has no version data at all.
        """
        if not manifest or manifest.get("_missing"):
            return None

        latest = manifest.get("dist-tags", {}).get("latest")
        if isinstance(latest, str) and latest:
            return latest

        versions = manifest.get("versions") or {}
        if not versions:
            return None

        try:
            return max(versions.keys(), key=Version)
        except (InvalidVersion, TypeError, ValueError):
            return max(versions.keys())

    def _direct_deps(
        self, manifest: dict, version: Optional[str]
    ) -> Dict[str, str]:
        """Direct dependencies for ``version``: name -> version range."""
        if not version or not manifest or manifest.get("_missing"):
            return {}
        version_data = manifest.get("versions", {}).get(version, {})
        deps: Dict[str, str] = {}
        runtime = version_data.get("dependencies") or {}
        if isinstance(runtime, dict):
            deps.update(runtime)
        if self.include_dev:
            dev = version_data.get("devDependencies") or {}
            if isinstance(dev, dict):
                deps.update(dev)
        return deps

    def _build_node(
        self, name: str, depth: int, manifest: dict
    ) -> Node:
        """Assemble a fully-populated Node from a manifest payload."""
        version = self.resolve_latest_version(manifest)

        published_at: Optional[str] = None
        maintainers: List[str] = []
        if version and not manifest.get("_missing"):
            time_block = manifest.get("time") or {}
            if isinstance(time_block, dict):
                published_at = time_block.get(version)
            raw_maintainers = manifest.get("maintainers") or []
            if isinstance(raw_maintainers, list):
                maintainers = [
                    n for n in (_coerce_maintainer(m) for m in raw_maintainers)
                    if n
                ]

        weekly = (
            self.fetch_weekly_downloads(name)
            if not manifest.get("_missing")
            else None
        )

        return Node(
            name=name,
            version=version,
            depth=depth,
            published_at=published_at,
            maintainers=maintainers,
            weekly_downloads=weekly,
        )

    # --- the actual crawl ----------------------------------------------------
    def crawl(self, seed: str) -> DiGraph:
        """BFS over the registry from ``seed`` up to ``self.max_depth``.

        At each layer we fetch the package manifest, build a Node with its
        metadata, then enqueue every direct dependency for the next layer.
        Stub Nodes are created for one-hop-too-deep dependencies via
        ``add_edge`` so the graph structure stays complete even when their
        manifests are out of scope.
        """
        graph = DiGraph()
        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        seen: set[str] = {seed}

        while queue:
            name, depth = queue.popleft()
            if depth > self.max_depth:
                continue

            try:
                manifest = self.fetch_manifest(name)
            except Exception:
                manifest = {"_missing": True}

            graph.add_node(self._build_node(name, depth, manifest))

            for child in self._direct_deps(manifest, self.resolve_latest_version(manifest)):
                graph.add_edge(name, child)
                if child not in seen and depth + 1 <= self.max_depth:
                    seen.add(child)
                    queue.append((child, depth + 1))

        return graph
