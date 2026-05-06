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
from typing import Optional

from .graph import DiGraph, Node


REGISTRY_BASE = "https://registry.npmjs.org"
DOWNLOADS_BASE = "https://api.npmjs.org/downloads/point/last-week"

# Polite header so npm's ops team can identify us if we mis-behave.
USER_AGENT = "MSML606-SupplyChainProject/0.1 (+student-research)"


def _safe_filename(package: str) -> str:
    """`@scope/name` -> `@scope__name` so it's safe as a filename.
    TODO (Helen): trivial; just replace '/' with '__'.
    """
    raise NotImplementedError


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
        # TODO (Helen):
        #   - Path.mkdir(parents=True, exist_ok=True) on both cache dirs
        #   - stash all the kwargs on self
        raise NotImplementedError

    # --- HTTP-with-cache primitives -----------------------------------------
    def fetch_manifest(self, package: str) -> dict:
        """GET https://registry.npmjs.org/<package>, with on-disk caching.

        TODO (Helen):
          1. cache_path = self.cache_dir / f"{_safe_filename(package)}.json"
          2. If cache_path.exists(): return json.loads(cache_path.read_text())
          3. Else requests.get(f"{REGISTRY_BASE}/{package}",
                                headers={"User-Agent": USER_AGENT},
                                timeout=self.timeout_s)
          4. On 200 -> write body to cache_path, return parsed json.
          5. On 404 -> cache {"_missing": True} so we don't re-hit the registry
             on every run for unpublished/yanked names; return that dict.
          6. On any other error -> raise (the BFS loop will catch and skip).
        """
        raise NotImplementedError

    def fetch_weekly_downloads(self, package: str) -> Optional[int]:
        """GET .../downloads/point/last-week/<package> -> int or None.

        TODO (Helen):
          - Cache under self.downloads_cache_dir/<safe_name>.json.
          - On success the body is {"downloads": int, ...} -> return the int.
          - Many obscure packages return {"error": "..."} -> return None.
        """
        raise NotImplementedError

    # --- pure helpers --------------------------------------------------------
    def resolve_latest_version(self, manifest: dict) -> Optional[str]:
        """Pick the version string this crawl will treat as canonical.

        TODO (Helen):
          - Prefer manifest['dist-tags']['latest'] when present.
          - Fall back to max(manifest['versions'].keys()) ordered by
            packaging.version.Version (npm semver isn't 100% PEP440 but
            for ordering it works on >99% of real packages).
          - Return None if `manifest` is the {"_missing": True} sentinel
            from a 404 cache hit.
        """
        raise NotImplementedError

    def _direct_deps(self, manifest: dict, version: str) -> dict:
        """Return the dependency map (name -> version range) for `version`.

        TODO (Helen):
          - Look up manifest['versions'][version].
          - Always read 'dependencies' (default to {}).
          - Also merge 'devDependencies' iff self.include_dev.
        """
        raise NotImplementedError

    # --- the actual crawl ----------------------------------------------------
    def crawl(self, seed: str) -> DiGraph:
        """BFS over the registry from `seed` up to self.max_depth.

        TODO (Helen):
          1. graph = DiGraph(); queue = deque([(seed, 0)]); seen = {seed}
          2. While queue:
                 name, depth = queue.popleft()
                 if depth > self.max_depth: continue
                 manifest = self.fetch_manifest(name)
                 version  = self.resolve_latest_version(manifest)
                 # populate Node:
                 #   published_at = manifest.get('time', {}).get(version)
                 #   maintainers  = [m['name'] for m in manifest.get('maintainers', [])]
                 #   weekly_downloads = self.fetch_weekly_downloads(name)
                 graph.add_node(Node(name=name, version=version, depth=depth,
                                     published_at=..., maintainers=...,
                                     weekly_downloads=...))
                 for child in self._direct_deps(manifest, version):
                     graph.add_edge(name, child)
                     if child not in seen and depth + 1 <= self.max_depth:
                         seen.add(child)
                         queue.append((child, depth + 1))
          3. Return graph.

        OPTIONAL once the sequential version is green:
          Wrap fetch_manifest in a concurrent.futures.ThreadPoolExecutor with
          self.max_workers, parallelizing the sibling fetches inside one BFS
          layer. Keep the outer BFS loop sequential so depth ordering and
          `seen`-set semantics stay correct.
        """
        raise NotImplementedError
