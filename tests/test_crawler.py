"""
Tests for the npm registry crawler using cached fixtures (no live network).

OWNER: Helen Li

Each test copies tests/fixtures/{registry,downloads}/ into a tmp_path so
the crawler's own writes don't pollute the committed fixture set, and so
every fetch hits the cache instead of the live network.

Fixture graph:

        pkg-a
       /     \\
    pkg-b   pkg-c
       \\     /
        pkg-d
          |
        pkg-e
"""

from __future__ import annotations

import shutil
from pathlib import Path

from src.crawler import NpmCrawler


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _setup_caches(tmp_path: Path) -> tuple[Path, Path]:
    """Copy fixture caches into tmp_path/<registry,downloads>/."""
    registry_dst = tmp_path / "registry"
    downloads_dst = tmp_path / "downloads"
    shutil.copytree(FIXTURE_DIR / "registry", registry_dst)
    shutil.copytree(FIXTURE_DIR / "downloads", downloads_dst)
    return registry_dst, downloads_dst


# -----------------------------------------------------------------------------
# resolve_latest_version -- pure unit tests
# -----------------------------------------------------------------------------
def test_resolve_latest_version_prefers_dist_tag(tmp_path):
    registry_dst, downloads_dst = _setup_caches(tmp_path)
    c = NpmCrawler(cache_dir=registry_dst, downloads_cache_dir=downloads_dst)
    manifest = {
        "dist-tags": {"latest": "1.2.3"},
        "versions": {"1.2.3": {}, "1.5.0-rc.1": {}},
    }
    assert c.resolve_latest_version(manifest) == "1.2.3"


def test_resolve_latest_version_falls_back_to_numeric_max(tmp_path):
    registry_dst, downloads_dst = _setup_caches(tmp_path)
    c = NpmCrawler(cache_dir=registry_dst, downloads_cache_dir=downloads_dst)
    manifest = {"versions": {"1.9.9": {}, "2.0.0": {}}}
    assert c.resolve_latest_version(manifest) == "2.0.0"


def test_resolve_latest_version_returns_none_for_missing(tmp_path):
    registry_dst, downloads_dst = _setup_caches(tmp_path)
    c = NpmCrawler(cache_dir=registry_dst, downloads_cache_dir=downloads_dst)
    assert c.resolve_latest_version({"_missing": True}) is None
    assert c.resolve_latest_version({}) is None


# -----------------------------------------------------------------------------
# crawl -- integration tests against cached fixtures
# -----------------------------------------------------------------------------
def test_crawl_respects_max_depth(tmp_path):
    """At max_depth=2 the BFS stops at pkg-d (depth 2). pkg-e is recorded
    as a stub (via add_edge from pkg-d) but is never assigned a depth."""
    registry_dst, downloads_dst = _setup_caches(tmp_path)
    c = NpmCrawler(
        cache_dir=registry_dst,
        downloads_cache_dir=downloads_dst,
        max_depth=2,
    )
    g = c.crawl("pkg-a")
    assert max((n.depth or 0) for n in g.nodes()) == 2


def test_crawl_does_not_revisit(tmp_path):
    """Diamond + chain via cached fixtures: every package appears exactly once
    even though pkg-d has two parents."""
    registry_dst, downloads_dst = _setup_caches(tmp_path)
    c = NpmCrawler(
        cache_dir=registry_dst,
        downloads_cache_dir=downloads_dst,
        max_depth=5,
    )
    g = c.crawl("pkg-a")

    names = sorted(n.name for n in g.nodes())
    assert names == ["pkg-a", "pkg-b", "pkg-c", "pkg-d", "pkg-e"]
    assert len(g) == 5
    # 5 directed edges: a->b, a->c, b->d, c->d, d->e
    assert g.edge_count() == 5


def test_crawl_populates_node_metadata(tmp_path):
    """After a full crawl, Nodes carry version, published_at, maintainers,
    weekly downloads -- the fields scoring.py reads."""
    registry_dst, downloads_dst = _setup_caches(tmp_path)
    c = NpmCrawler(
        cache_dir=registry_dst,
        downloads_cache_dir=downloads_dst,
        max_depth=5,
    )
    g = c.crawl("pkg-a")

    a = g.get_node("pkg-a")
    assert a.version == "1.0.0"
    assert a.published_at == "2024-01-01T00:00:00.000Z"
    assert a.maintainers == ["alice"]
    assert a.weekly_downloads == 100000
    assert a.depth == 0

    e = g.get_node("pkg-e")
    assert e.weekly_downloads == 3
    assert e.depth == 3
