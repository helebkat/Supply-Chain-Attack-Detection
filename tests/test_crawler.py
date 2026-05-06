"""
Tests for the npm registry crawler using cached fixtures (no live network).

OWNER: Helen Li

Setup
-----
Drop a few hand-trimmed manifest JSONs under tests/fixtures/registry/
(e.g. `pkg-a.json`, `pkg-b.json`, ...) and point NpmCrawler.cache_dir at
that directory. Because every fetch_manifest call hits the cache first,
no live HTTP call is ever made by these tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.crawler import NpmCrawler


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "registry"


def test_resolve_latest_version_prefers_dist_tag():
    """If manifest['dist-tags']['latest'] is set, that wins over numeric max.
    TODO (Helen): build a fake manifest dict in-memory:
        m = {"dist-tags": {"latest": "1.2.3"},
             "versions": {"1.2.3": {}, "1.5.0-rc.1": {}}}
        assert NpmCrawler().resolve_latest_version(m) == "1.2.3"
    """
    raise NotImplementedError


def test_resolve_latest_version_falls_back_to_numeric_max():
    """No dist-tag -> highest semver in `versions`.
    TODO (Helen): assert "2.0.0" beats "1.9.9" with no dist-tag.
    """
    raise NotImplementedError


def test_crawl_respects_max_depth(tmp_path):
    """A 4-level fixture chain crawled at max_depth=2 stops at layer 2.
    TODO (Helen):
        - shutil.copytree(FIXTURE_DIR, tmp_path/"registry")
        - c = NpmCrawler(cache_dir=tmp_path/"registry", max_depth=2)
        - g = c.crawl("pkg-a")
        - assert max((n.depth or 0) for n in g.nodes()) == 2
    """
    raise NotImplementedError


def test_crawl_does_not_revisit(tmp_path):
    """Diamond chain via cached fixtures: each package appears exactly once.
    TODO (Helen): assert len(g) equals the number of distinct package
    fixtures, even if multiple parents point to the same child.
    """
    raise NotImplementedError
