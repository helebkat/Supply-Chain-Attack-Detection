"""
Tests for the OSV client.

OWNER: Yaxita Amin

The pure helper `version_in_range` is the easiest place to start; it has no
network dependency and is the most error-prone part of the module.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.osv_client import OsvClient


# -----------------------------------------------------------------------------
# version_in_range -- pure unit tests
# -----------------------------------------------------------------------------
def test_version_in_range_introduced_fixed():
    """{introduced: 3.3.6, fixed: 4.0.0} should match 3.3.6 but NOT 4.0.0.
    TODO (Yaxita):
        ranges = [{"type":"SEMVER",
                   "events":[{"introduced":"3.3.6"},{"fixed":"4.0.0"}]}]
        assert OsvClient.version_in_range("3.3.6", ranges) is True
        assert OsvClient.version_in_range("3.99.0", ranges) is True
        assert OsvClient.version_in_range("4.0.0", ranges) is False
        assert OsvClient.version_in_range("3.3.5", ranges) is False
    """
    raise NotImplementedError


def test_version_in_range_open_introduced():
    """{introduced: 0} = "all versions affected". Matches 1.0.0.
    TODO (Yaxita):
        ranges = [{"type":"SEMVER", "events":[{"introduced":"0"}]}]
        assert OsvClient.version_in_range("1.0.0", ranges) is True
    """
    raise NotImplementedError


def test_version_in_range_falls_back_to_versions_list():
    """No usable ranges, but a versions[] list -> exact membership check.
    TODO (Yaxita):
        assert OsvClient.version_in_range("3.3.6", ranges=[],
                                          versions=["3.3.6"]) is True
        assert OsvClient.version_in_range("3.3.5", ranges=[],
                                          versions=["3.3.6"]) is False
    """
    raise NotImplementedError


def test_version_in_range_missing_version_returns_false():
    """If the resolved version is None (e.g. yanked package), never match.
    TODO (Yaxita): assert OsvClient.version_in_range(None, [...]) is False
    """
    raise NotImplementedError


# -----------------------------------------------------------------------------
# query() -- cached, no network
# -----------------------------------------------------------------------------
def test_query_uses_cache_when_present(tmp_path):
    """A pre-existing cache file must be returned without hitting the net.
    TODO (Yaxita):
        - write a fixture json into tmp_path:
            {"vulns":[{"id":"GHSA-mh6f-8j2x-4483",
                       "summary":"...",
                       "database_specific":{"severity":"CRITICAL"},
                       "affected":[{"package":{"name":"event-stream",
                                               "ecosystem":"npm"},
                                    "ranges":[{"type":"SEMVER",
                                               "events":[{"introduced":"3.3.6"},
                                                         {"fixed":"4.0.0"}]}],
                                    "versions":["3.3.6"]}]}]}
        - client = OsvClient(cache_dir=tmp_path)
        - vulns = client.query("event-stream")
        - assert len(vulns) == 1
        - assert vulns[0].osv_id == "GHSA-mh6f-8j2x-4483"
        - assert vulns[0].severity == "CRITICAL"
    """
    raise NotImplementedError
