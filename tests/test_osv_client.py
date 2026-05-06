"""
Tests for the OSV client.

The pure helper ``version_in_range`` is the easiest place to start; it has
no network dependency and is the most error-prone part of the module.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from src.osv_client import OsvClient, Vulnerability


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "osv"


# -----------------------------------------------------------------------------
# version_in_range -- pure unit tests
# -----------------------------------------------------------------------------
def test_version_in_range_introduced_fixed():
    """{introduced: 3.3.6, fixed: 4.0.0} matches 3.3.6 but not 4.0.0."""
    ranges = [
        {"type": "SEMVER",
         "events": [{"introduced": "3.3.6"}, {"fixed": "4.0.0"}]}
    ]
    assert OsvClient.version_in_range("3.3.6", ranges) is True
    assert OsvClient.version_in_range("3.99.0", ranges) is True
    assert OsvClient.version_in_range("4.0.0", ranges) is False
    assert OsvClient.version_in_range("3.3.5", ranges) is False


def test_version_in_range_open_introduced():
    """{introduced: 0} = 'all versions affected'."""
    ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    assert OsvClient.version_in_range("1.0.0", ranges) is True
    assert OsvClient.version_in_range("99.99.99", ranges) is True


def test_version_in_range_multiple_intervals():
    """Two introduced/fixed pairs in one events list -> union of intervals."""
    ranges = [{
        "type": "SEMVER",
        "events": [
            {"introduced": "1.0.0"}, {"fixed": "2.0.0"},
            {"introduced": "3.0.0"}, {"fixed": "4.0.0"},
        ],
    }]
    assert OsvClient.version_in_range("1.5.0", ranges) is True
    assert OsvClient.version_in_range("2.5.0", ranges) is False
    assert OsvClient.version_in_range("3.5.0", ranges) is True
    assert OsvClient.version_in_range("4.5.0", ranges) is False


def test_version_in_range_falls_back_to_versions_list():
    """No usable ranges, but a versions[] list -> exact membership check."""
    assert OsvClient.version_in_range(
        "3.3.6", ranges=[], versions=["3.3.6"]
    ) is True
    assert OsvClient.version_in_range(
        "3.3.5", ranges=[], versions=["3.3.6"]
    ) is False


def test_version_in_range_missing_version_returns_false():
    """If the resolved version is None (e.g. yanked package), never match."""
    ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    assert OsvClient.version_in_range(None, ranges) is False


# -----------------------------------------------------------------------------
# query() -- cached, no network
# -----------------------------------------------------------------------------
def test_query_uses_cache_when_present(tmp_path):
    """A pre-existing cache file is returned without hitting the network."""
    shutil.copy(FIXTURE_DIR / "event-stream.json", tmp_path / "event-stream.json")

    client = OsvClient(cache_dir=tmp_path)
    vulns = client.query("event-stream")

    assert len(vulns) == 1
    assert vulns[0].osv_id == "GHSA-mh6f-8j2x-4483"
    assert vulns[0].severity == "CRITICAL"
    assert vulns[0].affected_versions == ["3.3.6"]
    assert vulns[0].affected_ranges[0]["events"] == [
        {"introduced": "3.3.6"}, {"fixed": "4.0.0"}
    ]


def test_query_filters_to_correct_package(tmp_path):
    """The fixture covers both event-stream and flatmap-stream; queries for
    one must not return the affected[] entry for the other."""
    shutil.copy(
        FIXTURE_DIR / "event-stream.json", tmp_path / "event-stream.json"
    )
    shutil.copy(
        FIXTURE_DIR / "event-stream.json", tmp_path / "flatmap-stream.json"
    )

    client = OsvClient(cache_dir=tmp_path)

    es = client.query("event-stream")
    fm = client.query("flatmap-stream")

    assert es[0].affected_versions == ["3.3.6"]
    assert es[0].affected_ranges[0]["events"][0] == {"introduced": "3.3.6"}

    # flatmap-stream's affected entry has events=[{"introduced":"0"}] only
    assert fm[0].affected_versions == []
    assert fm[0].affected_ranges[0]["events"] == [{"introduced": "0"}]


def test_query_handles_no_vulns(tmp_path):
    """A package with no known vulns must produce an empty list."""
    (tmp_path / "clean-pkg.json").write_text(json.dumps({"vulns": []}))

    client = OsvClient(cache_dir=tmp_path)
    assert client.query("clean-pkg") == []


def test_event_stream_actual_match(tmp_path):
    """End-to-end: query + version_in_range together correctly identify
    event-stream@3.3.6 as compromised, exactly as the proposal predicts."""
    shutil.copy(FIXTURE_DIR / "event-stream.json", tmp_path / "event-stream.json")

    client = OsvClient(cache_dir=tmp_path)
    vulns = client.query("event-stream")

    assert OsvClient.version_in_range(
        "3.3.6", vulns[0].affected_ranges, vulns[0].affected_versions
    ) is True
    assert OsvClient.version_in_range(
        "3.3.4", vulns[0].affected_ranges, vulns[0].affected_versions
    ) is False
    assert OsvClient.version_in_range(
        "4.0.0", vulns[0].affected_ranges, vulns[0].affected_versions
    ) is False
