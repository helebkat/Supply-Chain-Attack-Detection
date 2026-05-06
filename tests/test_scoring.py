"""Tests for the suspicion scorer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.graph import DiGraph, Node
from src.osv_client import Vulnerability
from src.scoring import Scorer, _levenshtein


# -----------------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------------
def _vuln(severity: str = "CRITICAL") -> Vulnerability:
    return Vulnerability(
        osv_id="GHSA-test-0001",
        summary="test",
        severity=severity,
        affected_ranges=[],
        affected_versions=[],
    )


def _tiny_graph() -> DiGraph:
    """parent (popular, 10M dl/wk) -> child (suspicious, 3 dl/wk)."""
    g = DiGraph()
    g.add_node(Node(name="parent", version="1.0.0",
                    weekly_downloads=10_000_000))
    g.add_node(Node(name="child", version="0.1.0",
                    weekly_downloads=3))
    g.add_edge("parent", "child")
    return g


# -----------------------------------------------------------------------------
# Levenshtein helper
# -----------------------------------------------------------------------------
def test_levenshtein_basics():
    assert _levenshtein("express", "express") == 0
    assert _levenshtein("expres", "express") == 1
    assert _levenshtein("exprss", "express") == 1
    assert _levenshtein("xpress", "express") == 1
    assert _levenshtein("expr3ss", "express") == 1
    assert _levenshtein("xprss", "express") == 2
    assert _levenshtein("totally-different", "express") >= 5


# -----------------------------------------------------------------------------
# individual signals
# -----------------------------------------------------------------------------
def test_osv_signal_severity_mapping():
    s = Scorer()
    assert s._osv_signal([]) == 0.0
    assert s._osv_signal([_vuln("CRITICAL")]) == 1.0
    assert s._osv_signal([_vuln("HIGH")]) == 1.0
    assert s._osv_signal([_vuln("MODERATE")]) == 0.6
    assert s._osv_signal([_vuln("LOW")]) == 0.3
    # Worst-case wins when multiple severities present
    assert s._osv_signal([_vuln("LOW"), _vuln("CRITICAL")]) == 1.0


def test_typosquat_signal_distance_one():
    scorer = Scorer(popular_names=["express"])
    assert scorer._typosquat_signal("expres") == 1.0
    assert scorer._typosquat_signal("xpress") == 1.0
    # exact match must NOT be flagged as typosquat
    assert scorer._typosquat_signal("express") == 0.0


def test_typosquat_signal_distance_two():
    scorer = Scorer(popular_names=["express"])
    assert scorer._typosquat_signal("xprss") == 0.5
    assert scorer._typosquat_signal("totally-different") == 0.0


def test_typosquat_no_popular_list():
    """No popular names configured -> no typosquat signal possible."""
    assert Scorer()._typosquat_signal("expres") == 0.0


def test_ownership_signal_recent_publish():
    """A version published 5 days ago triggers the strongest ownership signal."""
    recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    node = Node(name="x", published_at=recent)
    assert Scorer()._ownership_signal(node) == 1.0


def test_ownership_signal_old_publish():
    """A version published 5 years ago is not suspicious by ownership alone."""
    old = (datetime.now(timezone.utc) - timedelta(days=5 * 365)).isoformat()
    node = Node(name="x", published_at=old)
    assert Scorer()._ownership_signal(node) == 0.0


def test_in_degree_signal():
    s = Scorer()
    assert s._in_degree_signal(0, 10) == 0.0
    assert s._in_degree_signal(5, 10) == 0.5
    assert s._in_degree_signal(10, 10) == 1.0
    # Defensive: avoid divide-by-zero when graph has no edges at all
    assert s._in_degree_signal(0, 0) == 0.0


# -----------------------------------------------------------------------------
# score_graph -- end-to-end
# -----------------------------------------------------------------------------
def test_critical_osv_dominates_total_score():
    """A node with a CRITICAL OSV hit must clear the threshold by itself."""
    g = _tiny_graph()
    scores = Scorer().score_graph(
        g,
        osv_hits={"child": [_vuln("CRITICAL")]},
        in_degrees={"parent": 0, "child": 1},
    )
    child = next(s for s in scores if s.name == "child")
    assert child.flagged is True
    assert child.osv == 1.0
    # OSV alone (0.50) already crosses the default 0.30 threshold
    assert child.total >= 0.5


def test_low_download_under_popular_parent():
    """3 dl/wk child under a 10M dl/wk parent produces a strong dl signal."""
    scores = Scorer().score_graph(
        _tiny_graph(),
        osv_hits={},
        in_degrees={"parent": 0, "child": 1},
    )
    child = next(s for s in scores if s.name == "child")
    assert child.downloads >= 0.7


def test_threshold_is_respected():
    """Below-threshold totals must produce flagged=False."""
    scorer = Scorer(threshold=0.95)
    scores = scorer.score_graph(
        _tiny_graph(),
        osv_hits={},
        in_degrees={"parent": 0, "child": 1},
    )
    assert all(not s.flagged for s in scores)


def test_scores_sorted_descending():
    """score_graph returns nodes sorted by total descending."""
    scores = Scorer().score_graph(
        _tiny_graph(),
        osv_hits={"child": [_vuln("CRITICAL")]},
        in_degrees={"parent": 0, "child": 1},
    )
    totals = [s.total for s in scores]
    assert totals == sorted(totals, reverse=True)


def test_reasons_explain_flagged_signals():
    """The Score.reasons list mentions each signal that fired."""
    g = _tiny_graph()
    scores = Scorer().score_graph(
        g,
        osv_hits={"child": [_vuln("CRITICAL")]},
        in_degrees={"parent": 0, "child": 1},
    )
    child = next(s for s in scores if s.name == "child")
    joined = " | ".join(child.reasons).lower()
    assert "osv" in joined
    assert "low downloads" in joined or "downloads" in joined
