"""
Tests for the suspicion scorer.

OWNER: Yaxita Amin

These are deterministic fixed-input -> fixed-output tests; build a tiny
3-node DiGraph in-memory, mock OSV hits, call score_graph.
"""

from __future__ import annotations

import pytest

from src.graph import DiGraph, Node
from src.osv_client import Vulnerability
from src.scoring import Scorer


# -----------------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------------
def _vuln(severity: str = "CRITICAL") -> Vulnerability:
    """TODO (Yaxita): return a Vulnerability with id='X', severity=severity."""
    raise NotImplementedError


def _tiny_graph() -> DiGraph:
    """parent (popular) -> child (suspicious).
    TODO (Yaxita):
        g = DiGraph()
        g.add_node(Node(name="parent", version="1.0.0",
                        weekly_downloads=10_000_000))
        g.add_node(Node(name="child",  version="0.1.0",
                        weekly_downloads=3))
        g.add_edge("parent", "child")
        return g
    """
    raise NotImplementedError


# -----------------------------------------------------------------------------
# tests
# -----------------------------------------------------------------------------
def test_critical_osv_dominates_total_score():
    """A node with a CRITICAL OSV hit must clear the threshold by itself.
    TODO (Yaxita):
        g = _tiny_graph()
        scorer = Scorer()
        scores = scorer.score_graph(
            g,
            osv_hits={"child": [_vuln("CRITICAL")]},
            in_degrees={"parent": 0, "child": 1},
        )
        child = next(s for s in scores if s.name == "child")
        assert child.flagged is True
        assert child.osv == 1.0
    """
    raise NotImplementedError


def test_low_download_under_popular_parent():
    """Even with no OSV, a 3-downloads child under a 10M-downloads parent
    should produce a noticeable downloads signal.
    TODO (Yaxita):
        scores = Scorer().score_graph(_tiny_graph(), osv_hits={},
                                      in_degrees={"parent":0,"child":1})
        child = next(s for s in scores if s.name == "child")
        assert child.downloads >= 0.7
    """
    raise NotImplementedError


def test_typosquat_signal_distance_one():
    """'expres' is Levenshtein distance 1 from 'express'.
    TODO (Yaxita):
        scorer = Scorer(popular_names=["express"])
        sig = scorer._typosquat_signal("expres")
        assert sig == 1.0
        # exact match must NOT be flagged as typosquat
        assert scorer._typosquat_signal("express") == 0.0
    """
    raise NotImplementedError


def test_threshold_is_respected():
    """Below-threshold totals must produce flagged=False.
    TODO (Yaxita):
        scorer = Scorer(threshold=0.95)  # absurdly high
        scores = scorer.score_graph(_tiny_graph(), osv_hits={},
                                    in_degrees={"parent":0,"child":1})
        assert all(not s.flagged for s in scores)
    """
    raise NotImplementedError
