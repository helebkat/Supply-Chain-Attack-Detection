"""
Unit tests for src/graph.py.

OWNER: Helen Li -- you only need to fill in the bodies. Each test docstring
already states the property the underlying algorithm must satisfy.
"""

from __future__ import annotations

import pytest

from src.graph import DiGraph, Node


# -----------------------------------------------------------------------------
# fixtures
# -----------------------------------------------------------------------------
def make_diamond() -> DiGraph:
    """Construct:
                A
               / \\
              B   C
               \\ /
                D
    TODO (Helen): use add_node + add_edge and return.
    """
    raise NotImplementedError


def make_cycle_triangle() -> DiGraph:
    """A -> B -> C -> A.
    TODO (Helen): build and return.
    """
    raise NotImplementedError


# -----------------------------------------------------------------------------
# BFS
# -----------------------------------------------------------------------------
def test_bfs_depths_diamond():
    """Depth map must be {A:0, B:1, C:1, D:2}.
    TODO (Helen):
        g = make_diamond()
        depths = g.bfs("A")
        assert depths == {"A": 0, "B": 1, "C": 1, "D": 2}
    """
    raise NotImplementedError


def test_bfs_writes_depth_onto_nodes():
    """After bfs, each Node.depth must equal its BFS layer.
    TODO (Helen): assert g.get_node("D").depth == 2.
    """
    raise NotImplementedError


# -----------------------------------------------------------------------------
# DFS paths
# -----------------------------------------------------------------------------
def test_dfs_paths_two_routes_in_diamond():
    """Diamond has exactly 2 simple A->D paths.
    TODO (Helen):
        paths = g.dfs_paths("A", "D")
        assert sorted(paths) == [["A","B","D"], ["A","C","D"]]
    """
    raise NotImplementedError


def test_dfs_paths_respects_max_paths():
    """`max_paths=1` returns at most one path.
    TODO (Helen): assert len(g.dfs_paths("A","D", max_paths=1)) == 1.
    """
    raise NotImplementedError


# -----------------------------------------------------------------------------
# Cycle detection
# -----------------------------------------------------------------------------
def test_cycle_detected_in_triangle():
    """find_cycles must return a length-3 cycle on A->B->C->A.
    TODO (Helen):
        cycles = make_cycle_triangle().find_cycles()
        assert len(cycles) == 1
        assert set(cycles[0]) == {"A", "B", "C"}
    """
    raise NotImplementedError


def test_no_cycle_in_diamond():
    """Diamond is acyclic.
    TODO (Helen): assert make_diamond().find_cycles() == [].
    """
    raise NotImplementedError


# -----------------------------------------------------------------------------
# Topological sort
# -----------------------------------------------------------------------------
def test_topo_sort_order_is_valid_for_diamond():
    """A must come before B, C; B and C must come before D.
    TODO (Helen):
        order, in_deg = make_diamond().topological_sort()
        idx = {n: i for i, n in enumerate(order)}
        assert idx["A"] < idx["B"] < idx["D"]
        assert idx["A"] < idx["C"] < idx["D"]
    """
    raise NotImplementedError


def test_topo_sort_in_degrees_match_diamond():
    """In-degree map: A=0, B=1, C=1, D=2.
    TODO (Helen): assert in_deg == {"A":0,"B":1,"C":1,"D":2}.
    """
    raise NotImplementedError


def test_topo_sort_partial_when_cyclic():
    """If a graph has a cycle, len(order) < len(graph).
    TODO (Helen):
        g = make_cycle_triangle()
        order, _ = g.topological_sort()
        assert len(order) < len(g)
    """
    raise NotImplementedError
