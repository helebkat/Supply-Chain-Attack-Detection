"""
Unit tests for src/graph.py.

OWNER: Helen Li
"""

from __future__ import annotations

from src.graph import DiGraph, Node


# -----------------------------------------------------------------------------
# fixtures
# -----------------------------------------------------------------------------
def make_diamond() -> DiGraph:
    """Build:
                A
               / \\
              B   C
               \\ /
                D
    """
    g = DiGraph()
    for name in ("A", "B", "C", "D"):
        g.add_node(Node(name=name))
    g.add_edge("A", "B")
    g.add_edge("A", "C")
    g.add_edge("B", "D")
    g.add_edge("C", "D")
    return g


def make_cycle_triangle() -> DiGraph:
    """A -> B -> C -> A."""
    g = DiGraph()
    g.add_edge("A", "B")
    g.add_edge("B", "C")
    g.add_edge("C", "A")
    return g


# -----------------------------------------------------------------------------
# BFS
# -----------------------------------------------------------------------------
def test_bfs_depths_diamond():
    g = make_diamond()
    depths = g.bfs("A")
    assert depths == {"A": 0, "B": 1, "C": 1, "D": 2}


def test_bfs_writes_depth_onto_nodes():
    g = make_diamond()
    g.bfs("A")
    assert g.get_node("A").depth == 0
    assert g.get_node("B").depth == 1
    assert g.get_node("C").depth == 1
    assert g.get_node("D").depth == 2


# -----------------------------------------------------------------------------
# DFS paths
# -----------------------------------------------------------------------------
def test_dfs_paths_two_routes_in_diamond():
    g = make_diamond()
    paths = g.dfs_paths("A", "D")
    assert sorted(paths) == [["A", "B", "D"], ["A", "C", "D"]]


def test_dfs_paths_respects_max_paths():
    g = make_diamond()
    paths = g.dfs_paths("A", "D", max_paths=1)
    assert len(paths) == 1


# -----------------------------------------------------------------------------
# Cycle detection
# -----------------------------------------------------------------------------
def test_cycle_detected_in_triangle():
    cycles = make_cycle_triangle().find_cycles()
    assert len(cycles) == 1
    assert set(cycles[0]) == {"A", "B", "C"}


def test_no_cycle_in_diamond():
    assert make_diamond().find_cycles() == []


# -----------------------------------------------------------------------------
# Topological sort
# -----------------------------------------------------------------------------
def test_topo_sort_order_is_valid_for_diamond():
    order, _ = make_diamond().topological_sort()
    idx = {n: i for i, n in enumerate(order)}
    assert idx["A"] < idx["B"] < idx["D"]
    assert idx["A"] < idx["C"] < idx["D"]


def test_topo_sort_in_degrees_match_diamond():
    _, in_deg = make_diamond().topological_sort()
    assert in_deg == {"A": 0, "B": 1, "C": 1, "D": 2}


def test_topo_sort_partial_when_cyclic():
    g = make_cycle_triangle()
    order, _ = g.topological_sort()
    assert len(order) < len(g)
