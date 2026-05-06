"""
Directed graph data structure and graph algorithms.

This is the algorithmic core of the project. It implements:
  - A simple adjacency-list DiGraph that holds package Nodes
  - BFS for level-order discovery + depth annotation
  - DFS for path enumeration (root -> any node)
  - Cycle detection via DFS coloring (WHITE / GRAY / BLACK)
  - Topological sort via Kahn's algorithm (also gives in-degree ranking)

OWNER: Helen Li

Rules of engagement
-------------------
* Do NOT pull in networkx or any external graph library. Hand-implementing
  the four algorithms below is the whole point of the assignment.
* The Node dataclass below is the shared contract with scoring.py.
  If you change a field name, ping Yaxita first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


# -----------------------------------------------------------------------------
# Shared contract: this is the data shape Yaxita's scorer will read.
# Keep field names stable.
# -----------------------------------------------------------------------------
@dataclass
class Node:
    """One package in the dependency graph."""

    name: str
    version: Optional[str] = None
    depth: Optional[int] = None              # set by DiGraph.bfs
    published_at: Optional[str] = None       # ISO-8601 from manifest['time'][version]
    maintainers: List[str] = field(default_factory=list)
    weekly_downloads: Optional[int] = None
    osv_ids: List[str] = field(default_factory=list)   # filled by OsvClient


# -----------------------------------------------------------------------------
# DiGraph
# -----------------------------------------------------------------------------
class DiGraph:
    """Adjacency-list directed graph keyed by package name."""

    def __init__(self) -> None:
        # TODO (Helen): pick storage. Suggested:
        #   self._nodes: Dict[str, Node]      = {}
        #   self._out:   Dict[str, Set[str]]  = {}   # name -> children
        #   self._in:    Dict[str, Set[str]]  = {}   # name -> parents
        # The reverse adjacency (_in) makes Kahn's algorithm O(V+E) without
        # an extra pass and gives Yaxita's scorer cheap in-degree lookups.
        raise NotImplementedError

    # --- mutation ------------------------------------------------------------
    def add_node(self, node: Node) -> None:
        """Insert a node, or merge metadata if the name is already present.

        TODO (Helen): if `node.name` already exists, copy over any non-None
        fields from `node` so a richer second crawl pass can enrich an
        existing entry without erasing what was already there.
        """
        raise NotImplementedError

    def add_edge(self, parent: str, child: str) -> None:
        """Add a directed edge parent -> child.

        TODO (Helen): create stub Nodes for either endpoint if missing
        (so an edge can be added before its endpoints have manifests),
        then update both _out[parent] and _in[child].
        """
        raise NotImplementedError

    # --- read-only views -----------------------------------------------------
    def nodes(self) -> Iterable[Node]:
        raise NotImplementedError

    def has_node(self, name: str) -> bool:
        raise NotImplementedError

    def get_node(self, name: str) -> Node:
        raise NotImplementedError

    def children(self, name: str) -> Set[str]:
        raise NotImplementedError

    def parents(self, name: str) -> Set[str]:
        raise NotImplementedError

    def edge_count(self) -> int:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError

    # --- algorithms (the graded part) ---------------------------------------
    def bfs(self, source: str) -> Dict[str, int]:
        """Breadth-first search from `source`.

        Returns a dict mapping every reachable node name to its depth from
        `source` (`source` itself maps to 0).

        TODO (Helen):
          1. collections.deque + a visited set.
          2. As you dequeue each (name, depth), also write the depth back onto
             the corresponding Node:  self._nodes[name].depth = depth
             (this is what the proposal calls "how many layers deep is this
             suspicious package hiding?").
          3. Return the depth map.
        """
        raise NotImplementedError

    def dfs_paths(
        self,
        source: str,
        target: str,
        max_paths: int = 50,
    ) -> List[List[str]]:
        """Enumerate up to `max_paths` simple paths from source -> target.

        TODO (Helen):
          - Recursive or stack-based DFS, your choice.
          - Maintain a `visited_in_path` set to avoid cycles WITHIN one path
            (we still want to find all alternative routes).
          - Stop collecting once `max_paths` paths have been recorded; the
            suspicion report only needs one or two routes per flagged node.
          - Each path is returned as a list of names, including endpoints.
        """
        raise NotImplementedError

    def find_cycles(self) -> List[List[str]]:
        """Return one representative cycle per back-edge found.

        TODO (Helen):
          - DFS with three colors:
              WHITE = unseen, GRAY = on current recursion stack, BLACK = done.
          - When you traverse to a GRAY neighbor you've found a back-edge,
            i.e. a cycle. Reconstruct it by walking the recursion stack from
            the re-entry point down to the current node.
          - npm forbids publish-time cycles, so any cycle found here will be
            reported as anomalous by analyzer.py.
        """
        raise NotImplementedError

    def topological_sort(self) -> Tuple[List[str], Dict[str, int]]:
        """Kahn's algorithm.

        Returns
        -------
        order : list[str]
            A topological ordering. If the graph contains cycles, only the
            acyclic prefix is returned; the caller should compare
            `len(order)` to `len(self)` to detect leftover cyclic nodes.
        in_degrees : dict[str, int]
            The ORIGINAL (pre-peel) in-degree of every node. Yaxita's scorer
            uses this directly as the "blast radius" signal.

        TODO (Helen):
          1. Compute initial in-degrees from self._in.
          2. Push every zero-in-degree node onto a queue.
          3. Pop, append to `order`, decrement in-degree of each child;
             when a child hits zero, enqueue it.
          4. Return (order, original_in_degrees_snapshot).
        """
        raise NotImplementedError
