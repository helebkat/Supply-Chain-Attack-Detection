"""
Directed graph data structure and graph algorithms.

Algorithmic core of the project:
  - Adjacency-list DiGraph keyed by package name
  - BFS for level-order discovery + depth annotation
  - DFS for path enumeration (root -> any node)
  - Cycle detection via iterative DFS coloring (WHITE / GRAY / BLACK)
  - Topological sort via Kahn's algorithm

OWNER: Helen Li

The Node dataclass is the shared contract with scoring.py; field names
must stay stable across modules.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple


@dataclass
class Node:
    """One package in the dependency graph."""

    name: str
    version: Optional[str] = None
    depth: Optional[int] = None
    published_at: Optional[str] = None
    maintainers: List[str] = field(default_factory=list)
    weekly_downloads: Optional[int] = None
    osv_ids: List[str] = field(default_factory=list)


class DiGraph:
    """Adjacency-list directed graph keyed by package name."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._out: Dict[str, Set[str]] = {}
        self._in: Dict[str, Set[str]] = {}

    # --- mutation ------------------------------------------------------------
    def add_node(self, node: Node) -> None:
        existing = self._nodes.get(node.name)
        if existing is None:
            self._nodes[node.name] = node
            self._out.setdefault(node.name, set())
            self._in.setdefault(node.name, set())
            return

        # Merge: copy any populated fields from the new node onto the existing
        # entry so a richer second crawl pass enriches without overwriting.
        if node.version is not None:
            existing.version = node.version
        if node.depth is not None:
            existing.depth = node.depth
        if node.published_at is not None:
            existing.published_at = node.published_at
        if node.maintainers:
            existing.maintainers = node.maintainers
        if node.weekly_downloads is not None:
            existing.weekly_downloads = node.weekly_downloads
        if node.osv_ids:
            existing.osv_ids = node.osv_ids

    def add_edge(self, parent: str, child: str) -> None:
        if parent not in self._nodes:
            self.add_node(Node(name=parent))
        if child not in self._nodes:
            self.add_node(Node(name=child))
        self._out[parent].add(child)
        self._in[child].add(parent)

    # --- read-only views -----------------------------------------------------
    def nodes(self) -> Iterable[Node]:
        return self._nodes.values()

    def has_node(self, name: str) -> bool:
        return name in self._nodes

    def get_node(self, name: str) -> Node:
        return self._nodes[name]

    def children(self, name: str) -> Set[str]:
        return self._out.get(name, set())

    def parents(self, name: str) -> Set[str]:
        return self._in.get(name, set())

    def edge_count(self) -> int:
        return sum(len(c) for c in self._out.values())

    def __len__(self) -> int:
        return len(self._nodes)

    # --- algorithms ----------------------------------------------------------
    def bfs(self, source: str) -> Dict[str, int]:
        """Breadth-first search from `source`.

        Returns a depth map; also writes the depth onto each Node so callers
        (the scorer, the report formatter) can read it directly.
        """
        if source not in self._nodes:
            return {}

        depths: Dict[str, int] = {source: 0}
        self._nodes[source].depth = 0
        queue: deque[str] = deque([source])

        while queue:
            current = queue.popleft()
            d = depths[current]
            for child in self._out.get(current, set()):
                if child in depths:
                    continue
                depths[child] = d + 1
                if child in self._nodes:
                    self._nodes[child].depth = d + 1
                queue.append(child)

        return depths

    def dfs_paths(
        self,
        source: str,
        target: str,
        max_paths: int = 50,
    ) -> List[List[str]]:
        """Enumerate up to `max_paths` simple paths source -> target.

        Returns a list of name-paths (each including both endpoints). A
        per-path visited set ensures simple paths even when the graph
        contains cycles.
        """
        if source not in self._nodes or target not in self._nodes:
            return []
        if source == target:
            return [[source]]

        results: List[List[str]] = []
        path: List[str] = [source]
        visited_in_path: Set[str] = {source}

        def _dfs(current: str) -> None:
            if len(results) >= max_paths:
                return
            for child in sorted(self._out.get(current, set())):
                if child in visited_in_path:
                    continue
                if child == target:
                    results.append(path + [child])
                    if len(results) >= max_paths:
                        return
                    continue
                visited_in_path.add(child)
                path.append(child)
                _dfs(child)
                path.pop()
                visited_in_path.discard(child)
                if len(results) >= max_paths:
                    return

        _dfs(source)
        return results

    def find_cycles(self) -> List[List[str]]:
        """Return one representative cycle per back-edge found.

        Iterative DFS with WHITE/GRAY/BLACK coloring. When the search
        encounters a GRAY neighbor, the recursion stack between the
        re-entry point and the current node forms the cycle.

        Iterative (not recursive) so a 2,000-node real-world graph cannot
        blow the Python recursion limit.
        """
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = {n: WHITE for n in self._nodes}
        cycles: List[List[str]] = []

        for start in sorted(self._nodes.keys()):
            if color[start] != WHITE:
                continue

            path: List[str] = [start]
            path_index: Dict[str, int] = {start: 0}
            color[start] = GRAY
            stack: List[Tuple[str, Iterator[str]]] = [
                (start, iter(sorted(self._out.get(start, set()))))
            ]

            while stack:
                node, it = stack[-1]
                child = next(it, None)
                if child is None:
                    stack.pop()
                    path.pop()
                    path_index.pop(node, None)
                    color[node] = BLACK
                    continue

                c = color.get(child, WHITE)
                if c == WHITE:
                    color[child] = GRAY
                    path_index[child] = len(path)
                    path.append(child)
                    stack.append(
                        (child, iter(sorted(self._out.get(child, set()))))
                    )
                elif c == GRAY:
                    start_idx = path_index[child]
                    cycles.append(path[start_idx:] + [child])

        return cycles

    def topological_sort(self) -> Tuple[List[str], Dict[str, int]]:
        """Kahn's algorithm.

        Returns
        -------
        order : list[str]
            A valid topological ordering. If the graph has cycles, only the
            acyclic prefix is returned and `len(order) < len(self)` signals
            the leftover cyclic nodes.
        in_degrees : dict[str, int]
            Original (pre-peel) in-degree of every node, suitable for the
            scorer's blast-radius signal.
        """
        in_degrees = {n: len(self._in.get(n, set())) for n in self._nodes}
        remaining = dict(in_degrees)

        queue: deque[str] = deque(
            sorted(n for n, d in remaining.items() if d == 0)
        )
        order: List[str] = []

        while queue:
            n = queue.popleft()
            order.append(n)
            for child in sorted(self._out.get(n, set())):
                remaining[child] -= 1
                if remaining[child] == 0:
                    queue.append(child)

        return order, in_degrees
