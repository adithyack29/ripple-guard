"""In-memory dependency graph, backed by NetworkX.

This is an internal representation only. NetworkX objects never leave
this module — `app.api.routes.analyze` converts nodes/edges into the
JSON-safe schemas defined in `app.schemas.analyze` before they reach the
API response.
"""

from typing import Dict, List, Optional

import networkx as nx

from app.models.dependency import DependencyEdge, DependencyNode, DependencyRelation


class DependencyGraph:
    """Wraps a networkx.DiGraph of DependencyNode objects keyed by node id."""

    def __init__(self) -> None:
        self._graph: "nx.DiGraph" = nx.DiGraph()
        self._nodes: Dict[str, DependencyNode] = {}

    def add_node(self, node: DependencyNode) -> DependencyNode:
        """Add a node if its id is new; otherwise return the existing node.

        Callers should add nodes in shortest-path-first (BFS) order: the
        first node stored under a given id "wins" for depth/category/
        relation, so depth ends up reflecting the shortest path from the
        root even when a package is reachable via multiple parents.
        """
        if node.id not in self._nodes:
            self._nodes[node.id] = node
            self._graph.add_node(node.id)
        return self._nodes[node.id]

    def add_edge(self, source_id: str, target_id: str) -> None:
        if source_id not in self._nodes or target_id not in self._nodes:
            raise ValueError(
                f"Cannot add edge {source_id} -> {target_id}: both endpoints "
                "must be added as nodes first"
            )
        self._graph.add_edge(source_id, target_id)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def get_node(self, node_id: str) -> Optional[DependencyNode]:
        return self._nodes.get(node_id)

    @property
    def nodes(self) -> List[DependencyNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> List[DependencyEdge]:
        return [DependencyEdge(source=s, target=t) for s, t in self._graph.edges()]

    @property
    def root(self) -> Optional[DependencyNode]:
        """The single root/application node in this graph, if present."""
        for node in self._nodes.values():
            if node.relation == DependencyRelation.ROOT:
                return node
        return None

    def dependents_of(self, node_id: str) -> List[str]:
        """Node ids that directly depend on `node_id` — i.e. predecessors
        of `node_id` in the stored dependency graph.

        Stored edges point parent -> dependency (A -> B means "A depends
        on B"). Compromise IMPACT travels the opposite way: if B is
        compromised, A (and anything that depends on A) may be affected.
        This method is that reversal — Phase 3's traversal
        (`app.simulation.propagation`) must always use this, never walk
        `self._graph` forward, to stay correct. See docs/ARCHITECTURE.md,
        "Phase 3", for the full rationale.

        Returns an empty list for an unknown node id, rather than raising.
        """
        if node_id not in self._nodes:
            return []
        return list(self._graph.predecessors(node_id))

    def __len__(self) -> int:
        return len(self._nodes)
