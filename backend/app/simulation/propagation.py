"""Pure graph-traversal algorithms for compromise-impact propagation,
plus small shared helpers that turn a traversal result into
`BlastRadius`/`ApplicationImpact` (used by both `app.services.
analysis_service` for baseline risk and `app.simulation.
simulation_service` for post-simulation results, so both compute impact
identically rather than each re-deriving it).

Operates only on `app.graph.dependency_graph.DependencyGraph` — no
knowledge of vulnerabilities, risk, analysis storage, or the API layer.

CRITICAL DIRECTION RULE (see docs/ARCHITECTURE.md, "Phase 3" for the
full rationale): stored dependency edges point parent -> dependency
(`A -> B` means "A depends on B"). Compromise IMPACT travels the
opposite way — if B is compromised, A may be affected, and anything that
depends on A may be affected too. Every traversal here goes through
`DependencyGraph.dependents_of()` (graph predecessors), never
`graph.edges` or any forward adjacency, to stay correct. This module
does not reverse or rebuild the stored graph — it just always walks it
backwards.
"""

from collections import deque
from typing import Dict, List, Tuple

from app.graph.dependency_graph import DependencyGraph
from app.models.simulation import ApplicationImpact, BlastRadius


def compute_affected_depths(graph: DependencyGraph, compromised_node_id: str) -> Dict[str, int]:
    """BFS over the impact direction (`dependents_of`) from the
    compromised node. Returns `{node_id: depth}` for every OTHER node
    reachable — the compromised node itself is never included. `depth=1`
    for direct dependents, incrementing per hop.

    Because BFS visits nodes in non-decreasing depth order and each node
    is enqueued at most once (via `visited`), every recorded depth is the
    shortest hop count from the compromised node — this is also what
    makes the traversal cycle-safe and guaranteed to terminate: a
    `visited` set means a node can never be re-enqueued, regardless of
    how many cycles or diamond-shaped dependency paths the graph
    contains. Runs in O(V + E), no recursion.
    """
    depths: Dict[str, int] = {}
    visited = {compromised_node_id}
    queue: "deque[Tuple[str, int]]" = deque([(compromised_node_id, 0)])

    while queue:
        node_id, depth = queue.popleft()
        for dependent_id in graph.dependents_of(node_id):
            if dependent_id in visited:
                continue
            visited.add(dependent_id)
            depths[dependent_id] = depth + 1
            queue.append((dependent_id, depth + 1))

    return depths


def find_propagation_paths(
    graph: DependencyGraph,
    compromised_node_id: str,
    target_node_id: str,
    max_paths: int,
    max_path_length: int,
) -> Tuple[List[List[str]], bool]:
    """Enumerate up to `max_paths` simple paths from the compromised node
    to `target_node_id` (typically the project root), in impact order:
    `[compromised_node_id, ..., target_node_id]`.

    Bounded on purpose: a diamond-shaped dependency graph can have
    combinatorially many simple paths between two nodes (see
    docs/ARCHITECTURE.md, "multiple paths") — this stops as soon as
    `max_paths` have been found rather than enumerating every one.
    `max_path_length` is an independent hard safety cap on individual
    path length.

    Returns `(paths, truncated)`. `truncated=True` means the search
    stopped early because a bound was hit — more paths *may* exist, but
    this is a conservative signal, not a guarantee (see
    `app.simulation.simulation_service`, which surfaces it as a warning
    rather than silently reporting the bounded count as exhaustive).
    `truncated=False` means every simple path within `max_path_length`
    was found.

    Cycle-safe by construction: a node already on the *current* path is
    never revisited (checked per-path via tuple membership, not with a
    global visited set), so multiple valid paths through a shared
    ancestor are still all individually discoverable, while a path that
    would loop back on itself is pruned immediately.
    """
    if compromised_node_id == target_node_id:
        return [[compromised_node_id]], False

    paths: List[List[str]] = []
    stack: List[Tuple[str, Tuple[str, ...]]] = [
        (compromised_node_id, (compromised_node_id,))
    ]
    truncated = False

    while stack:
        if len(paths) >= max_paths:
            truncated = True
            break

        current_id, path = stack.pop()

        if len(path) > max_path_length:
            truncated = True
            continue

        if current_id == target_node_id:
            paths.append(list(path))
            continue

        for dependent_id in graph.dependents_of(current_id):
            if dependent_id in path:
                continue  # cycle guard: never revisit a node already on this path
            stack.append((dependent_id, path + (dependent_id,)))

    paths.sort()
    return paths, truncated


def build_application_impact(depths: Dict[str, int], root_id: str) -> ApplicationImpact:
    """Turn a `compute_affected_depths` result into an `ApplicationImpact`.

    Shared by `app.simulation.simulation_service` (post-simulation) and
    `app.services.analysis_service` (baseline risk at analyze-time) so
    both compute this identically from the same reachability data,
    rather than each re-deriving it.
    """
    if root_id in depths:
        return ApplicationImpact(affected=True, root_node_id=root_id, shortest_path_depth=depths[root_id])
    return ApplicationImpact(affected=False, root_node_id=root_id, shortest_path_depth=None)


def build_blast_radius(
    depths: Dict[str, int], root_id: str, paths: List[List[str]], truncated: bool
) -> BlastRadius:
    """Turn `compute_affected_depths`/`find_propagation_paths` results
    into a `BlastRadius`. Shared for the same reason as
    `build_application_impact`.
    """
    affected_dependencies = len(depths) - (1 if root_id in depths else 0)
    affected_applications = 1 if root_id in depths else 0
    max_depth = max(depths.values()) if depths else 0
    return BlastRadius(
        affected_nodes=len(depths),
        affected_dependencies=affected_dependencies,
        affected_applications=affected_applications,
        max_propagation_depth=max_depth,
        propagation_path_count=len(paths),
        propagation_paths_truncated=truncated,
    )
