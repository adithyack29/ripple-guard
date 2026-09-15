"""Test helper: build a `DependencyGraph` directly from a simple edge list,
for Phase 3 traversal/simulation tests that need precise, hand-crafted
graph shapes (linear chains, diamonds, cycles, disconnected components)
that would be awkward to express as package.json/package-lock.json
fixtures.

Not a test module itself (no `test_*` functions) — pytest will not
collect it.
"""

from collections import defaultdict, deque
from typing import Iterable, List, Optional, Tuple

from app.graph.dependency_graph import DependencyGraph
from app.models.dependency import (
    DependencyCategory,
    DependencyNode,
    DependencyRelation,
    Ecosystem,
    ResolutionStatus,
)
from app.models.vulnerability import VulnerabilityEnrichmentStatus
from app.services.analysis_service import (
    AnalysisResult,
    AnalysisStatistics,
    RiskSummary,
    VulnerabilitySummary,
)

DEFAULT_VERSION = "1.0.0"


def build_test_graph(
    edges: Iterable[Tuple[str, str]],
    root: str = "my-app",
    node_version: str = DEFAULT_VERSION,
    disconnected: Optional[List[str]] = None,
) -> DependencyGraph:
    """Build a DependencyGraph for traversal tests.

    `edges` is a list of (parent, child) pairs in DEPENDENCY direction
    (parent depends on child) — exactly like real package-lock.json
    resolution. Every non-root node gets `version=node_version` (so
    simulation's "must have a resolved version" precondition passes) and
    `name` equal to the given label, so — since a non-root node's id is
    `name@version` — a node labeled "B" has id `f"B@{node_version}"`.
    The root's id is always just its bare name (see
    `DependencyNode.id`).

    `relation`/`depth` are computed via BFS from `root` over `edges`,
    mirroring how Phase 1's real resolvers build a graph (not
    hand-specified per node), so these fixtures stay both simple to
    write and realistic. Diamond shapes (a node reachable via more than
    one parent) and cycles are both supported — a node is only ever
    added once; every edge into it is still recorded.

    `disconnected` optionally lists extra node names with no edges to
    anyone — useful for "disconnected node" test cases where a package
    exists in the graph but nothing downstream (including root) can be
    reached from it, and it can't reach anything either.
    """
    children = defaultdict(list)
    all_names = {root}
    for parent, child in edges:
        children[parent].append(child)
        all_names.add(parent)
        all_names.add(child)
    if disconnected:
        all_names.update(disconnected)

    def node_id(name: str) -> str:
        return name if name == root else f"{name}@{node_version}"

    graph = DependencyGraph()
    root_node = DependencyNode(
        name=root,
        version=node_version,
        ecosystem=Ecosystem.NPM,
        relation=DependencyRelation.ROOT,
        depth=0,
    )
    graph.add_node(root_node)

    visited = {root}
    queue: "deque[Tuple[str, int]]" = deque([(root, 0)])
    while queue:
        parent, depth = queue.popleft()
        for child in children.get(parent, []):
            if child in visited:
                graph.add_edge(node_id(parent), node_id(child))
                continue
            visited.add(child)
            relation = DependencyRelation.DIRECT if depth == 0 else DependencyRelation.TRANSITIVE
            child_node = DependencyNode(
                name=child,
                version=node_version,
                ecosystem=Ecosystem.NPM,
                relation=relation,
                depth=depth + 1,
                category=DependencyCategory.RUNTIME,
            )
            graph.add_node(child_node)
            graph.add_edge(node_id(parent), child_node.id)
            queue.append((child, depth + 1))

    for name in all_names - visited:
        isolated_node = DependencyNode(
            name=name,
            version=node_version,
            ecosystem=Ecosystem.NPM,
            relation=DependencyRelation.TRANSITIVE,
            depth=-1,
            category=DependencyCategory.RUNTIME,
        )
        graph.add_node(isolated_node)

    return graph


def build_test_analysis_result(graph: DependencyGraph) -> AnalysisResult:
    """Wrap a synthetic DependencyGraph (from `build_test_graph`) into a
    minimal but valid AnalysisResult, for tests that need to put a graph
    into an AnalysisStore (Phase 3's simulation_service/API tests). The
    statistics/vulnerability_summary values are plausible placeholders —
    Phase 3 code never reads them, only `.graph`.
    """
    root = graph.root
    assert root is not None
    return AnalysisResult(
        project_name=root.name,
        project_version=root.version,
        ecosystem=Ecosystem.NPM,
        resolution_status=ResolutionStatus.LOCKFILE_RESOLVED,
        graph=graph,
        statistics=AnalysisStatistics(
            total_dependencies=len(graph) - 1,
            direct_dependencies=sum(1 for n in graph.nodes if n.relation == DependencyRelation.DIRECT),
            transitive_dependencies=sum(
                1 for n in graph.nodes if n.relation == DependencyRelation.TRANSITIVE
            ),
            max_depth=max((n.depth for n in graph.nodes if n.relation != DependencyRelation.ROOT), default=0),
        ),
        vulnerability_summary=VulnerabilitySummary(
            status=VulnerabilityEnrichmentStatus.OK,
            vulnerable_dependencies=0,
            total_vulnerabilities=0,
            direct_vulnerable_dependencies=0,
            transitive_vulnerable_dependencies=0,
        ),
        risk_summary=RiskSummary(
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            undetermined_count=0,
            highest_risk_score=None,
            highest_risk_level=None,
        ),
        mitigation_priorities=[],
    )
