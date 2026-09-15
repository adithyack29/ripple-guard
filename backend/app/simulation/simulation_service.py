"""Orchestrates Phase 3 compromise simulation, Phase 4 post-simulation
contextual risk, and a Phase 5 mitigation recommendation for the
simulated node.

Pipeline: `app.api.routes.simulate` -> `simulate_compromise()` (this
module) -> `app.simulation.propagation` (pure graph algorithms) for
impact, then `app.risk.risk_service` (pure scoring) for risk, then
`app.mitigation.prioritization` for a recommended action + reason ->
`app.models.simulation` (result assembly). The route then converts the
returned `SimulationResult` into `app.schemas.simulate` for the response.

Deliberately does NOT produce a project-wide mitigation ranking — that's
`/api/analyze`'s job (`app.services.analysis_service`). This module only
recommends an action for the single node the caller chose to simulate.

No network I/O is involved here (unlike Phase 2's `analyze_project`), so
this is a plain synchronous function — no async needed.
"""

from typing import List

from app.core.config import get_settings
from app.core.exceptions import AnalysisNotFoundError, InvalidSimulationNodeError
from app.graph.dependency_graph import DependencyGraph
from app.mitigation.prioritization import build_mitigation_reason, recommended_action_for_level
from app.models.dependency import DependencyRelation
from app.models.mitigation import MitigationRecommendation
from app.models.simulation import AffectedNode, ImpactType, SimulationResult
from app.risk.risk_service import compute_risk_assessment
from app.services.analysis_store import AnalysisStore
from app.simulation.propagation import (
    build_application_impact,
    build_blast_radius,
    compute_affected_depths,
    find_propagation_paths,
)


def simulate_compromise(analysis_id: str, node_id: str, store: AnalysisStore) -> SimulationResult:
    """Simulate compromising `node_id` within the analysis stored under
    `analysis_id`, compute its downstream blast radius, and combine that
    impact with the node's known vulnerability data into a contextual
    risk assessment.

    Raises `AnalysisNotFoundError` if `analysis_id` is unknown/expired,
    or `InvalidSimulationNodeError` if `node_id` doesn't exist in that
    analysis, is the root node, or has no resolved version (see
    "simulation precondition" in docs/ARCHITECTURE.md). Looking the node
    up inside the stored analysis's own graph also guarantees it belongs
    to that analysis — there is no way to reference a node from a
    different analysis.

    The simulation engine is deliberately vulnerability-agnostic: any
    valid dependency node can be "compromised" here regardless of
    whether OSV found anything for it (the problem statement explicitly
    allows simulated compromise scenarios) — see docs/ARCHITECTURE.md,
    "Phase 3". When the node has no known vulnerability, the resulting
    `risk_assessment.basis` is `SIMULATED_NO_VULNERABILITY`, not
    `KNOWN_VULNERABILITY` — see docs/ARCHITECTURE.md, "Phase 4".
    """
    analysis = store.get(analysis_id)
    if analysis is None:
        raise AnalysisNotFoundError(
            f"No analysis found for analysis_id '{analysis_id}' — it may have expired or never existed."
        )

    graph = analysis.graph
    node = graph.get_node(node_id)
    if node is None:
        raise InvalidSimulationNodeError(f"Node '{node_id}' does not exist in this analysis.")
    if node.relation == DependencyRelation.ROOT:
        raise InvalidSimulationNodeError(
            f"'{node_id}' is the analyzed project's root and cannot be a compromise target. "
            "Select a dependency package instead."
        )
    if node.version is None:
        raise InvalidSimulationNodeError(
            f"'{node_id}' has no resolved version (this analysis had no package-lock.json), "
            "so its compromise cannot be simulated. Re-run /api/analyze with a lockfile."
        )

    root = graph.root
    assert root is not None, "every analysis graph has exactly one root node"

    settings = get_settings()
    depths = compute_affected_depths(graph, node_id)
    paths, truncated = find_propagation_paths(
        graph,
        node_id,
        root.id,
        max_paths=settings.simulation_max_propagation_paths,
        max_path_length=settings.simulation_max_path_length,
    )

    affected_nodes = _build_affected_nodes(graph, depths)
    application_impact = build_application_impact(depths, root.id)
    blast_radius = build_blast_radius(depths, root.id, paths, truncated)

    risk_assessment = compute_risk_assessment(
        vulnerabilities=node.vulnerabilities,
        lookup_status=node.vulnerability_lookup_status,
        application_affected=application_impact.affected,
        affected_dependencies=blast_radius.affected_dependencies,
        affected_nodes=blast_radius.affected_nodes,
        propagation_path_count=blast_radius.propagation_path_count,
        max_propagation_depth=blast_radius.max_propagation_depth,
        direct_dependents=len(graph.dependents_of(node_id)),
    )

    mitigation = MitigationRecommendation(
        recommended_action=recommended_action_for_level(risk_assessment.level),
        reason=build_mitigation_reason(
            level=risk_assessment.level,
            basis=risk_assessment.basis,
            highest_severity=risk_assessment.highest_severity,
            vulnerability_count=risk_assessment.vulnerability_count,
            application_affected=application_impact.affected,
            affected_dependencies=blast_radius.affected_dependencies,
        ),
    )

    warnings: List[str] = []
    if truncated:
        warnings.append(
            f"Propagation path enumeration stopped at {len(paths)} path(s) (bound reached); more "
            "paths may exist. affected_nodes, affected_dependencies, and max_propagation_depth are "
            "exact regardless, since they come from full graph reachability, not path enumeration."
        )

    return SimulationResult(
        analysis_id=analysis_id,
        compromised_node_id=node_id,
        compromised_node_name=node.name,
        compromised_node_version=node.version,
        blast_radius=blast_radius,
        affected_nodes=affected_nodes,
        propagation_paths=paths,
        application_impact=application_impact,
        risk_assessment=risk_assessment,
        mitigation=mitigation,
        warnings=warnings,
    )


def _build_affected_nodes(graph: DependencyGraph, depths) -> List[AffectedNode]:
    affected = []
    for affected_id, depth in depths.items():
        node = graph.get_node(affected_id)
        assert node is not None
        affected.append(
            AffectedNode(
                node_id=affected_id,
                name=node.name,
                version=node.version,
                relation=node.relation,
                impact_type=ImpactType.DIRECT if depth == 1 else ImpactType.INDIRECT,
                depth=depth,
            )
        )
    affected.sort(key=lambda n: (n.depth, n.node_id))
    return affected
