"""POST /api/simulate — Phase 3 compromise simulation & impact analysis,
combined with Phase 4 contextual risk scoring and a Phase 5 mitigation
recommendation for the simulated node.

Given an `analysis_id` (returned by a prior `POST /api/analyze` call) and
a `node_id` from that analysis's dependency graph, simulates that node
being compromised, reports the downstream blast radius (which other
dependencies — and possibly the analyzed application itself — would be
affected, how many hops away, and via which propagation paths), combines
that impact with the node's known vulnerability data (if any) into a
contextual risk assessment, and returns a recommended action + reason
for that single node.

Does NOT return a project-wide mitigation ranking — that's
`/api/analyze`'s `mitigation_priorities` (see docs/ARCHITECTURE.md).
"""

from fastapi import APIRouter

from app.models.simulation import SimulationResult
from app.schemas.mitigation import MitigationRecommendationSchema
from app.schemas.risk import RiskAssessmentSchema, RiskBreakdownSchema
from app.schemas.simulate import (
    AffectedNodeSchema,
    ApplicationImpactSchema,
    BlastRadiusSchema,
    CompromisedNodeSchema,
    SimulateRequest,
    SimulateResponse,
)
from app.services.analysis_store import get_analysis_store
from app.simulation.simulation_service import simulate_compromise

router = APIRouter(tags=["simulate"])


@router.post("/simulate", response_model=SimulateResponse)
async def simulate(request: SimulateRequest) -> SimulateResponse:
    result = simulate_compromise(request.analysis_id, request.node_id, get_analysis_store())
    return _to_response(result)


def _to_response(result: SimulationResult) -> SimulateResponse:
    return SimulateResponse(
        analysis_id=result.analysis_id,
        compromised_node=CompromisedNodeSchema(
            node_id=result.compromised_node_id,
            name=result.compromised_node_name,
            version=result.compromised_node_version,
        ),
        blast_radius=BlastRadiusSchema(
            affected_nodes=result.blast_radius.affected_nodes,
            affected_dependencies=result.blast_radius.affected_dependencies,
            affected_applications=result.blast_radius.affected_applications,
            max_propagation_depth=result.blast_radius.max_propagation_depth,
            propagation_path_count=result.blast_radius.propagation_path_count,
            propagation_paths_truncated=result.blast_radius.propagation_paths_truncated,
        ),
        affected_nodes=[
            AffectedNodeSchema(
                node_id=n.node_id,
                name=n.name,
                version=n.version,
                relation=n.relation.value,
                impact_type=n.impact_type.value,
                depth=n.depth,
            )
            for n in result.affected_nodes
        ],
        propagation_paths=result.propagation_paths,
        application_impact=ApplicationImpactSchema(
            affected=result.application_impact.affected,
            root_node_id=result.application_impact.root_node_id,
            shortest_path_depth=result.application_impact.shortest_path_depth,
        ),
        risk_assessment=RiskAssessmentSchema(
            score=result.risk_assessment.score,
            level=result.risk_assessment.level.value,
            basis=result.risk_assessment.basis.value,
            breakdown=RiskBreakdownSchema(
                severity=result.risk_assessment.breakdown.severity,
                reachability=result.risk_assessment.breakdown.reachability,
                blast_radius=result.risk_assessment.breakdown.blast_radius,
                propagation=result.risk_assessment.breakdown.propagation,
                structural_importance=result.risk_assessment.breakdown.structural_importance,
            ),
            explanation=result.risk_assessment.explanation,
            vulnerability_count=result.risk_assessment.vulnerability_count,
            highest_severity=(
                result.risk_assessment.highest_severity.value
                if result.risk_assessment.highest_severity is not None
                else None
            ),
        ),
        mitigation=MitigationRecommendationSchema(
            recommended_action=result.mitigation.recommended_action.value,
            reason=result.mitigation.reason,
        ),
        warnings=result.warnings,
    )
