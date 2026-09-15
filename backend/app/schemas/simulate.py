"""Request/response schemas for POST /api/simulate.

See docs/API_CONTRACT.md for the documented contract.
"""

from typing import List, Optional

from pydantic import BaseModel, Field

from app.schemas.mitigation import MitigationRecommendationSchema
from app.schemas.risk import RiskAssessmentSchema


class SimulateRequest(BaseModel):
    analysis_id: str = Field(description="The analysis_id returned by a prior POST /api/analyze call.")
    node_id: str = Field(description="The dependency node id to simulate as compromised.")


class CompromisedNodeSchema(BaseModel):
    node_id: str
    name: str
    version: Optional[str] = None


class AffectedNodeSchema(BaseModel):
    node_id: str
    name: str
    version: Optional[str] = None
    relation: str = Field(
        description="root | direct | transitive — this node's Phase 1 dependency relation to the "
        "project root. Distinct from impact_type."
    )
    impact_type: str = Field(
        description="direct | indirect — whether this node directly depends on the compromised node "
        "(depth 1), or is affected through one or more intermediate dependents (depth > 1)."
    )
    depth: int = Field(description="Hops from the compromised node in the impact direction; 1 = direct dependent.")


class BlastRadiusSchema(BaseModel):
    affected_nodes: int = Field(description="Total distinct nodes reachable from the compromised node in the impact direction (dependencies + the root, if reached).")
    affected_dependencies: int = Field(description="affected_nodes excluding the root.")
    affected_applications: int = Field(description="1 if the root/application is reachable, else 0 (single-project MVP, so this is always 0 or 1).")
    max_propagation_depth: int = Field(description="Longest shortest-hop depth among all affected nodes. Exact — not affected by path-count bounding.")
    propagation_path_count: int = Field(description="Number of propagation paths returned in propagation_paths (bounded — see propagation_paths_truncated).")
    propagation_paths_truncated: bool = Field(
        description="True if path enumeration stopped at a bound and more paths may exist beyond "
        "propagation_path_count. affected_nodes/affected_dependencies/max_propagation_depth remain "
        "exact regardless, since they come from full graph reachability, not path enumeration."
    )


class ApplicationImpactSchema(BaseModel):
    affected: bool = Field(description="Whether the analyzed application (root node) is reachable from the compromised node.")
    root_node_id: str
    shortest_path_depth: Optional[int] = Field(
        default=None, description="Hop depth at which the root was reached, or null if application affected is false."
    )


class SimulateResponse(BaseModel):
    analysis_id: str
    compromised_node: CompromisedNodeSchema
    blast_radius: BlastRadiusSchema
    affected_nodes: List[AffectedNodeSchema]
    propagation_paths: List[List[str]] = Field(
        description="Each path is ordered in the IMPACT direction: [compromised_node_id, ..., root_node_id]."
    )
    application_impact: ApplicationImpactSchema
    risk_assessment: RiskAssessmentSchema = Field(
        description="Contextual risk combining this node's known vulnerability data (if any) with "
        "the impact just computed. Always present — basis distinguishes a real known vulnerability "
        "from a hypothetical simulated-compromise assessment of a currently-clean package."
    )
    mitigation: MitigationRecommendationSchema = Field(
        description="Recommended action + short reason for THIS simulated node only — not a "
        "project-wide ranking (see /api/analyze's mitigation_priorities for that)."
    )
    warnings: List[str] = []
