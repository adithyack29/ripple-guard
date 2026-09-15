"""Internal domain model for Phase 3 compromise-simulation results.

These describe the *impact* of a hypothetical (or real) compromise of one
dependency node — deliberately independent of both vulnerability status
(`app.models.vulnerability`) and any future contextual-risk rating. A
package can be vulnerable but low-impact, or not currently known
vulnerable but structurally high-impact — RippleGuard keeps these as
separate signals a later phase combines, not conflated here. See
docs/ARCHITECTURE.md, "Phase 3".
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from app.models.dependency import DependencyRelation
from app.models.mitigation import MitigationRecommendation
from app.models.risk import RiskAssessment


class ImpactType(str, Enum):
    """A node's relationship to the *compromised* node, in the impact
    (dependents) direction.

    Distinct from `DependencyRelation`, which describes a node's
    relationship to the *project root* in the dependency (requires)
    direction — a node can be a DIRECT impact type (an immediate
    dependent of the compromised package) while being a TRANSITIVE
    dependency of the project overall, and vice versa. Never conflate
    the two.
    """

    DIRECT = "direct"
    INDIRECT = "indirect"


@dataclass
class AffectedNode:
    node_id: str
    name: str
    version: Optional[str]
    relation: DependencyRelation
    impact_type: ImpactType
    depth: int


@dataclass
class BlastRadius:
    """Graph-based impact metrics. Deliberately descriptive only — no
    severity/priority judgment. See docs/ARCHITECTURE.md for exact
    definitions of each field.
    """

    affected_nodes: int
    affected_dependencies: int
    affected_applications: int
    max_propagation_depth: int
    propagation_path_count: int
    propagation_paths_truncated: bool


@dataclass
class ApplicationImpact:
    affected: bool
    root_node_id: str
    shortest_path_depth: Optional[int] = None


@dataclass
class SimulationResult:
    analysis_id: str
    compromised_node_id: str
    compromised_node_name: str
    compromised_node_version: Optional[str]
    blast_radius: BlastRadius
    affected_nodes: List[AffectedNode]
    propagation_paths: List[List[str]]
    application_impact: ApplicationImpact
    risk_assessment: RiskAssessment
    mitigation: MitigationRecommendation
    warnings: List[str] = field(default_factory=list)
