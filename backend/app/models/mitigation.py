"""Internal domain model for Phase 5 mitigation prioritization.

Phase 4 answers "how risky is this dependency?" (`RiskAssessment`).
Phase 5 answers "which dependency should we address first?" — it ranks
the *existing* `RiskAssessment` objects deterministically and attaches a
short, data-driven reason and a recommended action category. It computes
no new signals of its own; everything here is derived from data Phase 2
(vulnerabilities), Phase 3 (impact), and Phase 4 (risk) already produced.
See docs/ARCHITECTURE.md, "Phase 5".
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.models.risk import RiskAssessment, RiskLevel


class RecommendedAction(str, Enum):
    """A deterministic, level-driven action category.

    These are prototype recommendations for a human security team to
    act on — NOT automated remediation, not a patch, not a pull request.
    RippleGuard never claims exploit likelihood, patch availability, or
    business criticality it wasn't given.
    """

    INVESTIGATE_IMMEDIATELY = "investigate_immediately"
    PRIORITIZE_REMEDIATION = "prioritize_remediation"
    PLAN_REMEDIATION = "plan_remediation"
    MONITOR = "monitor"
    INVESTIGATE_VULNERABILITY_DATA = "investigate_vulnerability_data"


@dataclass
class MitigationCandidate:
    """One assessed node's identity + risk assessment + raw impact counts —
    the input to the ranking algorithm in `app.mitigation.prioritization`.

    Deliberately carries the full `RiskAssessment` (not just score/level)
    so ranking and reason-generation can use `basis`/`highest_severity`
    without recomputing anything. `affected_dependencies`/
    `affected_applications` are raw counts (not the 0-100 blast_radius
    score) — the same numbers already computed by
    `app.simulation.propagation.build_blast_radius` for this node.
    """

    node_id: str
    name: str
    version: Optional[str]
    assessment: RiskAssessment
    affected_dependencies: int
    affected_applications: int


@dataclass
class MitigationPriority:
    """One ranked, numbered entry in a mitigation-priority list."""

    priority: int
    node_id: str
    name: str
    version: Optional[str]
    risk_level: RiskLevel
    risk_score: Optional[int]
    vulnerability_count: int
    affected_dependencies: int
    affected_applications: int
    recommended_action: RecommendedAction
    reason: str


@dataclass
class MitigationRecommendation:
    """The single-node equivalent of a `MitigationPriority`, without a
    `priority` rank — used by `POST /api/simulate`, which recommends an
    action for the one node the caller chose to simulate rather than
    producing a project-wide ranking (that's `/api/analyze`'s job — see
    docs/ARCHITECTURE.md, "Phase 5").
    """

    recommended_action: RecommendedAction
    reason: str
