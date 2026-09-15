"""Shared Pydantic schemas for Phase 5 mitigation prioritization.

Used by both `app.schemas.analyze` (project-wide `mitigation_priorities`
list) and `app.schemas.simulate` (single-node `mitigation` recommendation),
so the recommendation shape is identical wherever it appears in the API.
"""

from typing import Optional

from pydantic import BaseModel, Field


class MitigationPrioritySchema(BaseModel):
    priority: int = Field(description="1-indexed rank; 1 is the top recommendation.")
    node_id: str
    name: str
    version: Optional[str] = None
    risk_level: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW | UNDETERMINED")
    risk_score: Optional[int] = Field(
        default=None, description="Null when risk_level is UNDETERMINED — never treat as 0/low."
    )
    vulnerability_count: int
    affected_dependencies: int
    affected_applications: int = Field(description="0 or 1 (single-project MVP).")
    recommended_action: str = Field(
        description="investigate_immediately | prioritize_remediation | plan_remediation | monitor | "
        "investigate_vulnerability_data — a deterministic, level-driven category for a human security "
        "team to act on. NOT automated remediation."
    )
    reason: str = Field(
        description="Short, data-driven reason for this ranking — distinct from (and shorter than) "
        "the full risk_assessment.explanation."
    )


class MitigationRecommendationSchema(BaseModel):
    """The single-node equivalent of a MitigationPrioritySchema entry,
    without a `priority` rank — used by POST /api/simulate.
    """

    recommended_action: str = Field(
        description="investigate_immediately | prioritize_remediation | plan_remediation | monitor | "
        "investigate_vulnerability_data"
    )
    reason: str
