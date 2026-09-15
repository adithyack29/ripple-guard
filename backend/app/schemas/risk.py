"""Shared Pydantic schemas for Phase 4 contextual risk fields.

Used by both `app.schemas.analyze` (per-node `risk_assessment` +
analysis-level `risk_summary`) and `app.schemas.simulate`
(post-simulation `risk_assessment`), so the shape is identical wherever
risk appears in the API.
"""

from typing import List, Optional

from pydantic import BaseModel, Field


class RiskBreakdownSchema(BaseModel):
    severity: Optional[int] = Field(
        default=None,
        description="0-100, weighted 40%. Null only when level is UNDETERMINED (vulnerability "
        "presence itself is unknown) — 0 means a real, known absence of vulnerability.",
    )
    reachability: int = Field(description="0-100, weighted 25%. See docs/ARCHITECTURE.md for the formula.")
    blast_radius: int = Field(description="0-100, weighted 20%.")
    propagation: int = Field(description="0-100, weighted 15%.")
    structural_importance: int = Field(
        description="0-100. Informational only — NOT included in the weighted score. Based on "
        "direct dependent count; see docs/ARCHITECTURE.md."
    )


class RiskAssessmentSchema(BaseModel):
    score: Optional[int] = Field(
        default=None,
        description="0-100 composite contextual risk score, or null when level is UNDETERMINED. "
        "Never treat a null score as 0/low — see basis and level.",
    )
    level: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW | UNDETERMINED")
    basis: str = Field(
        description="known_vulnerability (score driven by a real OSV finding) | "
        "simulated_no_vulnerability (no known vulnerability; score reflects hypothetical/structural "
        "exposure only, mathematically capped at 60/MEDIUM) | undetermined (vulnerability presence "
        "itself is unknown — OSV lookup failed or no lockfile was supplied)."
    )
    breakdown: RiskBreakdownSchema
    explanation: str = Field(
        description="Human-readable, generated from the actual computed signals — never a generic string."
    )
    vulnerability_count: int
    highest_severity: Optional[str] = Field(
        default=None, description="CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN — the vulnerability driving `breakdown.severity`, if any."
    )


class RiskRankEntrySchema(BaseModel):
    node_id: str
    name: str
    version: Optional[str] = None
    score: Optional[int] = None
    level: str


class RiskSummarySchema(BaseModel):
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    undetermined_count: int
    highest_risk_score: Optional[int] = None
    highest_risk_level: Optional[str] = None
    ranked_risks: List[RiskRankEntrySchema] = Field(
        default_factory=list,
        description="UNDETERMINED entries first (uncertainty demands attention, never sorted as "
        "low risk), then scored entries by descending score. Bounded — see "
        "docs/API_CONTRACT.md for the cap.",
    )
