"""Response schema for POST /api/analyze.

See docs/API_CONTRACT.md for the documented contract. The request is a
multipart file upload handled directly via FastAPI File() parameters in
the route (see `app.api.routes.analyze`), so no request body schema is
needed here — only the response shape.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.mitigation import MitigationPrioritySchema
from app.schemas.risk import RiskAssessmentSchema, RiskSummarySchema


class ProjectInfo(BaseModel):
    name: str
    version: Optional[str] = None


class VulnerabilityReferenceSchema(BaseModel):
    url: str
    type: Optional[str] = None


class VulnerabilitySchema(BaseModel):
    id: str = Field(description="Canonical vulnerability id (e.g. a GHSA id) — the OSV `id` field.")
    source: str = Field(description='Always "OSV" in Phase 2.')
    summary: Optional[str] = None
    severity: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN")
    severity_vector: Optional[str] = Field(
        default=None,
        description=(
            "Raw CVSS vector string when OSV provided one and no plain severity label "
            "was available. Not interpreted into a score by RippleGuard."
        ),
    )
    aliases: List[str] = Field(
        default_factory=list, description="Other identifiers for the same vulnerability, e.g. CVE ids."
    )
    references: List[VulnerabilityReferenceSchema] = []
    published: Optional[str] = None
    modified: Optional[str] = None


class DependencyNodeSchema(BaseModel):
    id: str
    name: str
    version: Optional[str] = None
    declared_range: Optional[str] = Field(
        default=None,
        description=(
            "Raw semver range from package.json, only present when resolution_status "
            "is direct_dependencies_only (no exact version was resolved)."
        ),
    )
    ecosystem: str
    relation: str = Field(description="root | direct | transitive")
    category: Optional[str] = Field(default=None, description="runtime | development | optional")
    depth: int
    install_path: Optional[str] = Field(
        default=None,
        description="node_modules path this node resolved to, when known from a lockfile.",
    )
    vulnerabilities: List[VulnerabilitySchema] = Field(
        default_factory=list,
        description="Always a list, never null. Empty means either 'checked, clean' or "
        "'not checked' — see vulnerability_lookup_status to tell which.",
    )
    vulnerability_lookup_status: Optional[str] = Field(
        default=None,
        description="ok | unavailable | not_checked | not_applicable (see docs/API_CONTRACT.md)",
    )
    risk_assessment: Optional[RiskAssessmentSchema] = Field(
        default=None,
        description="Baseline contextual risk (Phase 4), present only for nodes with a known "
        "vulnerability or an inconclusive vulnerability lookup. Null for the root, and for nodes "
        "genuinely checked and found clean — see docs/API_CONTRACT.md.",
    )


class DependencyEdgeSchema(BaseModel):
    source: str
    target: str


class StatisticsSchema(BaseModel):
    total_dependencies: int
    direct_dependencies: int
    transitive_dependencies: int
    max_depth: int
    category_breakdown: Dict[str, int]


class VulnerabilitySummarySchema(BaseModel):
    status: str = Field(description="ok | partial | unavailable")
    vulnerable_dependencies: int
    total_vulnerabilities: int
    direct_vulnerable_dependencies: int
    transitive_vulnerable_dependencies: int
    severity_breakdown: Dict[str, int]
    nodes_checked: int
    nodes_skipped_no_version: int
    nodes_failed: int


class AnalyzeResponse(BaseModel):
    analysis_id: str = Field(
        description="Ephemeral, in-memory identifier for this analysis. Pass it to POST "
        "/api/simulate (with a node_id from this response's nodes[]) to simulate a compromise. "
        "Not durable — see docs/API_CONTRACT.md for expiry/eviction behavior."
    )
    project: ProjectInfo
    ecosystem: str
    resolution_status: str = Field(
        description="lockfile_resolved | lockfile_partial | direct_dependencies_only"
    )
    statistics: StatisticsSchema
    vulnerability_summary: VulnerabilitySummarySchema
    risk_summary: RiskSummarySchema
    mitigation_priorities: List[MitigationPrioritySchema] = Field(
        default_factory=list,
        description="Top-N (see docs/API_CONTRACT.md for the exact cap) dependencies to investigate "
        "or mitigate first, deterministically ranked. Reuses the same RiskAssessment objects as "
        "risk_summary/nodes[].risk_assessment — this is a ranking + recommendation layer on top of "
        "them, not a separate analysis. Excludes clean dependencies (no known vulnerability and no "
        "inconclusive lookup).",
    )
    nodes: List[DependencyNodeSchema]
    edges: List[DependencyEdgeSchema]
    unresolved_dependencies: List[str] = []
    warnings: List[str] = []
