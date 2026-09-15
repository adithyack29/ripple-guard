"""Internal domain model for Phase 4 contextual risk assessment.

A `RiskAssessment` combines Phase 2 vulnerability data with Phase 3
impact data into a single explainable score — it is the ONLY place these
two signals are combined. Neither `app.vulnerability` nor
`app.simulation.propagation` knows anything about risk; this model (and
`app.risk.risk_service`, which produces it) is intentionally the sole
meeting point. See docs/ARCHITECTURE.md, "Phase 4", for the full
rationale, including why this is an explainable prototype heuristic, not
a validated industry-standard risk score.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.models.vulnerability import VulnerabilitySeverityLevel


class RiskLevel(str, Enum):
    """A small number of understandable risk levels, derived from a
    deterministic score threshold — see `app.risk.scoring`.

    UNDETERMINED is not a level "below LOW" — it means the underlying
    vulnerability data was unavailable, so no numeric score was computed
    at all. It must never be confused with, sorted as, or displayed like
    a low-risk result.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNDETERMINED = "UNDETERMINED"


class RiskBasis(str, Enum):
    """What kind of evidence a risk assessment is actually based on.

    RippleGuard keeps "known vulnerability risk" and "simulated
    structural exposure" as related but explicitly distinct concepts
    (see docs/ARCHITECTURE.md) — this field is how a consumer tells
    them apart without having to infer it from the score alone.
    """

    KNOWN_VULNERABILITY = "known_vulnerability"
    """At least one real OSV vulnerability is known for this package/version."""

    SIMULATED_NO_VULNERABILITY = "simulated_no_vulnerability"
    """No known OSV vulnerability; this reflects hypothetical/structural
    exposure only, from a vulnerability-agnostic compromise simulation."""

    UNDETERMINED = "undetermined"
    """Whether a vulnerability exists at all is unknown (OSV lookup
    failed, or no resolved version was available to check) — never
    treated as equivalent to "no vulnerability" or "low risk"."""


@dataclass
class RiskBreakdown:
    """Component scores (0-100), each independently computed and
    documented in `app.risk.scoring`. `severity` is `None` only when
    `RiskAssessment.basis` is UNDETERMINED — every other field is always
    a real number, since reachability/blast-radius/propagation/structural
    importance are computable from the graph regardless of vulnerability
    status. `structural_importance` is informational only: it is
    surfaced here and used in the explanation, but deliberately excluded
    from the weighted composite `score` — see docs/ARCHITECTURE.md.
    """

    severity: Optional[int]
    reachability: int
    blast_radius: int
    propagation: int
    structural_importance: int


@dataclass
class RiskAssessment:
    score: Optional[int]
    level: RiskLevel
    basis: RiskBasis
    breakdown: RiskBreakdown
    explanation: str
    vulnerability_count: int
    highest_severity: Optional[VulnerabilitySeverityLevel]
