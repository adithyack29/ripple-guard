"""Combines vulnerability data (Phase 2) and impact data (Phase 3) into a
single explainable `RiskAssessment` (Phase 4).

`compute_risk_assessment()` is the ONLY function callers should use. It
takes plain values — no `DependencyGraph`, no `DependencyNode`, no OSV
JSON — so it performs no network requests and no graph traversal itself;
the caller (`app.services.analysis_service` for baseline risk,
`app.simulation.simulation_service` for post-simulation risk) is
responsible for extracting these values from the graph/vulnerability
data it already has. This keeps the risk engine trivially unit-testable
and structurally unable to duplicate work another module already did.
"""

from typing import List, Optional

from app.models.risk import RiskAssessment, RiskBasis, RiskBreakdown, RiskLevel
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilityLookupStatus,
    VulnerabilitySeverityLevel,
)
from app.risk.explanation import build_explanation
from app.risk.scoring import (
    SEVERITY_SCORE_MAP,
    blast_radius_score,
    composite_score,
    propagation_score,
    reachability_score,
    risk_level_for_score,
    severity_score,
    structural_importance_score,
)

_UNDETERMINED_LOOKUP_STATUSES = (VulnerabilityLookupStatus.UNAVAILABLE, VulnerabilityLookupStatus.NOT_CHECKED)


def compute_risk_assessment(
    vulnerabilities: List[Vulnerability],
    lookup_status: VulnerabilityLookupStatus,
    application_affected: bool,
    affected_dependencies: int,
    affected_nodes: int,
    propagation_path_count: int,
    max_propagation_depth: int,
    direct_dependents: int,
) -> RiskAssessment:
    """Compute a contextual risk assessment for one dependency node.

    `basis` is derived first and determines everything else:

    - `lookup_status` unavailable/not-checked -> `UNDETERMINED`: whether
      a vulnerability even exists is unknown, so `score` is `None` and
      `level` is `UNDETERMINED` — never silently treated as "no
      vulnerability" / "low risk" (see docs/ARCHITECTURE.md).
    - `vulnerabilities` non-empty -> `KNOWN_VULNERABILITY`: the normal
      weighted formula, driven by the single most severe vulnerability.
    - otherwise -> `SIMULATED_NO_VULNERABILITY`: no known vulnerability,
      but the caller still wants impact-based context (this is how
      Phase 3's vulnerability-agnostic simulation surfaces risk for a
      hypothetically-compromised, currently-clean package). Severity
      contributes 0, which mathematically caps the score at 60/100
      (MEDIUM) — see `app.risk.scoring`.
    """
    if lookup_status in _UNDETERMINED_LOOKUP_STATUSES:
        basis = RiskBasis.UNDETERMINED
    elif vulnerabilities:
        basis = RiskBasis.KNOWN_VULNERABILITY
    else:
        basis = RiskBasis.SIMULATED_NO_VULNERABILITY

    reachability = reachability_score(application_affected, affected_dependencies)
    blast_radius = blast_radius_score(affected_nodes, propagation_path_count)
    propagation = propagation_score(max_propagation_depth)
    structural = structural_importance_score(direct_dependents)

    if basis == RiskBasis.UNDETERMINED:
        severity: Optional[int] = None
        score: Optional[int] = None
        level = RiskLevel.UNDETERMINED
    else:
        severity = severity_score(vulnerabilities)
        score = composite_score(severity, reachability, blast_radius, propagation)
        level = risk_level_for_score(score)

    highest_severity = _highest_severity(vulnerabilities)

    explanation = build_explanation(
        basis=basis,
        highest_severity=highest_severity,
        vulnerability_count=len(vulnerabilities),
        application_affected=application_affected,
        affected_dependencies=affected_dependencies,
        propagation_path_count=propagation_path_count,
        max_propagation_depth=max_propagation_depth,
        direct_dependents=direct_dependents,
        lookup_status=lookup_status,
    )

    return RiskAssessment(
        score=score,
        level=level,
        basis=basis,
        breakdown=RiskBreakdown(
            severity=severity,
            reachability=reachability,
            blast_radius=blast_radius,
            propagation=propagation,
            structural_importance=structural,
        ),
        explanation=explanation,
        vulnerability_count=len(vulnerabilities),
        highest_severity=highest_severity,
    )


def _highest_severity(vulnerabilities: List[Vulnerability]) -> Optional[VulnerabilitySeverityLevel]:
    """The vulnerability driving `severity_score` — same "most severe by
    mapped score" rule, so this always agrees with the number in
    `RiskBreakdown.severity`.
    """
    if not vulnerabilities:
        return None
    return max(vulnerabilities, key=lambda v: SEVERITY_SCORE_MAP[v.severity]).severity
