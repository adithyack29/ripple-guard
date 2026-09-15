"""Generates the human-readable `explanation` string for a RiskAssessment.

Built entirely from the actual computed signals passed in — never a
hard-coded generic sentence. Kept separate from `app.risk.scoring` so the
numeric model and the prose generation can be read, tested, and changed
independently.
"""

from typing import Optional

from app.models.risk import RiskBasis
from app.models.vulnerability import VulnerabilityLookupStatus, VulnerabilitySeverityLevel

_STRUCTURAL_SIGNIFICANCE_THRESHOLD = 2  # direct dependents at/above this get an explicit callout


def build_explanation(
    basis: RiskBasis,
    highest_severity: Optional[VulnerabilitySeverityLevel],
    vulnerability_count: int,
    application_affected: bool,
    affected_dependencies: int,
    propagation_path_count: int,
    max_propagation_depth: int,
    direct_dependents: int,
    lookup_status: VulnerabilityLookupStatus,
) -> str:
    impact_clause = _impact_clause(
        application_affected, affected_dependencies, propagation_path_count, max_propagation_depth
    )

    if basis == RiskBasis.UNDETERMINED:
        reason = (
            "an OSV lookup failure"
            if lookup_status == VulnerabilityLookupStatus.UNAVAILABLE
            else "no resolved version to check (no package-lock.json was supplied)"
        )
        return (
            f"Vulnerability data unavailable ({reason}); contextual risk cannot be determined "
            f"reliably. If compromised, {impact_clause}"
        )

    if basis == RiskBasis.SIMULATED_NO_VULNERABILITY:
        sentence = f"No known OSV vulnerability for this dependency; simulated compromise shows {impact_clause}"
    else:
        severity_label = (highest_severity.value if highest_severity else "UNKNOWN").capitalize()
        vuln_clause = (
            f"{severity_label} severity vulnerability (highest of {vulnerability_count} known vulnerabilities)"
            if vulnerability_count > 1
            else f"{severity_label} severity vulnerability"
        )
        sentence = f"{vuln_clause}; compromise shows {impact_clause}"

    if direct_dependents >= _STRUCTURAL_SIGNIFICANCE_THRESHOLD:
        sentence += (
            f" Structurally significant: {direct_dependents} packages directly depend on this dependency."
        )

    return sentence


def _impact_clause(
    application_affected: bool,
    affected_dependencies: int,
    propagation_path_count: int,
    max_propagation_depth: int,
) -> str:
    if application_affected:
        return (
            f"downstream reachability to the analyzed application through {propagation_path_count} "
            f"propagation path(s), affecting {affected_dependencies} dependencies at depth up to "
            f"{max_propagation_depth}."
        )
    if affected_dependencies > 0:
        return (
            f"impact on {affected_dependencies} downstream dependencies, but does not reach the "
            "analyzed application."
        )
    return "no downstream dependents and does not reach the analyzed application."
