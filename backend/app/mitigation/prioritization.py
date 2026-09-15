"""Deterministic ranking, recommended actions, and reason generation for
Phase 5 mitigation prioritization.

Pure functions only — no graph traversal, no network requests, no new
risk signals. Everything here operates on `MitigationCandidate` objects
the caller (`app.services.analysis_service` for the project-wide list,
`app.simulation.simulation_service` for a single simulated node) already
built from Phase 4's `RiskAssessment` output.
"""

from typing import List, Optional

from app.models.mitigation import MitigationCandidate, MitigationPriority, RecommendedAction
from app.models.risk import RiskBasis, RiskLevel
from app.models.vulnerability import VulnerabilitySeverityLevel

# --- Deterministic ranking -----------------------------------------------
#
# Sort key, most to least significant (see docs/ARCHITECTURE.md, "Phase 5"
# for the full rationale):
#   1. UNDETERMINED first — unresolved uncertainty must never be sorted
#      as if it were low risk (never silently converted to "safe").
#   2. score, descending (only meaningful within the determined group;
#      UNDETERMINED entries have no score and are already separated above).
#   3. risk level, descending (CRITICAL > HIGH > MEDIUM > LOW).
#   4. highest known vulnerability severity, descending.
#   5. affected_applications, descending (reaching the analyzed
#      application outranks affecting only peer dependencies).
#   6. affected_dependencies, descending.
#   7. node_id, ascending — final, stable tie-breaker so two otherwise
#      identical candidates always sort the same way on every run.

_LEVEL_RANK = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH: 3,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 1,
    RiskLevel.UNDETERMINED: 0,
}

_SEVERITY_RANK = {
    VulnerabilitySeverityLevel.CRITICAL: 4,
    VulnerabilitySeverityLevel.HIGH: 3,
    VulnerabilitySeverityLevel.MEDIUM: 2,
    VulnerabilitySeverityLevel.LOW: 1,
    VulnerabilitySeverityLevel.UNKNOWN: 0,
}


def _sort_key(candidate: MitigationCandidate):
    assessment = candidate.assessment
    is_determined = assessment.level != RiskLevel.UNDETERMINED
    score = assessment.score if assessment.score is not None else -1
    severity_rank = _SEVERITY_RANK.get(assessment.highest_severity, -1)
    return (
        is_determined,  # False (0) sorts before True (1) -> UNDETERMINED first
        -score,
        -_LEVEL_RANK[assessment.level],
        -severity_rank,
        -candidate.affected_applications,
        -candidate.affected_dependencies,
        candidate.node_id,
    )


def sort_mitigation_candidates(candidates: List[MitigationCandidate]) -> List[MitigationCandidate]:
    """Sort candidates by the deterministic key above. Does not truncate —
    see `build_mitigation_priorities` for the top-N projection.
    """
    return sorted(candidates, key=_sort_key)


# --- Recommended action ---------------------------------------------------
#
# A deterministic, level-driven category — a prototype recommendation for
# a human to act on, never an automated remediation.
_RECOMMENDED_ACTIONS = {
    RiskLevel.CRITICAL: RecommendedAction.INVESTIGATE_IMMEDIATELY,
    RiskLevel.HIGH: RecommendedAction.PRIORITIZE_REMEDIATION,
    RiskLevel.MEDIUM: RecommendedAction.PLAN_REMEDIATION,
    RiskLevel.LOW: RecommendedAction.MONITOR,
    RiskLevel.UNDETERMINED: RecommendedAction.INVESTIGATE_VULNERABILITY_DATA,
}


def recommended_action_for_level(level: RiskLevel) -> RecommendedAction:
    return _RECOMMENDED_ACTIONS[level]


# --- Reason generation ------------------------------------------------------


def build_mitigation_reason(
    level: RiskLevel,
    basis: RiskBasis,
    highest_severity: Optional[VulnerabilitySeverityLevel],
    vulnerability_count: int,
    application_affected: bool,
    affected_dependencies: int,
) -> str:
    """A short, data-driven reason for this priority ranking — distinct
    from (and shorter than) `RiskAssessment.explanation`, which describes
    the impact in full. Never a single generic sentence: the vulnerability
    clause and impact clause both vary with the actual computed signals.
    """
    if level == RiskLevel.UNDETERMINED:
        return "Vulnerability data is unavailable for this dependency; investigate to determine actual risk."

    if basis == RiskBasis.SIMULATED_NO_VULNERABILITY:
        vuln_clause = "No known vulnerability, but simulated compromise"
    else:
        severity_label = (highest_severity.value if highest_severity else "UNKNOWN").capitalize()
        if vulnerability_count > 1:
            vuln_clause = f"{severity_label} severity vulnerability (highest of {vulnerability_count} known)"
        else:
            vuln_clause = f"{severity_label} severity vulnerability"

    if application_affected:
        impact_clause = "reaches the analyzed application"
    elif affected_dependencies > 0:
        impact_clause = f"affects {affected_dependencies} downstream dependencies"
    else:
        impact_clause = "has limited downstream exposure"

    return f"{vuln_clause}; {impact_clause}. Overall contextual risk: {level.value.title()}."


# --- Top-N projection --------------------------------------------------------


def build_mitigation_priorities(
    sorted_candidates: List[MitigationCandidate], max_entries: int
) -> List[MitigationPriority]:
    """Project the top `max_entries` of an ALREADY-SORTED candidate list
    (see `sort_mitigation_candidates`) into numbered `MitigationPriority`
    entries. `priority` starts at 1. The full candidate set still exists
    upstream (e.g. `RiskSummary`'s counts) — this list is intentionally
    summarized to the top N actionable dependencies, not the whole graph.
    """
    top = sorted_candidates[:max_entries]
    return [
        MitigationPriority(
            priority=index + 1,
            node_id=candidate.node_id,
            name=candidate.name,
            version=candidate.version,
            risk_level=candidate.assessment.level,
            risk_score=candidate.assessment.score,
            vulnerability_count=candidate.assessment.vulnerability_count,
            affected_dependencies=candidate.affected_dependencies,
            affected_applications=candidate.affected_applications,
            recommended_action=recommended_action_for_level(candidate.assessment.level),
            reason=build_mitigation_reason(
                level=candidate.assessment.level,
                basis=candidate.assessment.basis,
                highest_severity=candidate.assessment.highest_severity,
                vulnerability_count=candidate.assessment.vulnerability_count,
                application_affected=candidate.affected_applications > 0,
                affected_dependencies=candidate.affected_dependencies,
            ),
        )
        for index, candidate in enumerate(top)
    ]
