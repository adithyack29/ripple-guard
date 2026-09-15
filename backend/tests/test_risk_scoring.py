import pytest

from app.models.risk import RiskLevel
from app.models.vulnerability import Vulnerability, VulnerabilitySeverityLevel
from app.risk.scoring import (
    blast_radius_score,
    composite_score,
    propagation_score,
    reachability_score,
    risk_level_for_score,
    severity_score,
    structural_importance_score,
)


def _vuln(severity: VulnerabilitySeverityLevel) -> Vulnerability:
    return Vulnerability(id="GHSA-x", source="OSV", severity=severity)


# --- severity_score -------------------------------------------------


def test_severity_score_mapping():
    assert severity_score([_vuln(VulnerabilitySeverityLevel.CRITICAL)]) == 100
    assert severity_score([_vuln(VulnerabilitySeverityLevel.HIGH)]) == 80
    assert severity_score([_vuln(VulnerabilitySeverityLevel.MEDIUM)]) == 60
    assert severity_score([_vuln(VulnerabilitySeverityLevel.LOW)]) == 30
    assert severity_score([_vuln(VulnerabilitySeverityLevel.UNKNOWN)]) == 50


def test_severity_score_empty_list_is_zero():
    assert severity_score([]) == 0


def test_severity_score_uses_worst_of_multiple_not_average():
    vulns = [_vuln(VulnerabilitySeverityLevel.LOW), _vuln(VulnerabilitySeverityLevel.CRITICAL)]
    assert severity_score(vulns) == 100  # not an average (which would be 65)


def test_unknown_severity_scores_above_low_below_medium():
    # UNKNOWN must never be treated as safe (below LOW) or overclaimed (at/above MEDIUM).
    assert severity_score([_vuln(VulnerabilitySeverityLevel.UNKNOWN)]) > severity_score(
        [_vuln(VulnerabilitySeverityLevel.LOW)]
    )
    assert severity_score([_vuln(VulnerabilitySeverityLevel.UNKNOWN)]) < severity_score(
        [_vuln(VulnerabilitySeverityLevel.MEDIUM)]
    )


# --- reachability_score -----------------------------------------------


def test_reachability_application_affected_dominates():
    affected_no_deps = reachability_score(application_affected=True, affected_dependencies=0)
    not_affected_many_deps = reachability_score(application_affected=False, affected_dependencies=10)
    assert affected_no_deps > not_affected_many_deps


def test_reachability_bonus_is_capped():
    at_cap = reachability_score(application_affected=True, affected_dependencies=10)
    beyond_cap = reachability_score(application_affected=True, affected_dependencies=1000)
    assert at_cap == beyond_cap
    assert at_cap <= 100


def test_reachability_monotonic_in_affected_dependencies():
    low = reachability_score(application_affected=True, affected_dependencies=1)
    high = reachability_score(application_affected=True, affected_dependencies=5)
    assert high > low


# --- blast_radius_score -------------------------------------------------


def test_blast_radius_capped_at_100():
    assert blast_radius_score(affected_nodes=10_000, propagation_path_count=10_000) == 100


def test_blast_radius_zero_when_nothing_affected():
    assert blast_radius_score(affected_nodes=0, propagation_path_count=0) == 0


def test_blast_radius_increases_with_scale():
    small = blast_radius_score(affected_nodes=1, propagation_path_count=1)
    large = blast_radius_score(affected_nodes=10, propagation_path_count=3)
    assert large > small


# --- propagation_score -------------------------------------------------


def test_propagation_score_scales_with_depth():
    assert propagation_score(0) == 0
    assert propagation_score(1) == 20
    assert propagation_score(5) == 100
    assert propagation_score(50) == 100  # capped, "deep" does not mean "off the charts"


def test_propagation_depth_is_not_automatically_critical_alone():
    # A single very deep chain, with no other signal, must not alone push
    # the composite score into CRITICAL territory (severity=0, reachability
    # default-low, blast_radius=0 in this synthetic check).
    score = composite_score(severity=0, reachability=15, blast_radius=0, propagation=100)
    assert risk_level_for_score(score) != RiskLevel.CRITICAL


# --- structural_importance_score ----------------------------------------


def test_structural_importance_scales_and_caps():
    assert structural_importance_score(0) == 0
    assert structural_importance_score(1) == 25
    assert structural_importance_score(4) == 100
    assert structural_importance_score(100) == 100


# --- composite_score & risk_level_for_score (threshold boundaries) ------


def test_composite_score_all_max_is_100():
    assert composite_score(severity=100, reachability=100, blast_radius=100, propagation=100) == 100


def test_composite_score_all_zero_is_zero():
    assert composite_score(severity=0, reachability=0, blast_radius=0, propagation=0) == 0


@pytest.mark.parametrize(
    "score,expected_level",
    [
        (100, RiskLevel.CRITICAL),
        (85, RiskLevel.CRITICAL),
        (84, RiskLevel.HIGH),
        (65, RiskLevel.HIGH),
        (64, RiskLevel.MEDIUM),
        (40, RiskLevel.MEDIUM),
        (39, RiskLevel.LOW),
        (0, RiskLevel.LOW),
    ],
)
def test_risk_level_thresholds_are_exact_boundaries(score, expected_level):
    assert risk_level_for_score(score) == expected_level


def test_severity_without_vulnerability_caps_score_at_60():
    # No known vulnerability -> severity=0 -> at most 60% of the formula
    # is reachable (25+20+15), even with maximum impact on every other axis.
    score = composite_score(severity=0, reachability=100, blast_radius=100, propagation=100)
    assert score == 60
    assert risk_level_for_score(score) in (RiskLevel.MEDIUM, RiskLevel.LOW)
    assert risk_level_for_score(score) != RiskLevel.CRITICAL
    assert risk_level_for_score(score) != RiskLevel.HIGH
