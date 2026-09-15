from app.models.risk import RiskBasis, RiskLevel
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilityLookupStatus,
    VulnerabilitySeverityLevel,
)
from app.risk.risk_service import compute_risk_assessment


def _vuln(severity: VulnerabilitySeverityLevel, vuln_id: str = "GHSA-x") -> Vulnerability:
    return Vulnerability(id=vuln_id, source="OSV", severity=severity)


# 1. CRITICAL vulnerability + high impact -> CRITICAL risk.
def test_critical_vulnerability_high_impact_is_critical():
    result = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.CRITICAL)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=10,
        affected_nodes=15,
        propagation_path_count=5,
        max_propagation_depth=5,
        direct_dependents=3,
    )
    assert result.level == RiskLevel.CRITICAL
    assert result.score == 100
    assert result.basis == RiskBasis.KNOWN_VULNERABILITY


# 2. HIGH vulnerability + low impact -> lower contextual risk than #1.
def test_high_vulnerability_low_impact_is_lower_than_critical_high_impact():
    high_impact = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.CRITICAL)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=10,
        affected_nodes=15,
        propagation_path_count=5,
        max_propagation_depth=5,
        direct_dependents=3,
    )
    low_impact = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.HIGH)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=False,
        affected_dependencies=0,
        affected_nodes=0,
        propagation_path_count=0,
        max_propagation_depth=0,
        direct_dependents=0,
    )
    assert low_impact.score < high_impact.score
    assert low_impact.level != RiskLevel.CRITICAL


# 3. MEDIUM vulnerability + large blast radius -> elevated risk.
def test_medium_vulnerability_large_blast_radius_is_elevated():
    small_blast = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.MEDIUM)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=0,
        affected_nodes=1,
        propagation_path_count=1,
        max_propagation_depth=1,
        direct_dependents=0,
    )
    large_blast = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.MEDIUM)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=10,
        affected_nodes=15,
        propagation_path_count=5,
        max_propagation_depth=4,
        direct_dependents=3,
    )
    assert large_blast.score > small_blast.score


# 4. LOW vulnerability + very high structural exposure — still bounded
# by severity; structural_importance never inflates the composite score.
def test_low_vulnerability_high_structural_exposure_stays_bounded_by_severity():
    result = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.LOW)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=10,
        affected_nodes=15,
        propagation_path_count=5,
        max_propagation_depth=5,
        direct_dependents=50,  # very high structural exposure
    )
    # severity=30 caps the contribution: even with max impact elsewhere,
    # score = 0.4*30 + 0.25*100 + 0.2*100 + 0.15*100 = 12 + 25 + 20 + 15 = 72
    assert result.score == 72
    assert result.breakdown.structural_importance == 100
    # structural importance alone must not push this above what severity allows
    assert result.level != RiskLevel.CRITICAL


# 5. Vulnerability with UNKNOWN severity.
def test_unknown_severity_vulnerability_is_not_treated_as_low():
    unknown = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.UNKNOWN)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=5,
        affected_nodes=5,
        propagation_path_count=2,
        max_propagation_depth=2,
        direct_dependents=1,
    )
    low = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.LOW)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=5,
        affected_nodes=5,
        propagation_path_count=2,
        max_propagation_depth=2,
        direct_dependents=1,
    )
    assert unknown.breakdown.severity == 50
    assert unknown.score > low.score
    assert unknown.basis == RiskBasis.KNOWN_VULNERABILITY  # a real, confirmed vulnerability exists


# 6. No vulnerability.
def test_no_vulnerability_is_simulated_basis_and_capped_at_medium():
    result = compute_risk_assessment(
        vulnerabilities=[],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=10,
        affected_nodes=15,
        propagation_path_count=5,
        max_propagation_depth=5,
        direct_dependents=3,
    )
    assert result.basis == RiskBasis.SIMULATED_NO_VULNERABILITY
    assert result.breakdown.severity == 0
    assert result.score == 60  # capped: 0.25*100+0.20*100+0.15*100
    assert result.level in (RiskLevel.MEDIUM, RiskLevel.LOW)
    assert result.level not in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    assert result.highest_severity is None


# 7. Multiple vulnerabilities on one package.
def test_multiple_vulnerabilities_use_worst_severity_and_report_count():
    result = compute_risk_assessment(
        vulnerabilities=[
            _vuln(VulnerabilitySeverityLevel.LOW, "GHSA-a"),
            _vuln(VulnerabilitySeverityLevel.CRITICAL, "GHSA-b"),
            _vuln(VulnerabilitySeverityLevel.MEDIUM, "GHSA-c"),
        ],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=1,
        affected_nodes=1,
        propagation_path_count=1,
        max_propagation_depth=1,
        direct_dependents=0,
    )
    assert result.vulnerability_count == 3
    assert result.highest_severity == VulnerabilitySeverityLevel.CRITICAL
    assert result.breakdown.severity == 100
    assert "3" in result.explanation  # explanation reflects actual count


# 8. OSV unavailable.
def test_osv_unavailable_is_undetermined_not_low():
    result = compute_risk_assessment(
        vulnerabilities=[],
        lookup_status=VulnerabilityLookupStatus.UNAVAILABLE,
        application_affected=True,
        affected_dependencies=5,
        affected_nodes=5,
        propagation_path_count=2,
        max_propagation_depth=2,
        direct_dependents=1,
    )
    assert result.basis == RiskBasis.UNDETERMINED
    assert result.level == RiskLevel.UNDETERMINED
    assert result.score is None
    assert result.breakdown.severity is None
    # impact-derived breakdown fields remain real numbers, not hidden
    assert result.breakdown.reachability > 0


def test_not_checked_is_also_undetermined():
    result = compute_risk_assessment(
        vulnerabilities=[],
        lookup_status=VulnerabilityLookupStatus.NOT_CHECKED,
        application_affected=False,
        affected_dependencies=0,
        affected_nodes=0,
        propagation_path_count=0,
        max_propagation_depth=0,
        direct_dependents=0,
    )
    assert result.basis == RiskBasis.UNDETERMINED
    assert result.level == RiskLevel.UNDETERMINED
    assert result.score is None


# 9. Application affected vs not affected.
def test_application_affected_increases_score_over_not_affected():
    affected = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.HIGH)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=2,
        affected_nodes=3,
        propagation_path_count=1,
        max_propagation_depth=2,
        direct_dependents=1,
    )
    not_affected = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.HIGH)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=False,
        affected_dependencies=2,
        affected_nodes=3,
        propagation_path_count=1,
        max_propagation_depth=2,
        direct_dependents=1,
    )
    assert affected.score > not_affected.score


# 10. Different propagation depths.
def test_deeper_propagation_increases_score_monotonically():
    shallow = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.MEDIUM)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=1,
        affected_nodes=1,
        propagation_path_count=1,
        max_propagation_depth=1,
        direct_dependents=0,
    )
    deep = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.MEDIUM)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=1,
        affected_nodes=1,
        propagation_path_count=1,
        max_propagation_depth=4,
        direct_dependents=0,
    )
    assert deep.score > shallow.score


# 11. Different blast radii.
def test_larger_blast_radius_increases_score():
    small = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.MEDIUM)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=0,
        affected_nodes=1,
        propagation_path_count=1,
        max_propagation_depth=1,
        direct_dependents=0,
    )
    large = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.MEDIUM)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=0,
        affected_nodes=15,
        propagation_path_count=5,
        max_propagation_depth=1,
        direct_dependents=0,
    )
    assert large.score > small.score


# 12. Risk score deterministic across repeated runs.
def test_deterministic_across_repeated_calls():
    kwargs = dict(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.HIGH)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=4,
        affected_nodes=6,
        propagation_path_count=2,
        max_propagation_depth=3,
        direct_dependents=2,
    )
    first = compute_risk_assessment(**kwargs)
    second = compute_risk_assessment(**kwargs)
    assert first.score == second.score
    assert first.level == second.level
    assert first.explanation == second.explanation
    assert first.breakdown == second.breakdown


# 13. Risk level threshold boundaries — see test_risk_scoring.py for the
# exhaustive parametrized boundary test against risk_level_for_score
# directly; this confirms the same behavior end-to-end through
# compute_risk_assessment.
def test_threshold_boundary_end_to_end():
    just_critical = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.CRITICAL)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=10,
        affected_nodes=15,
        propagation_path_count=5,
        max_propagation_depth=5,
        direct_dependents=0,
    )
    assert just_critical.score == 100
    assert just_critical.level == RiskLevel.CRITICAL


# 14. Risk explanation contains actual factors.
def test_explanation_contains_real_computed_values():
    result = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.HIGH)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=7,
        affected_nodes=9,
        propagation_path_count=3,
        max_propagation_depth=4,
        direct_dependents=1,
    )
    assert "High" in result.explanation
    assert "7" in result.explanation
    assert "3" in result.explanation
    assert "4" in result.explanation


def test_explanation_mentions_structural_significance_when_relevant():
    result = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.MEDIUM)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=1,
        affected_nodes=1,
        propagation_path_count=1,
        max_propagation_depth=1,
        direct_dependents=3,
    )
    assert "Structurally significant" in result.explanation
    assert "3" in result.explanation


def test_explanation_distinguishes_undetermined_reasons():
    unavailable = compute_risk_assessment(
        vulnerabilities=[],
        lookup_status=VulnerabilityLookupStatus.UNAVAILABLE,
        application_affected=False,
        affected_dependencies=0,
        affected_nodes=0,
        propagation_path_count=0,
        max_propagation_depth=0,
        direct_dependents=0,
    )
    not_checked = compute_risk_assessment(
        vulnerabilities=[],
        lookup_status=VulnerabilityLookupStatus.NOT_CHECKED,
        application_affected=False,
        affected_dependencies=0,
        affected_nodes=0,
        propagation_path_count=0,
        max_propagation_depth=0,
        direct_dependents=0,
    )
    assert "lookup failure" in unavailable.explanation
    assert "no package-lock.json" in not_checked.explanation
    assert unavailable.explanation != not_checked.explanation


# 15. Risk ranking is deterministic.
def test_risk_ranking_deterministic():
    critical = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.CRITICAL)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=10,
        affected_nodes=15,
        propagation_path_count=5,
        max_propagation_depth=5,
        direct_dependents=0,
    )
    medium = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.MEDIUM)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=True,
        affected_dependencies=1,
        affected_nodes=1,
        propagation_path_count=1,
        max_propagation_depth=1,
        direct_dependents=0,
    )
    low = compute_risk_assessment(
        vulnerabilities=[_vuln(VulnerabilitySeverityLevel.LOW)],
        lookup_status=VulnerabilityLookupStatus.OK,
        application_affected=False,
        affected_dependencies=0,
        affected_nodes=0,
        propagation_path_count=0,
        max_propagation_depth=0,
        direct_dependents=0,
    )
    entries = [("medium", medium), ("critical", critical), ("low", low)]
    ranked_once = sorted(entries, key=lambda e: e[1].score, reverse=True)
    ranked_twice = sorted(entries, key=lambda e: e[1].score, reverse=True)
    assert [name for name, _ in ranked_once] == ["critical", "medium", "low"]
    assert ranked_once == ranked_twice
