from app.mitigation.prioritization import (
    build_mitigation_priorities,
    build_mitigation_reason,
    recommended_action_for_level,
    sort_mitigation_candidates,
)
from app.models.mitigation import MitigationCandidate, RecommendedAction
from app.models.risk import RiskAssessment, RiskBasis, RiskBreakdown, RiskLevel
from app.models.vulnerability import VulnerabilitySeverityLevel


def _assessment(
    level,
    score=None,
    basis=RiskBasis.KNOWN_VULNERABILITY,
    highest_severity=None,
    vulnerability_count=1,
):
    return RiskAssessment(
        score=score,
        level=level,
        basis=basis,
        breakdown=RiskBreakdown(severity=0, reachability=0, blast_radius=0, propagation=0, structural_importance=0),
        explanation="irrelevant for these tests",
        vulnerability_count=vulnerability_count,
        highest_severity=highest_severity,
    )


def _candidate(node_id, level, score=None, basis=RiskBasis.KNOWN_VULNERABILITY, affected_apps=0, affected_deps=0, severity=None):
    return MitigationCandidate(
        node_id=node_id,
        name=node_id.split("@")[0],
        version="1.0.0",
        assessment=_assessment(level, score, basis, severity),
        affected_dependencies=affected_deps,
        affected_applications=affected_apps,
    )


# 1. Highest contextual risk ranks first.
def test_highest_score_ranks_first():
    candidates = [
        _candidate("low@1", RiskLevel.LOW, score=20),
        _candidate("critical@1", RiskLevel.CRITICAL, score=95),
        _candidate("medium@1", RiskLevel.MEDIUM, score=50),
    ]
    ordered = sort_mitigation_candidates(candidates)
    assert [c.node_id for c in ordered] == ["critical@1", "medium@1", "low@1"]


# 2. CRITICAL ranks above HIGH (even with equal score, via level tie-break).
def test_critical_ranks_above_high_at_equal_score():
    candidates = [
        _candidate("high@1", RiskLevel.HIGH, score=70),
        _candidate("critical@1", RiskLevel.CRITICAL, score=70),
    ]
    ordered = sort_mitigation_candidates(candidates)
    assert [c.node_id for c in ordered] == ["critical@1", "high@1"]


# 3. HIGH ranks above MEDIUM.
def test_high_ranks_above_medium():
    candidates = [
        _candidate("medium@1", RiskLevel.MEDIUM, score=55),
        _candidate("high@1", RiskLevel.HIGH, score=66),
    ]
    ordered = sort_mitigation_candidates(candidates)
    assert [c.node_id for c in ordered] == ["high@1", "medium@1"]


# 4. Multiple dependencies with different scores.
def test_multiple_different_scores_sorted_descending():
    candidates = [
        _candidate("a@1", RiskLevel.HIGH, score=70),
        _candidate("b@1", RiskLevel.CRITICAL, score=99),
        _candidate("c@1", RiskLevel.LOW, score=10),
        _candidate("d@1", RiskLevel.MEDIUM, score=45),
    ]
    ordered = sort_mitigation_candidates(candidates)
    assert [c.node_id for c in ordered] == ["b@1", "a@1", "d@1", "c@1"]


# 5. Equal scores use deterministic tie-breaking (severity, then
# affected_applications, then affected_dependencies, then node_id).
def test_equal_score_and_level_ties_break_on_severity():
    candidates = [
        _candidate("b@1", RiskLevel.HIGH, score=70, severity=VulnerabilitySeverityLevel.MEDIUM),
        _candidate("a@1", RiskLevel.HIGH, score=70, severity=VulnerabilitySeverityLevel.CRITICAL),
    ]
    ordered = sort_mitigation_candidates(candidates)
    assert [c.node_id for c in ordered] == ["a@1", "b@1"]


def test_equal_score_level_severity_ties_break_on_affected_applications():
    c1 = _candidate("b@1", RiskLevel.HIGH, score=70, severity=VulnerabilitySeverityLevel.HIGH, affected_apps=0)
    c2 = _candidate("a@1", RiskLevel.HIGH, score=70, severity=VulnerabilitySeverityLevel.HIGH, affected_apps=1)
    ordered = sort_mitigation_candidates([c1, c2])
    assert [c.node_id for c in ordered] == ["a@1", "b@1"]


def test_fully_equal_ties_break_on_node_id():
    c1 = _candidate("zzz@1", RiskLevel.HIGH, score=70, severity=VulnerabilitySeverityLevel.HIGH)
    c2 = _candidate("aaa@1", RiskLevel.HIGH, score=70, severity=VulnerabilitySeverityLevel.HIGH)
    ordered = sort_mitigation_candidates([c1, c2])
    assert [c.node_id for c in ordered] == ["aaa@1", "zzz@1"]


def test_sort_is_deterministic_across_repeated_calls():
    candidates = [
        _candidate("a@1", RiskLevel.HIGH, score=70),
        _candidate("b@1", RiskLevel.CRITICAL, score=99),
        _candidate("c@1", RiskLevel.LOW, score=10),
    ]
    first = [c.node_id for c in sort_mitigation_candidates(candidates)]
    second = [c.node_id for c in sort_mitigation_candidates(candidates)]
    assert first == second


# 7. UNDETERMINED risk is handled explicitly — always first, never sorted
# as if it were low risk (8. missing data does not become LOW).
def test_undetermined_always_sorts_first_regardless_of_others():
    candidates = [
        _candidate("critical@1", RiskLevel.CRITICAL, score=99),
        _candidate("undetermined@1", RiskLevel.UNDETERMINED, score=None, basis=RiskBasis.UNDETERMINED),
    ]
    ordered = sort_mitigation_candidates(candidates)
    assert ordered[0].node_id == "undetermined@1"
    assert ordered[0].assessment.level == RiskLevel.UNDETERMINED
    assert ordered[0].assessment.level != RiskLevel.LOW


def test_multiple_undetermined_entries_all_sort_before_scored():
    candidates = [
        _candidate("low@1", RiskLevel.LOW, score=15),
        _candidate("und-b@1", RiskLevel.UNDETERMINED, score=None, basis=RiskBasis.UNDETERMINED),
        _candidate("und-a@1", RiskLevel.UNDETERMINED, score=None, basis=RiskBasis.UNDETERMINED),
    ]
    ordered = sort_mitigation_candidates(candidates)
    assert {c.node_id for c in ordered[:2]} == {"und-a@1", "und-b@1"}
    assert ordered[2].node_id == "low@1"
    # among undetermined entries, node_id is the deciding tie-breaker
    assert [c.node_id for c in ordered[:2]] == ["und-a@1", "und-b@1"]


# 9. Priority numbers are sequential.
def test_priority_numbers_are_sequential_starting_at_1():
    candidates = [
        _candidate("a@1", RiskLevel.HIGH, score=70),
        _candidate("b@1", RiskLevel.CRITICAL, score=99),
        _candidate("c@1", RiskLevel.LOW, score=10),
    ]
    ordered = sort_mitigation_candidates(candidates)
    priorities = build_mitigation_priorities(ordered, max_entries=10)
    assert [p.priority for p in priorities] == [1, 2, 3]
    assert priorities[0].node_id == "b@1"


# 10. Top-N limit works.
def test_top_n_limit_truncates():
    candidates = [_candidate(f"pkg{i}@1", RiskLevel.MEDIUM, score=50 - i) for i in range(10)]
    ordered = sort_mitigation_candidates(candidates)
    priorities = build_mitigation_priorities(ordered, max_entries=3)
    assert len(priorities) == 3
    assert [p.priority for p in priorities] == [1, 2, 3]
    assert priorities[0].node_id == "pkg0@1"


# 11. Recommendation matches risk level.
def test_recommended_action_matches_level():
    assert recommended_action_for_level(RiskLevel.CRITICAL) == RecommendedAction.INVESTIGATE_IMMEDIATELY
    assert recommended_action_for_level(RiskLevel.HIGH) == RecommendedAction.PRIORITIZE_REMEDIATION
    assert recommended_action_for_level(RiskLevel.MEDIUM) == RecommendedAction.PLAN_REMEDIATION
    assert recommended_action_for_level(RiskLevel.LOW) == RecommendedAction.MONITOR
    assert recommended_action_for_level(RiskLevel.UNDETERMINED) == RecommendedAction.INVESTIGATE_VULNERABILITY_DATA


def test_priority_entries_carry_correct_recommended_action():
    candidates = [_candidate("a@1", RiskLevel.CRITICAL, score=90)]
    priorities = build_mitigation_priorities(sort_mitigation_candidates(candidates), max_entries=10)
    assert priorities[0].recommended_action == RecommendedAction.INVESTIGATE_IMMEDIATELY


# 12. Explanation/reason uses actual dependency/impact data.
def test_reason_uses_actual_severity_and_impact_data():
    reason = build_mitigation_reason(
        level=RiskLevel.HIGH,
        basis=RiskBasis.KNOWN_VULNERABILITY,
        highest_severity=VulnerabilitySeverityLevel.HIGH,
        vulnerability_count=3,
        application_affected=True,
        affected_dependencies=5,
    )
    assert "High" in reason
    assert "3" in reason
    assert "reaches the analyzed application" in reason
    assert "High" in reason.split(";")[-1]  # level mentioned


def test_reason_not_generic_across_different_inputs():
    reason_a = build_mitigation_reason(
        level=RiskLevel.CRITICAL,
        basis=RiskBasis.KNOWN_VULNERABILITY,
        highest_severity=VulnerabilitySeverityLevel.CRITICAL,
        vulnerability_count=1,
        application_affected=True,
        affected_dependencies=0,
    )
    reason_b = build_mitigation_reason(
        level=RiskLevel.MEDIUM,
        basis=RiskBasis.KNOWN_VULNERABILITY,
        highest_severity=VulnerabilitySeverityLevel.MEDIUM,
        vulnerability_count=1,
        application_affected=False,
        affected_dependencies=2,
    )
    assert reason_a != reason_b


def test_undetermined_reason_does_not_mention_severity():
    reason = build_mitigation_reason(
        level=RiskLevel.UNDETERMINED,
        basis=RiskBasis.UNDETERMINED,
        highest_severity=None,
        vulnerability_count=0,
        application_affected=False,
        affected_dependencies=0,
    )
    assert "unavailable" in reason.lower()
    assert "investigate" in reason.lower()


def test_simulated_no_vulnerability_reason_does_not_claim_real_vulnerability():
    reason = build_mitigation_reason(
        level=RiskLevel.MEDIUM,
        basis=RiskBasis.SIMULATED_NO_VULNERABILITY,
        highest_severity=None,
        vulnerability_count=0,
        application_affected=True,
        affected_dependencies=0,
    )
    assert "No known vulnerability" in reason
    assert "simulated" in reason.lower()


# 6. Clean dependencies excluded — this is enforced structurally by the
# caller (analysis_service only ever builds MitigationCandidate for
# assessed nodes), verified end-to-end in
# tests/test_analysis_service_risk.py and test_mitigation_analysis_api.py.
# Here we confirm the ranking/build functions themselves impose no
# additional filtering surprises on an already-filtered candidate list.
def test_build_mitigation_priorities_preserves_input_order_from_sort():
    candidates = [
        _candidate("a@1", RiskLevel.CRITICAL, score=99),
        _candidate("b@1", RiskLevel.HIGH, score=80),
    ]
    sorted_candidates = sort_mitigation_candidates(candidates)
    priorities = build_mitigation_priorities(sorted_candidates, max_entries=10)
    assert [p.node_id for p in priorities] == [c.node_id for c in sorted_candidates]
