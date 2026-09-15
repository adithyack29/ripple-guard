from app.models.risk import RiskBasis, RiskLevel
from app.models.vulnerability import Vulnerability, VulnerabilitySeverityLevel
from app.services.analysis_store import AnalysisStore
from app.simulation.simulation_service import simulate_compromise
from tests.graph_builders import build_test_analysis_result, build_test_graph


def _store_with(graph):
    store = AnalysisStore(max_size=10, ttl_seconds=3600)
    analysis_id = store.put(build_test_analysis_result(graph))
    return store, analysis_id


def test_simulation_of_known_vulnerable_node_produces_known_vulnerability_risk():
    graph = build_test_graph([("my-app", "A"), ("A", "B"), ("B", "C")])
    node = graph.get_node("C@1.0.0")
    node.vulnerabilities = [Vulnerability(id="GHSA-x", source="OSV", severity=VulnerabilitySeverityLevel.CRITICAL)]
    from app.models.vulnerability import VulnerabilityLookupStatus

    node.vulnerability_lookup_status = VulnerabilityLookupStatus.OK

    store, analysis_id = _store_with(graph)
    result = simulate_compromise(analysis_id, "C@1.0.0", store)

    assert result.risk_assessment.basis == RiskBasis.KNOWN_VULNERABILITY
    assert result.risk_assessment.highest_severity == VulnerabilitySeverityLevel.CRITICAL
    assert result.risk_assessment.score is not None
    # application is reached at depth 3 in this linear chain -> substantial impact
    assert result.risk_assessment.level in (RiskLevel.CRITICAL, RiskLevel.HIGH)


def test_simulation_of_clean_node_produces_simulated_no_vulnerability_risk():
    from app.models.vulnerability import VulnerabilityLookupStatus

    graph = build_test_graph([("my-app", "A"), ("A", "B")])
    node = graph.get_node("B@1.0.0")
    node.vulnerabilities = []
    node.vulnerability_lookup_status = VulnerabilityLookupStatus.OK

    store, analysis_id = _store_with(graph)
    result = simulate_compromise(analysis_id, "B@1.0.0", store)

    assert result.risk_assessment.basis == RiskBasis.SIMULATED_NO_VULNERABILITY
    assert result.risk_assessment.breakdown.severity == 0
    assert result.risk_assessment.highest_severity is None
    # capped: can never reach HIGH/CRITICAL from structure alone
    assert result.risk_assessment.level not in (RiskLevel.CRITICAL, RiskLevel.HIGH)


def test_simulation_of_lookup_unavailable_node_is_undetermined():
    from app.models.vulnerability import VulnerabilityLookupStatus

    graph = build_test_graph([("my-app", "A"), ("A", "B")])
    node = graph.get_node("B@1.0.0")
    node.vulnerabilities = []
    node.vulnerability_lookup_status = VulnerabilityLookupStatus.UNAVAILABLE

    store, analysis_id = _store_with(graph)
    result = simulate_compromise(analysis_id, "B@1.0.0", store)

    assert result.risk_assessment.basis == RiskBasis.UNDETERMINED
    assert result.risk_assessment.level == RiskLevel.UNDETERMINED
    assert result.risk_assessment.score is None


def test_simulation_risk_uses_same_impact_as_blast_radius():
    from app.models.vulnerability import VulnerabilityLookupStatus

    graph = build_test_graph([("my-app", "A"), ("A", "B"), ("B", "C")])
    node = graph.get_node("C@1.0.0")
    node.vulnerabilities = [Vulnerability(id="GHSA-x", source="OSV", severity=VulnerabilitySeverityLevel.HIGH)]
    node.vulnerability_lookup_status = VulnerabilityLookupStatus.OK

    store, analysis_id = _store_with(graph)
    result = simulate_compromise(analysis_id, "C@1.0.0", store)

    # risk breakdown's reachability/blast_radius/propagation must be
    # derivable from the SAME blast_radius/application_impact the
    # response already reports — not an independently re-derived figure.
    from app.risk.scoring import (
        blast_radius_score as bscore,
        propagation_score as pscore,
        reachability_score as rscore,
    )

    expected_reachability = rscore(
        result.application_impact.affected, result.blast_radius.affected_dependencies
    )
    expected_blast = bscore(result.blast_radius.affected_nodes, result.blast_radius.propagation_path_count)
    expected_propagation = pscore(result.blast_radius.max_propagation_depth)

    assert result.risk_assessment.breakdown.reachability == expected_reachability
    assert result.risk_assessment.breakdown.blast_radius == expected_blast
    assert result.risk_assessment.breakdown.propagation == expected_propagation


def test_simulation_risk_structural_importance_uses_direct_dependents():
    from app.models.vulnerability import VulnerabilityLookupStatus

    # D has two direct dependents: B and C (diamond).
    graph = build_test_graph([("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")], root="A")
    node = graph.get_node("D@1.0.0")
    node.vulnerabilities = []
    node.vulnerability_lookup_status = VulnerabilityLookupStatus.OK

    store, analysis_id = _store_with(graph)
    result = simulate_compromise(analysis_id, "D@1.0.0", store)

    assert result.risk_assessment.breakdown.structural_importance == 50  # 2 dependents * 25
    assert "Structurally significant" in result.risk_assessment.explanation
