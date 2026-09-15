import pytest

from app.models.mitigation import RecommendedAction
from app.models.risk import RiskBasis, RiskLevel
from app.services.analysis_service import analyze_project
from tests.conftest import read_fixture, read_json_fixture


def _mock_query_osv(monkeypatch, vulnerable: dict, failing: set = frozenset()):
    from app.vulnerability.osv_client import OsvQueryOutcome

    async def fake_query_osv(client, name, version, ecosystem, base_url=None, timeout=None):
        if (name, version) in failing:
            return OsvQueryOutcome(success=False, error="OSV request timed out: simulated")
        raw_vulns = vulnerable.get((name, version), [])
        return OsvQueryOutcome(success=True, raw_vulns=raw_vulns)

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", fake_query_osv)


@pytest.mark.asyncio
async def test_no_vulnerabilities_means_empty_mitigation_priorities(monkeypatch):
    _mock_query_osv(monkeypatch, vulnerable={})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert result.mitigation_priorities == []


@pytest.mark.asyncio
async def test_vulnerable_package_appears_in_mitigation_priorities(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(monkeypatch, vulnerable={("express", "4.18.2"): single_vuln})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert len(result.mitigation_priorities) == 1
    entry = result.mitigation_priorities[0]
    assert entry.priority == 1
    assert entry.node_id == "express@4.18.2"
    assert entry.name == "express"
    assert entry.vulnerability_count == 1
    assert entry.recommended_action in (
        RecommendedAction.INVESTIGATE_IMMEDIATELY,
        RecommendedAction.PRIORITIZE_REMEDIATION,
        RecommendedAction.PLAN_REMEDIATION,
    )
    assert len(entry.reason) > 0


@pytest.mark.asyncio
async def test_clean_dependencies_never_appear_even_with_other_vulnerable_ones(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(monkeypatch, vulnerable={("express", "4.18.2"): single_vuln})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    priority_ids = {e.node_id for e in result.mitigation_priorities}
    assert "axios@1.6.7" not in priority_ids  # clean, must not appear
    assert "jest@29.7.0" not in priority_ids  # clean, must not appear
    assert "express@4.18.2" in priority_ids


@pytest.mark.asyncio
async def test_undetermined_never_labeled_low_in_mitigation_list(monkeypatch):
    all_keys = {
        ("express", "4.18.2"),
        ("axios", "1.6.7"),
        ("jest", "29.7.0"),
        ("body-parser", "1.20.2"),
        ("follow-redirects", "1.15.5"),
        ("jest-cli", "29.7.0"),
        ("bytes", "3.1.2"),
    }
    _mock_query_osv(monkeypatch, vulnerable={}, failing=all_keys)

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert len(result.mitigation_priorities) == 7
    for entry in result.mitigation_priorities:
        assert entry.risk_level == RiskLevel.UNDETERMINED
        assert entry.risk_level != RiskLevel.LOW
        assert entry.risk_score is None
        assert entry.recommended_action == RecommendedAction.INVESTIGATE_VULNERABILITY_DATA


@pytest.mark.asyncio
async def test_undetermined_ranked_before_known_vulnerability(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(
        monkeypatch,
        vulnerable={("express", "4.18.2"): single_vuln},
        failing={("axios", "1.6.7")},
    )

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    priorities = result.mitigation_priorities
    assert priorities[0].node_id == "axios@1.6.7"
    assert priorities[0].risk_level == RiskLevel.UNDETERMINED
    assert priorities[1].node_id == "express@4.18.2"


@pytest.mark.asyncio
async def test_priority_numbers_sequential_in_real_analysis(monkeypatch):
    multi_vuln = read_json_fixture("osv", "multi_vuln.json")["vulns"]
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(
        monkeypatch,
        vulnerable={
            ("express", "4.18.2"): single_vuln,
            ("body-parser", "1.20.2"): multi_vuln,
        },
    )

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    priorities = [e.priority for e in result.mitigation_priorities]
    assert priorities == list(range(1, len(priorities) + 1))


@pytest.mark.asyncio
async def test_mitigation_priorities_are_known_vulnerability_or_undetermined_only(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(
        monkeypatch,
        vulnerable={("express", "4.18.2"): single_vuln},
        failing={("axios", "1.6.7")},
    )

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    # verify basis at the node level (mitigation_priorities entries don't
    # carry basis directly, but the underlying nodes do)
    for entry in result.mitigation_priorities:
        node = result.graph.get_node(entry.node_id)
        assert node.risk_assessment.basis in (RiskBasis.KNOWN_VULNERABILITY, RiskBasis.UNDETERMINED)


@pytest.mark.asyncio
async def test_top_n_limit_applies_to_analysis_api(monkeypatch):
    from app.core.config import get_settings

    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]

    async def fake_query_osv(client, name, version, ecosystem, base_url=None, timeout=None):
        from app.vulnerability.osv_client import OsvQueryOutcome

        return OsvQueryOutcome(success=True, raw_vulns=single_vuln)

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", fake_query_osv)

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    settings = get_settings()
    assert len(result.mitigation_priorities) <= settings.risk_ranked_list_max_size
