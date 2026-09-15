import pytest

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
async def test_vulnerable_direct_dependency_gets_baseline_risk(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]  # HIGH severity
    _mock_query_osv(monkeypatch, vulnerable={("express", "4.18.2"): single_vuln})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )

    express = result.graph.get_node("express@4.18.2")
    assert express.risk_assessment is not None
    assert express.risk_assessment.basis == RiskBasis.KNOWN_VULNERABILITY
    assert express.risk_assessment.score is not None
    assert express.risk_assessment.level != RiskLevel.UNDETERMINED


@pytest.mark.asyncio
async def test_clean_dependency_gets_no_risk_assessment(monkeypatch):
    _mock_query_osv(monkeypatch, vulnerable={})  # nothing vulnerable

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )

    for node in result.graph.nodes:
        if node.relation.value != "root":
            assert node.risk_assessment is None


@pytest.mark.asyncio
async def test_osv_unavailable_nodes_get_undetermined_risk_not_omitted(monkeypatch):
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

    express = result.graph.get_node("express@4.18.2")
    assert express.risk_assessment is not None
    assert express.risk_assessment.basis == RiskBasis.UNDETERMINED
    assert express.risk_assessment.level == RiskLevel.UNDETERMINED
    assert express.risk_assessment.score is None

    assert result.risk_summary.undetermined_count == 7
    assert result.risk_summary.critical_count == 0


@pytest.mark.asyncio
async def test_no_lockfile_nodes_get_undetermined_risk():
    result = await analyze_project(read_fixture("no_lockfile", "package.json"), None)

    non_root = [n for n in result.graph.nodes if n.relation.value != "root"]
    for node in non_root:
        assert node.risk_assessment is not None
        assert node.risk_assessment.basis == RiskBasis.UNDETERMINED
        assert node.risk_assessment.level == RiskLevel.UNDETERMINED

    assert result.risk_summary.undetermined_count == len(non_root)


@pytest.mark.asyncio
async def test_risk_summary_ranking_undetermined_first(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(
        monkeypatch,
        vulnerable={("express", "4.18.2"): single_vuln},
        failing={("axios", "1.6.7")},
    )

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )

    levels_in_order = [entry.level for entry in result.risk_summary.ranked_risks]
    # every UNDETERMINED entry must precede every scored entry
    first_scored_index = next(
        (i for i, lvl in enumerate(levels_in_order) if lvl != RiskLevel.UNDETERMINED), len(levels_in_order)
    )
    assert all(lvl == RiskLevel.UNDETERMINED for lvl in levels_in_order[:first_scored_index])
    assert all(lvl != RiskLevel.UNDETERMINED for lvl in levels_in_order[first_scored_index:])

    # scored entries are sorted descending by score
    scored = [e.score for e in result.risk_summary.ranked_risks if e.score is not None]
    assert scored == sorted(scored, reverse=True)


@pytest.mark.asyncio
async def test_risk_summary_highest_score_matches_top_entry(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    multi_vuln = read_json_fixture("osv", "multi_vuln.json")["vulns"]  # contains a CRITICAL
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

    assert result.risk_summary.highest_risk_score is not None
    assert result.risk_summary.highest_risk_level is not None
    scored = [e.score for e in result.risk_summary.ranked_risks if e.score is not None]
    assert result.risk_summary.highest_risk_score == max(scored)


@pytest.mark.asyncio
async def test_root_node_never_gets_risk_assessment(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(monkeypatch, vulnerable={("express", "4.18.2"): single_vuln})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    root = result.graph.get_node("my-app")
    assert root.risk_assessment is None
