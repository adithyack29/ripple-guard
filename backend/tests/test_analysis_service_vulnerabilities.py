import pytest

from app.models.vulnerability import VulnerabilityEnrichmentStatus, VulnerabilityLookupStatus
from app.vulnerability.osv_client import OsvQueryOutcome
from app.services.analysis_service import analyze_project
from tests.conftest import read_fixture, read_json_fixture


def _mock_query_osv(monkeypatch, vulnerable: dict, failing: set = frozenset()):
    """vulnerable: {(name, version): raw_vulns_list}. failing: {(name, version)}."""

    async def fake_query_osv(client, name, version, ecosystem, base_url=None, timeout=None):
        if (name, version) in failing:
            return OsvQueryOutcome(success=False, error="OSV request timed out: simulated")
        raw_vulns = vulnerable.get((name, version), [])
        return OsvQueryOutcome(success=True, raw_vulns=raw_vulns)

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", fake_query_osv)


@pytest.mark.asyncio
async def test_vulnerable_direct_dependency_is_enriched(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(monkeypatch, vulnerable={("express", "4.18.2"): single_vuln})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )

    express = result.graph.get_node("express@4.18.2")
    assert express is not None
    assert len(express.vulnerabilities) == 1
    assert express.vulnerabilities[0].id == "GHSA-p6mc-m468-83gw"
    assert express.vulnerability_lookup_status == VulnerabilityLookupStatus.OK

    assert result.vulnerability_summary.direct_vulnerable_dependencies == 1
    assert result.vulnerability_summary.transitive_vulnerable_dependencies == 0
    assert result.vulnerability_summary.total_vulnerabilities == 1
    assert result.vulnerability_summary.status == VulnerabilityEnrichmentStatus.OK


@pytest.mark.asyncio
async def test_vulnerable_transitive_dependency_is_enriched(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    _mock_query_osv(monkeypatch, vulnerable={("body-parser", "1.20.2"): single_vuln})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )

    body_parser = result.graph.get_node("body-parser@1.20.2")
    assert len(body_parser.vulnerabilities) == 1
    assert result.vulnerability_summary.transitive_vulnerable_dependencies == 1
    assert result.vulnerability_summary.direct_vulnerable_dependencies == 0


@pytest.mark.asyncio
async def test_mixed_vulnerable_and_clean_dependencies(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]
    multi_vuln = read_json_fixture("osv", "multi_vuln.json")["vulns"]
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

    by_id = {n.id: n for n in result.graph.nodes}
    assert len(by_id["express@4.18.2"].vulnerabilities) == 1
    assert len(by_id["body-parser@1.20.2"].vulnerabilities) == 2
    assert by_id["axios@1.6.7"].vulnerabilities == []
    assert by_id["axios@1.6.7"].vulnerability_lookup_status == VulnerabilityLookupStatus.OK

    assert result.vulnerability_summary.vulnerable_dependencies == 2
    assert result.vulnerability_summary.total_vulnerabilities == 3
    assert result.vulnerability_summary.severity_breakdown == {"HIGH": 1, "CRITICAL": 1, "LOW": 1}


@pytest.mark.asyncio
async def test_no_vulnerabilities_found_reports_ok_not_missing(monkeypatch):
    _mock_query_osv(monkeypatch, vulnerable={})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )

    assert result.vulnerability_summary.status == VulnerabilityEnrichmentStatus.OK
    assert result.vulnerability_summary.vulnerable_dependencies == 0
    for node in result.graph.nodes:
        if node.relation.value != "root":
            assert node.vulnerabilities == []
            assert node.vulnerability_lookup_status == VulnerabilityLookupStatus.OK


@pytest.mark.asyncio
async def test_osv_unavailable_is_not_reported_as_zero_vulnerabilities(monkeypatch):
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

    assert result.vulnerability_summary.status == VulnerabilityEnrichmentStatus.UNAVAILABLE
    assert result.vulnerability_summary.nodes_failed == 7
    assert result.vulnerability_summary.nodes_checked == 0

    express = result.graph.get_node("express@4.18.2")
    assert express.vulnerability_lookup_status == VulnerabilityLookupStatus.UNAVAILABLE
    assert express.vulnerabilities == []  # empty, but NOT because it was confirmed clean

    assert any("OSV vulnerability lookup failed" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_partial_osv_failure_reports_partial_status(monkeypatch):
    _mock_query_osv(monkeypatch, vulnerable={}, failing={("express", "4.18.2")})

    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )

    assert result.vulnerability_summary.status == VulnerabilityEnrichmentStatus.PARTIAL
    assert result.vulnerability_summary.nodes_failed == 1
    assert result.vulnerability_summary.nodes_checked == 6

    express = result.graph.get_node("express@4.18.2")
    assert express.vulnerability_lookup_status == VulnerabilityLookupStatus.UNAVAILABLE
    axios = result.graph.get_node("axios@1.6.7")
    assert axios.vulnerability_lookup_status == VulnerabilityLookupStatus.OK


@pytest.mark.asyncio
async def test_no_lockfile_nodes_are_not_checked_not_silently_clean():
    result = await analyze_project(read_fixture("no_lockfile", "package.json"), None)

    non_root = [n for n in result.graph.nodes if n.relation.value != "root"]
    assert len(non_root) == 4
    for node in non_root:
        assert node.vulnerability_lookup_status == VulnerabilityLookupStatus.NOT_CHECKED
        assert node.vulnerabilities == []

    assert result.vulnerability_summary.nodes_skipped_no_version == 4
    assert result.vulnerability_summary.nodes_checked == 0
    assert result.vulnerability_summary.status == VulnerabilityEnrichmentStatus.OK
    assert any("no lockfile supplied" in w.lower() for w in result.warnings)


@pytest.mark.asyncio
async def test_root_node_is_not_applicable():
    result = await analyze_project(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    root = result.graph.get_node("my-app")
    assert root.vulnerability_lookup_status == VulnerabilityLookupStatus.NOT_APPLICABLE
    assert root.vulnerabilities == []
