from app.models.vulnerability import VulnerabilitySeverityLevel
from app.vulnerability.osv_adapter import parse_osv_vulnerability
from tests.conftest import read_json_fixture


def test_parses_single_vulnerability_fields():
    raw = read_json_fixture("osv", "single_vuln.json")["vulns"][0]
    vuln = parse_osv_vulnerability(raw, "lodash", "4.17.15")

    assert vuln.id == "GHSA-p6mc-m468-83gw"
    assert vuln.source == "OSV"
    assert vuln.summary == "Prototype Pollution in lodash"
    assert vuln.severity == VulnerabilitySeverityLevel.HIGH
    assert vuln.aliases == ["CVE-2020-8203"]
    assert vuln.affected_package == "lodash"
    assert vuln.affected_version == "4.17.15"
    assert vuln.published == "2020-07-15T17:54:00Z"
    assert vuln.modified == "2023-11-08T04:12:30Z"
    assert len(vuln.references) == 2
    assert vuln.references[0].url == "https://github.com/advisories/GHSA-p6mc-m468-83gw"
    assert vuln.references[0].type == "ADVISORY"


def test_moderate_maps_to_medium():
    raw = {"id": "GHSA-x", "database_specific": {"severity": "MODERATE"}}
    vuln = parse_osv_vulnerability(raw, "pkg", "1.0.0")
    assert vuln.severity == VulnerabilitySeverityLevel.MEDIUM


def test_missing_severity_returns_unknown():
    raw = read_json_fixture("osv", "missing_severity.json")["vulns"][0]
    vuln = parse_osv_vulnerability(raw, "example-pkg", "1.0.0")
    assert vuln.severity == VulnerabilitySeverityLevel.UNKNOWN
    assert vuln.severity_vector is None


def test_cvss_vector_preserved_without_inventing_a_label():
    raw = {
        "id": "GHSA-y",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }
    vuln = parse_osv_vulnerability(raw, "pkg", "1.0.0")
    assert vuln.severity == VulnerabilitySeverityLevel.UNKNOWN
    assert vuln.severity_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_severity_from_per_affected_database_specific():
    raw = {
        "id": "GHSA-z",
        "affected": [
            {"package": {"name": "pkg", "ecosystem": "npm"}, "database_specific": {"severity": "CRITICAL"}}
        ],
    }
    vuln = parse_osv_vulnerability(raw, "pkg", "1.0.0")
    assert vuln.severity == VulnerabilitySeverityLevel.CRITICAL


def test_multiple_vulnerabilities_parsed_independently():
    vulns_raw = read_json_fixture("osv", "multi_vuln.json")["vulns"]
    parsed = [parse_osv_vulnerability(v, "example-pkg", "2.0.0") for v in vulns_raw]

    assert len(parsed) == 2
    assert parsed[0].id == "GHSA-jf85-cpcp-j695"
    assert parsed[0].severity == VulnerabilitySeverityLevel.CRITICAL
    assert parsed[0].aliases == ["CVE-2021-23337"]
    assert parsed[1].id == "GHSA-29mw-wpgm-hmr9"
    assert parsed[1].severity == VulnerabilitySeverityLevel.LOW


def test_summary_falls_back_to_truncated_details():
    raw = {"id": "GHSA-a", "details": "x" * 500}
    vuln = parse_osv_vulnerability(raw, "pkg", "1.0.0")
    assert vuln.summary is not None
    assert len(vuln.summary) <= 300
    assert vuln.summary.endswith("...")


def test_references_are_capped():
    raw = {
        "id": "GHSA-b",
        "references": [{"type": "WEB", "url": f"https://example.com/{i}"} for i in range(10)],
    }
    vuln = parse_osv_vulnerability(raw, "pkg", "1.0.0")
    assert len(vuln.references) == 5


def test_missing_id_falls_back_to_unknown():
    vuln = parse_osv_vulnerability({}, "pkg", "1.0.0")
    assert vuln.id == "UNKNOWN"
    assert vuln.severity == VulnerabilitySeverityLevel.UNKNOWN
