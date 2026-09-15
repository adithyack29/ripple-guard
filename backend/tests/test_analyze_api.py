from fastapi.testclient import TestClient

from app.main import app
from app.vulnerability.osv_client import OsvQueryOutcome
from tests.conftest import read_fixture, read_json_fixture

client = TestClient(app)


def _upload(package_json: bytes, package_lock_json: bytes = None):
    files = {"package_json": ("package.json", package_json, "application/json")}
    if package_lock_json is not None:
        files["package_lock_json"] = ("package-lock.json", package_lock_json, "application/json")
    return client.post("/api/analyze", files=files)


def test_analyze_with_lockfile_returns_full_graph():
    response = _upload(
        read_fixture("simple", "package.json"),
        read_fixture("simple", "package-lock.json"),
    )
    assert response.status_code == 200
    body = response.json()

    assert body["project"]["name"] == "my-app"
    assert body["ecosystem"] == "npm"
    assert body["resolution_status"] == "lockfile_resolved"
    assert body["statistics"]["total_dependencies"] == 7
    assert body["statistics"]["direct_dependencies"] == 3
    assert body["statistics"]["transitive_dependencies"] == 4
    assert body["statistics"]["max_depth"] == 3

    node_ids = {n["id"] for n in body["nodes"]}
    assert "my-app" in node_ids
    assert "express@4.18.2" in node_ids
    assert "body-parser@1.20.2" in node_ids

    edge_pairs = {(e["source"], e["target"]) for e in body["edges"]}
    assert ("my-app", "express@4.18.2") in edge_pairs
    assert ("express@4.18.2", "body-parser@1.20.2") in edge_pairs


def test_analyze_without_lockfile_returns_direct_only():
    response = _upload(read_fixture("no_lockfile", "package.json"))
    assert response.status_code == 200
    body = response.json()

    assert body["resolution_status"] == "direct_dependencies_only"
    assert body["statistics"]["transitive_dependencies"] == 0
    relations = {n["relation"] for n in body["nodes"] if n["relation"] != "root"}
    assert relations == {"direct"}


def test_analyze_duplicate_versions_stay_distinct_via_api():
    response = _upload(
        read_fixture("duplicate_versions", "package.json"),
        read_fixture("duplicate_versions", "package-lock.json"),
    )
    assert response.status_code == 200
    body = response.json()
    lodash_nodes = [n for n in body["nodes"] if n["name"] == "lodash"]
    assert len(lodash_nodes) == 2
    assert {n["version"] for n in lodash_nodes} == {"4.17.21", "4.17.20"}


def test_analyze_invalid_package_json_returns_422():
    response = _upload(read_fixture("invalid", "package.json"))
    assert response.status_code == 422
    body = response.json()
    assert body["detail"]["error_type"] == "ManifestParseError"


def test_analyze_unsupported_lockfile_version_returns_422():
    response = _upload(
        read_fixture("simple", "package.json"),
        b'{"lockfileVersion": 1, "packages": {}}',
    )
    assert response.status_code == 422
    body = response.json()
    assert body["detail"]["error_type"] == "UnsupportedLockfileVersionError"


def test_analyze_missing_package_json_returns_422():
    response = client.post("/api/analyze", files={})
    assert response.status_code == 422


def test_health_still_works():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_default_mock_returns_empty_vulnerabilities():
    """Every other test in this file relies on the autouse OSV mock in
    conftest.py (zero vulnerabilities, all lookups succeed) — this test
    asserts that behavior explicitly at the API contract level.
    """
    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()

    assert body["vulnerability_summary"]["status"] == "ok"
    assert body["vulnerability_summary"]["vulnerable_dependencies"] == 0
    assert body["vulnerability_summary"]["total_vulnerabilities"] == 0
    for node in body["nodes"]:
        assert node["vulnerabilities"] == []
        expected_status = "not_applicable" if node["relation"] == "root" else "ok"
        assert node["vulnerability_lookup_status"] == expected_status


def test_analyze_reports_vulnerable_package_via_api(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]

    async def fake_query_osv(client, name, version, ecosystem, base_url=None, timeout=None):
        if (name, version) == ("express", "4.18.2"):
            return OsvQueryOutcome(success=True, raw_vulns=single_vuln)
        return OsvQueryOutcome(success=True, raw_vulns=[])

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", fake_query_osv)

    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()

    express = next(n for n in body["nodes"] if n["id"] == "express@4.18.2")
    assert len(express["vulnerabilities"]) == 1
    vuln = express["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-p6mc-m468-83gw"
    assert vuln["source"] == "OSV"
    assert vuln["severity"] == "HIGH"
    assert vuln["aliases"] == ["CVE-2020-8203"]
    assert len(vuln["references"]) == 2

    assert body["vulnerability_summary"]["vulnerable_dependencies"] == 1
    assert body["vulnerability_summary"]["direct_vulnerable_dependencies"] == 1
    assert body["vulnerability_summary"]["total_vulnerabilities"] == 1
    assert body["vulnerability_summary"]["severity_breakdown"] == {"HIGH": 1}


def test_analyze_osv_unavailable_via_api_is_distinct_from_clean(monkeypatch):
    async def always_fails(client, name, version, ecosystem, base_url=None, timeout=None):
        return OsvQueryOutcome(success=False, error="OSV request timed out: simulated")

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", always_fails)

    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()

    assert body["vulnerability_summary"]["status"] == "unavailable"
    for node in body["nodes"]:
        if node["relation"] != "root":
            assert node["vulnerability_lookup_status"] == "unavailable"
            assert node["vulnerabilities"] == []  # empty, but status says "unavailable" not "ok"
    assert any("OSV vulnerability lookup failed" in w for w in body["warnings"])


def test_analyze_no_lockfile_nodes_not_checked_via_api():
    response = _upload(read_fixture("no_lockfile", "package.json"))
    assert response.status_code == 200
    body = response.json()

    for node in body["nodes"]:
        if node["relation"] != "root":
            assert node["vulnerability_lookup_status"] == "not_checked"
    assert body["vulnerability_summary"]["nodes_skipped_no_version"] == 4


def test_analyze_risk_summary_present_and_clean_by_default():
    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()

    assert "risk_summary" in body
    assert body["risk_summary"]["critical_count"] == 0
    assert body["risk_summary"]["undetermined_count"] == 0
    assert body["risk_summary"]["highest_risk_score"] is None
    assert body["risk_summary"]["ranked_risks"] == []
    for node in body["nodes"]:
        assert node["risk_assessment"] is None


def test_analyze_vulnerable_node_carries_risk_assessment_via_api(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]

    async def fake_query_osv(client, name, version, ecosystem, base_url=None, timeout=None):
        if (name, version) == ("express", "4.18.2"):
            return OsvQueryOutcome(success=True, raw_vulns=single_vuln)
        return OsvQueryOutcome(success=True, raw_vulns=[])

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", fake_query_osv)

    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()

    express = next(n for n in body["nodes"] if n["id"] == "express@4.18.2")
    risk = express["risk_assessment"]
    assert risk is not None
    assert risk["basis"] == "known_vulnerability"
    assert risk["level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert isinstance(risk["score"], int)
    assert risk["breakdown"]["severity"] == 80  # HIGH
    assert risk["highest_severity"] == "HIGH"
    assert len(risk["explanation"]) > 0

    assert body["risk_summary"]["ranked_risks"]
    entry = next(e for e in body["risk_summary"]["ranked_risks"] if e["node_id"] == "express@4.18.2")
    assert entry["score"] == risk["score"]
    assert entry["level"] == risk["level"]
    assert body["risk_summary"]["highest_risk_score"] == risk["score"]


def test_analyze_undetermined_risk_via_api_is_never_labeled_low(monkeypatch):
    async def always_fails(client, name, version, ecosystem, base_url=None, timeout=None):
        return OsvQueryOutcome(success=False, error="OSV request timed out: simulated")

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", always_fails)

    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()

    for node in body["nodes"]:
        if node["relation"] == "root":
            assert node["risk_assessment"] is None
            continue
        risk = node["risk_assessment"]
        assert risk is not None
        assert risk["level"] == "UNDETERMINED"
        assert risk["level"] != "LOW"
        assert risk["score"] is None

    assert body["risk_summary"]["undetermined_count"] == 7
    # every ranked entry should be UNDETERMINED and listed (not silently dropped)
    assert len(body["risk_summary"]["ranked_risks"]) == 7
    assert all(e["level"] == "UNDETERMINED" for e in body["risk_summary"]["ranked_risks"])


def test_analyze_mitigation_priorities_empty_when_clean():
    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mitigation_priorities"] == []


def test_analyze_mitigation_priorities_via_api(monkeypatch):
    single_vuln = read_json_fixture("osv", "single_vuln.json")["vulns"]

    async def fake_query_osv(client, name, version, ecosystem, base_url=None, timeout=None):
        if (name, version) == ("express", "4.18.2"):
            return OsvQueryOutcome(success=True, raw_vulns=single_vuln)
        return OsvQueryOutcome(success=True, raw_vulns=[])

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", fake_query_osv)

    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()

    priorities = body["mitigation_priorities"]
    assert len(priorities) == 1
    entry = priorities[0]
    assert entry["priority"] == 1
    assert entry["node_id"] == "express@4.18.2"
    assert entry["name"] == "express"
    assert entry["version"] == "4.18.2"
    assert entry["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert isinstance(entry["risk_score"], int)
    assert entry["vulnerability_count"] == 1
    assert entry["recommended_action"] in (
        "investigate_immediately",
        "prioritize_remediation",
        "plan_remediation",
        "monitor",
    )
    assert len(entry["reason"]) > 0

    # clean deps must never appear
    priority_ids = {e["node_id"] for e in priorities}
    assert "axios@1.6.7" not in priority_ids
    assert "jest@29.7.0" not in priority_ids


def test_analyze_mitigation_priorities_undetermined_not_low_via_api(monkeypatch):
    async def always_fails(client, name, version, ecosystem, base_url=None, timeout=None):
        return OsvQueryOutcome(success=False, error="simulated")

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", always_fails)

    response = _upload(
        read_fixture("simple", "package.json"), read_fixture("simple", "package-lock.json")
    )
    assert response.status_code == 200
    body = response.json()

    priorities = body["mitigation_priorities"]
    assert len(priorities) == 7
    for entry in priorities:
        assert entry["risk_level"] == "UNDETERMINED"
        assert entry["risk_score"] is None
        assert entry["recommended_action"] == "investigate_vulnerability_data"
