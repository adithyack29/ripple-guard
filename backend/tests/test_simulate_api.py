from fastapi.testclient import TestClient

from app.main import app
from app.services.analysis_store import get_analysis_store
from tests.conftest import read_fixture
from tests.graph_builders import build_test_analysis_result, build_test_graph

client = TestClient(app)


def _upload_simple():
    files = {
        "package_json": ("package.json", read_fixture("simple", "package.json"), "application/json"),
        "package_lock_json": (
            "package-lock.json",
            read_fixture("simple", "package-lock.json"),
            "application/json",
        ),
    }
    return client.post("/api/analyze", files=files)


def test_analyze_response_includes_analysis_id():
    response = _upload_simple()
    assert response.status_code == 200
    body = response.json()
    assert "analysis_id" in body
    assert isinstance(body["analysis_id"], str)
    assert len(body["analysis_id"]) > 0


def test_full_flow_analyze_then_simulate():
    analyze_body = _upload_simple().json()
    analysis_id = analyze_body["analysis_id"]

    # body-parser@1.20.2 is a transitive dependency of express in the
    # `simple` fixture (express -> body-parser -> bytes).
    response = client.post(
        "/api/simulate", json={"analysis_id": analysis_id, "node_id": "body-parser@1.20.2"}
    )
    assert response.status_code == 200
    body = response.json()

    assert body["analysis_id"] == analysis_id
    assert body["compromised_node"]["node_id"] == "body-parser@1.20.2"
    assert body["compromised_node"]["name"] == "body-parser"
    assert body["compromised_node"]["version"] == "1.20.2"

    affected_ids = {n["node_id"] for n in body["affected_nodes"]}
    assert "express@4.18.2" in affected_ids  # direct dependent
    assert "my-app" in affected_ids  # indirect, via express
    assert "bytes@3.1.2" not in affected_ids  # body-parser's own dependency — wrong direction

    express_entry = next(n for n in body["affected_nodes"] if n["node_id"] == "express@4.18.2")
    assert express_entry["impact_type"] == "direct"
    assert express_entry["depth"] == 1

    app_entry = next(n for n in body["affected_nodes"] if n["node_id"] == "my-app")
    assert app_entry["impact_type"] == "indirect"

    assert body["application_impact"]["affected"] is True
    assert body["blast_radius"]["affected_applications"] == 1

    risk = body["risk_assessment"]
    assert risk is not None
    assert risk["basis"] == "simulated_no_vulnerability"  # body-parser has no known OSV vuln here
    assert risk["breakdown"]["severity"] == 0
    assert risk["level"] not in ("CRITICAL", "HIGH")


def test_simulate_unknown_analysis_id_returns_404():
    response = client.post("/api/simulate", json={"analysis_id": "does-not-exist", "node_id": "x@1.0.0"})
    assert response.status_code == 404
    body = response.json()
    assert body["detail"]["error_type"] == "AnalysisNotFoundError"


def test_simulate_unknown_node_id_returns_422():
    analyze_body = _upload_simple().json()
    response = client.post(
        "/api/simulate", json={"analysis_id": analyze_body["analysis_id"], "node_id": "ghost@9.9.9"}
    )
    assert response.status_code == 422
    body = response.json()
    assert body["detail"]["error_type"] == "InvalidSimulationNodeError"


def test_simulate_root_node_returns_422():
    analyze_body = _upload_simple().json()
    response = client.post(
        "/api/simulate", json={"analysis_id": analyze_body["analysis_id"], "node_id": "my-app"}
    )
    assert response.status_code == 422
    body = response.json()
    assert body["detail"]["error_type"] == "InvalidSimulationNodeError"


def test_simulate_missing_request_fields_returns_422():
    response = client.post("/api/simulate", json={"analysis_id": "abc"})
    assert response.status_code == 422


def test_simulate_no_lockfile_node_rejected():
    response = client.post(
        "/api/analyze",
        files={
            "package_json": (
                "package.json",
                read_fixture("no_lockfile", "package.json"),
                "application/json",
            )
        },
    )
    analysis_id = response.json()["analysis_id"]

    sim_response = client.post("/api/simulate", json={"analysis_id": analysis_id, "node_id": "lodash"})
    assert sim_response.status_code == 422
    assert sim_response.json()["detail"]["error_type"] == "InvalidSimulationNodeError"


def test_diamond_shape_via_api_reports_multiple_paths():
    graph = build_test_graph([("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")], root="A")
    analysis_id = get_analysis_store().put(build_test_analysis_result(graph))

    response = client.post("/api/simulate", json={"analysis_id": analysis_id, "node_id": "D@1.0.0"})
    assert response.status_code == 200
    body = response.json()

    assert body["blast_radius"]["propagation_path_count"] == 2
    assert len(body["propagation_paths"]) == 2
    assert sorted(body["propagation_paths"]) == sorted(
        [["D@1.0.0", "B@1.0.0", "A"], ["D@1.0.0", "C@1.0.0", "A"]]
    )


def test_response_is_json_serializable_and_well_formed():
    analyze_body = _upload_simple().json()
    response = client.post(
        "/api/simulate",
        json={"analysis_id": analyze_body["analysis_id"], "node_id": "follow-redirects@1.15.5"},
    )
    assert response.status_code == 200
    # response.json() already proves this parsed as JSON; assert the
    # documented top-level shape is present.
    body = response.json()
    for key in (
        "analysis_id",
        "compromised_node",
        "blast_radius",
        "affected_nodes",
        "propagation_paths",
        "application_impact",
        "risk_assessment",
        "mitigation",
        "warnings",
    ):
        assert key in body
    assert "mitigation_priorities" not in body  # project-wide ranking belongs to /api/analyze only


def test_simulate_vulnerable_node_risk_via_api(monkeypatch):
    from app.vulnerability.osv_client import OsvQueryOutcome

    async def fake_query_osv(client, name, version, ecosystem, base_url=None, timeout=None):
        if (name, version) == ("body-parser", "1.20.2"):
            from tests.conftest import read_json_fixture

            return OsvQueryOutcome(
                success=True, raw_vulns=read_json_fixture("osv", "single_vuln.json")["vulns"]
            )
        return OsvQueryOutcome(success=True, raw_vulns=[])

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", fake_query_osv)

    analyze_body = _upload_simple().json()
    response = client.post(
        "/api/simulate",
        json={"analysis_id": analyze_body["analysis_id"], "node_id": "body-parser@1.20.2"},
    )
    assert response.status_code == 200
    body = response.json()

    risk = body["risk_assessment"]
    assert risk["basis"] == "known_vulnerability"
    assert risk["highest_severity"] == "HIGH"
    assert risk["score"] is not None
    assert risk["breakdown"]["severity"] == 80

    mitigation = body["mitigation"]
    assert mitigation["recommended_action"] in (
        "investigate_immediately",
        "prioritize_remediation",
        "plan_remediation",
        "monitor",
    )
    assert "High" in mitigation["reason"]
    assert len(mitigation["reason"]) > 0


def test_simulate_no_vulnerability_mitigation_does_not_claim_real_vulnerability():
    analyze_body = _upload_simple().json()
    response = client.post(
        "/api/simulate",
        json={"analysis_id": analyze_body["analysis_id"], "node_id": "body-parser@1.20.2"},
    )
    assert response.status_code == 200
    body = response.json()

    assert body["risk_assessment"]["basis"] == "simulated_no_vulnerability"
    assert "No known vulnerability" in body["mitigation"]["reason"]
    assert "simulated" in body["mitigation"]["reason"].lower()


def test_simulate_osv_unavailable_node_risk_is_undetermined_via_api(monkeypatch):
    from app.vulnerability.osv_client import OsvQueryOutcome

    async def always_fails(client, name, version, ecosystem, base_url=None, timeout=None):
        return OsvQueryOutcome(success=False, error="simulated failure")

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", always_fails)

    analyze_body = _upload_simple().json()
    response = client.post(
        "/api/simulate",
        json={"analysis_id": analyze_body["analysis_id"], "node_id": "body-parser@1.20.2"},
    )
    assert response.status_code == 200
    body = response.json()

    risk = body["risk_assessment"]
    assert risk["basis"] == "undetermined"
    assert risk["level"] == "UNDETERMINED"
    assert risk["score"] is None

    assert body["mitigation"]["recommended_action"] == "investigate_vulnerability_data"
    assert "unavailable" in body["mitigation"]["reason"].lower()


def test_health_and_analyze_still_work_after_phase3():
    assert client.get("/api/health").status_code == 200
    assert _upload_simple().status_code == 200
