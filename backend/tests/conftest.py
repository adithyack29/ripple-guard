import json
from pathlib import Path

import pytest

from app.services.analysis_store import get_analysis_store
from app.vulnerability.osv_client import OsvQueryOutcome

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def read_fixture(*parts: str) -> bytes:
    return FIXTURES_DIR.joinpath(*parts).read_bytes()


def read_json_fixture(*parts: str):
    return json.loads(read_fixture(*parts))


@pytest.fixture(autouse=True)
def _default_osv_mock(monkeypatch):
    """By default, every test's OSV lookups succeed with zero vulnerabilities
    found — so existing/unrelated tests never make real network calls and
    never need to know about OSV. A test that exercises specific OSV
    behavior (vulnerabilities found, lookup failures, etc.) calls
    `monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", ...)`
    itself after this fixture runs, which takes precedence for that test.
    """

    async def _fake_query_osv(client, name, version, ecosystem, base_url=None, timeout=None):
        return OsvQueryOutcome(success=True, raw_vulns=[])

    monkeypatch.setattr("app.vulnerability.vulnerability_service.query_osv", _fake_query_osv)


@pytest.fixture(autouse=True)
def _clear_analysis_store():
    """The process-wide analysis store (app.services.analysis_store) is a
    singleton shared across the whole test session — clear it before each
    test so one test's stored analyses (and their bounded-size/TTL state)
    never leak into another's assertions.
    """
    get_analysis_store().clear()
    yield
    get_analysis_store().clear()
