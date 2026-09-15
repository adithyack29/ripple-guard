import json

import httpx
import pytest

from app.vulnerability.osv_client import query_osv
from tests.conftest import read_json_fixture


def _client_with_handler(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_query_osv_success_with_vulns():
    body = read_json_fixture("osv", "single_vuln.json")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    async with _client_with_handler(handler) as client:
        outcome = await query_osv(client, "lodash", "4.17.15", "npm")

    assert outcome.success is True
    assert outcome.error is None
    assert len(outcome.raw_vulns) == 1
    assert outcome.raw_vulns[0]["id"] == "GHSA-p6mc-m468-83gw"


@pytest.mark.asyncio
async def test_query_osv_success_no_vulns():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    async with _client_with_handler(handler) as client:
        outcome = await query_osv(client, "left-pad", "1.3.0", "npm")

    assert outcome.success is True
    assert outcome.raw_vulns == []


@pytest.mark.asyncio
async def test_query_osv_sends_name_version_ecosystem():
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json={})

    async with _client_with_handler(handler) as client:
        await query_osv(client, "axios", "1.6.7", "npm")

    assert captured["payload"] == {"version": "1.6.7", "package": {"name": "axios", "ecosystem": "npm"}}


@pytest.mark.asyncio
async def test_query_osv_timeout():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("simulated timeout")

    async with _client_with_handler(handler) as client:
        outcome = await query_osv(client, "pkg", "1.0.0", "npm")

    assert outcome.success is False
    assert "timed out" in outcome.error


@pytest.mark.asyncio
async def test_query_osv_connection_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated connection failure")

    async with _client_with_handler(handler) as client:
        outcome = await query_osv(client, "pkg", "1.0.0", "npm")

    assert outcome.success is False
    assert "OSV request failed" in outcome.error


@pytest.mark.asyncio
async def test_query_osv_http_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal server error")

    async with _client_with_handler(handler) as client:
        outcome = await query_osv(client, "pkg", "1.0.0", "npm")

    assert outcome.success is False
    assert "500" in outcome.error


@pytest.mark.asyncio
async def test_query_osv_malformed_json():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not valid json")

    async with _client_with_handler(handler) as client:
        outcome = await query_osv(client, "pkg", "1.0.0", "npm")

    assert outcome.success is False
    assert "malformed" in outcome.error.lower()


@pytest.mark.asyncio
async def test_query_osv_vulns_field_wrong_type():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": "not-a-list"})

    async with _client_with_handler(handler) as client:
        outcome = await query_osv(client, "pkg", "1.0.0", "npm")

    assert outcome.success is False
