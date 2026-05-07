"""Tests for mcp-opnsense tools. All HTTP calls are mocked."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


# ---------------------------------------------------------------------------
# Auth layer tests
# ---------------------------------------------------------------------------

async def test_request_missing_credentials_raises(monkeypatch):
    """_request() raises ValueError when API credentials are not set."""
    monkeypatch.delenv("OPNSENSE_API_KEY", raising=False)
    monkeypatch.delenv("OPNSENSE_API_SECRET", raising=False)

    import mcp_opnsense.server as srv
    with pytest.raises(ValueError, match="OPNSENSE_API_KEY"):
        await srv._request("GET", "/core/system/status")


async def test_request_uses_basic_auth(monkeypatch):
    """_request() sends API key + secret as HTTP Basic credentials."""
    monkeypatch.setenv("OPNSENSE_API_KEY", "mykey")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "mysecret")
    monkeypatch.setenv("OPNSENSE_HOST", "https://10.0.0.1")

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("mcp_opnsense.server.httpx.AsyncClient", return_value=mock_client):
        import mcp_opnsense.server as srv
        resp = await srv._request("GET", "/core/system/status")

    assert resp.status_code == 200
    mock_client.request.assert_called_once_with(
        "GET",
        "https://10.0.0.1/api/core/system/status",
        auth=("mykey", "mysecret"),
    )


async def test_request_verify_ssl_false_by_default(monkeypatch):
    """_request() passes verify=False to AsyncClient by default."""
    monkeypatch.setenv("OPNSENSE_API_KEY", "mykey")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "mysecret")
    monkeypatch.delenv("OPNSENSE_VERIFY_SSL", raising=False)

    captured = {}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.request = AsyncMock(return_value=mock_resp)

    def capture(**kwargs):
        captured.update(kwargs)
        return mock_client

    with patch("mcp_opnsense.server.httpx.AsyncClient", side_effect=capture):
        import mcp_opnsense.server as srv
        await srv._request("GET", "/core/system/status")

    assert captured.get("verify") is False


# ---------------------------------------------------------------------------
# Tool test helper
# ---------------------------------------------------------------------------

def make_response(status: int, data) -> httpx.Response:
    """Build a real httpx.Response with JSON body."""
    import json
    mock_req = MagicMock()
    resp = httpx.Response(
        status,
        content=json.dumps(data).encode(),
        headers={"content-type": "application/json"},
    )
    resp._request = mock_req
    return resp


# ---------------------------------------------------------------------------
# system_status
# ---------------------------------------------------------------------------

async def test_system_status_success(monkeypatch):
    payload = {"product": {"product_version": "24.1"}, "cpu": {"used": "3%"}, "mem": {"used": "28%"}}

    async def fake_request(method, path, **kw):
        assert method == "GET"
        assert path == "/core/system/status"
        return make_response(200, payload)

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.system_status()

    assert "product" in result["result"]
    assert result["result"]["product"]["product_version"] == "24.1"


async def test_system_status_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.system_status()

    assert "error" in result
    assert result["tool"] == "system_status"


# ---------------------------------------------------------------------------
# get_gateways
# ---------------------------------------------------------------------------

async def test_get_gateways_success(monkeypatch):
    payload = {"items": [{"name": "WAN_DHCP", "address": "1.2.3.4", "status": "online", "delay": "1.2ms", "loss": "0.0%"}]}

    async def fake_request(method, path, **kw):
        assert path == "/routes/gateway/status"
        return make_response(200, payload)

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.get_gateways()

    assert isinstance(result["result"]["items"], list)
    assert result["result"]["items"][0]["name"] == "WAN_DHCP"
    assert result["result"]["items"][0]["status"] == "online"


async def test_get_gateways_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.get_gateways()

    assert "error" in result
    assert result["tool"] == "get_gateways"


# ---------------------------------------------------------------------------
# list_interfaces
# ---------------------------------------------------------------------------

async def test_list_interfaces_success(monkeypatch):
    payload = [
        {"name": "igc0", "description": "WAN", "ipaddr": "1.2.3.4", "status": "up"},
        {"name": "igc1", "description": "LAN", "ipaddr": "10.0.0.1", "status": "up"},
    ]

    async def fake_request(method, path, **kw):
        assert path == "/interfaces/overview/export"
        return make_response(200, payload)

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_interfaces()

    assert isinstance(result["result"], list)
    assert len(result["result"]) == 2
    assert result["result"][0]["description"] == "WAN"


async def test_list_interfaces_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_interfaces()

    assert "error" in result
    assert result["tool"] == "list_interfaces"
