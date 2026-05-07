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
