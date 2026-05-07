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


# ---------------------------------------------------------------------------
# list_services
# ---------------------------------------------------------------------------

async def test_list_services_success(monkeypatch):
    payload = [
        {"id": "unbound", "name": "Unbound DNS", "running": True},
        {"id": "haproxy", "name": "HAProxy", "running": False},
    ]

    async def fake_request(method, path, **kw):
        assert method == "GET"
        assert path == "/core/service/"
        return make_response(200, payload)

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_services()

    assert isinstance(result["result"], list)
    assert result["result"][0]["id"] == "unbound"


async def test_list_services_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_services()

    assert "error" in result
    assert result["tool"] == "list_services"


# ---------------------------------------------------------------------------
# restart_service
# ---------------------------------------------------------------------------

async def test_restart_service_success(monkeypatch):
    async def fake_request(method, path, **kw):
        assert method == "POST"
        assert path == "/core/service/restart/unbound"
        return make_response(200, {"response": "OK"})

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.restart_service(name="unbound")

    assert result["result"]["name"] == "unbound"
    assert result["result"]["restarted"] is True


async def test_restart_service_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.restart_service(name="unbound")

    assert "error" in result
    assert result["tool"] == "restart_service"


# ---------------------------------------------------------------------------
# apply_changes
# ---------------------------------------------------------------------------

async def test_apply_changes_success(monkeypatch):
    async def fake_request(method, path, **kw):
        assert method == "POST"
        assert path == "/firewall/filter/apply"
        return make_response(200, {"status": "ok"})

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.apply_changes()

    assert result["result"]["applied"] is True


async def test_apply_changes_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.apply_changes()

    assert "error" in result
    assert result["tool"] == "apply_changes"


# ---------------------------------------------------------------------------
# list_dhcp_leases
# ---------------------------------------------------------------------------

async def test_list_dhcp_leases_success(monkeypatch):
    payload = {
        "rows": [
            {"address": "10.0.0.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "mypc", "type": "dynamic"},
            {"address": "10.0.0.10", "mac": "11:22:33:44:55:66", "hostname": "server", "type": "static"},
        ],
        "rowCount": 2,
    }

    async def fake_request(method, path, **kw):
        assert method == "GET"
        assert path == "/dhcpv4/leases/searchLease"
        return make_response(200, payload)

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_dhcp_leases()

    assert isinstance(result["result"]["rows"], list)
    assert len(result["result"]["rows"]) == 2
    assert result["result"]["rows"][0]["address"] == "10.0.0.100"


async def test_list_dhcp_leases_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_dhcp_leases()

    assert "error" in result
    assert result["tool"] == "list_dhcp_leases"


# ---------------------------------------------------------------------------
# add_static_lease
# ---------------------------------------------------------------------------

async def test_add_static_lease_success(monkeypatch):
    async def fake_request(method, path, **kw):
        assert method == "POST"
        assert path == "/dhcpv4/settings/addStaticMap"
        body = kw.get("json", {})
        assert body.get("staticmap", {}).get("mac") == "aa:bb:cc:dd:ee:ff"
        assert body.get("staticmap", {}).get("ipaddr") == "10.0.0.50"
        return make_response(200, {"result": "saved", "uuid": "uuid-123"})

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.add_static_lease(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.50", hostname="mydevice")

    assert result["result"]["result"] == "saved"


async def test_add_static_lease_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.add_static_lease(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.50")

    assert "error" in result
    assert result["tool"] == "add_static_lease"


# ---------------------------------------------------------------------------
# list_dns_overrides
# ---------------------------------------------------------------------------

async def test_list_dns_overrides_success(monkeypatch):
    payload = {
        "rows": [
            {"uuid": "abc-123", "host": "myserver", "domain": "local", "server": "10.0.0.5"},
        ],
        "rowCount": 1,
    }

    async def fake_request(method, path, **kw):
        assert path == "/unbound/host/searchHostOverride"
        return make_response(200, payload)

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_dns_overrides()

    assert result["result"]["rows"][0]["host"] == "myserver"


async def test_list_dns_overrides_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_dns_overrides()

    assert "error" in result
    assert result["tool"] == "list_dns_overrides"


# ---------------------------------------------------------------------------
# add_dns_override
# ---------------------------------------------------------------------------

async def test_add_dns_override_success(monkeypatch):
    calls = []

    async def fake_request(method, path, **kw):
        calls.append(path)
        if "/addHostOverride" in path:
            body = kw.get("json", {})
            assert body.get("host", {}).get("host") == "myserver"
            assert body.get("host", {}).get("domain") == "local"
            assert body.get("host", {}).get("server") == "10.0.0.5"
            return make_response(200, {"result": "saved", "uuid": "new-uuid"})
        return make_response(200, {"status": "ok"})

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.add_dns_override(hostname="myserver", domain="local", server="10.0.0.5")

    assert any("/addHostOverride" in c for c in calls)
    assert any("/reconfigure" in c for c in calls)
    assert result["result"]["result"] == "saved"


async def test_add_dns_override_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.add_dns_override(hostname="myserver", domain="local", server="10.0.0.5")

    assert "error" in result
    assert result["tool"] == "add_dns_override"


# ---------------------------------------------------------------------------
# delete_dns_override
# ---------------------------------------------------------------------------

async def test_delete_dns_override_success(monkeypatch):
    calls = []

    async def fake_request(method, path, **kw):
        calls.append(path)
        return make_response(200, {"result": "deleted"})

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.delete_dns_override(uuid="abc-123")

    assert any("abc-123" in c for c in calls)
    assert any("/reconfigure" in c for c in calls)
    assert result["result"]["deleted"] is True


async def test_delete_dns_override_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.delete_dns_override(uuid="abc-123")

    assert "error" in result
    assert result["tool"] == "delete_dns_override"


# ---------------------------------------------------------------------------
# list_firewall_rules
# ---------------------------------------------------------------------------

async def test_list_firewall_rules_success(monkeypatch):
    payload = {
        "rows": [
            {"uuid": "rule-1", "action": "pass", "interface": "lan", "description": "Allow LAN"},
            {"uuid": "rule-2", "action": "block", "interface": "wan", "description": "Block WAN"},
        ],
        "rowCount": 2,
    }

    async def fake_request(method, path, **kw):
        assert path == "/firewall/filter/searchRule"
        return make_response(200, payload)

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_firewall_rules()

    assert isinstance(result["result"]["rows"], list)
    assert result["result"]["rows"][0]["action"] == "pass"


async def test_list_firewall_rules_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.list_firewall_rules()

    assert "error" in result
    assert result["tool"] == "list_firewall_rules"


# ---------------------------------------------------------------------------
# add_firewall_rule
# ---------------------------------------------------------------------------

async def test_add_firewall_rule_success(monkeypatch):
    calls = []

    async def fake_request(method, path, **kw):
        calls.append(path)
        if "/addRule" in path:
            body = kw.get("json", {})
            assert body.get("rule", {}).get("action") == "pass"
            assert body.get("rule", {}).get("interface") == "lan"
            return make_response(200, {"result": "saved", "uuid": "new-rule-uuid"})
        return make_response(200, {"status": "ok"})

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.add_firewall_rule(
        action="pass", interface="lan", protocol="tcp",
        src="any", dst="10.0.0.5", description="Allow test",
    )

    assert any("/addRule" in c for c in calls)
    assert any("/apply" in c for c in calls)
    assert result["result"]["result"] == "saved"


async def test_add_firewall_rule_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.add_firewall_rule(
        action="pass", interface="lan", protocol="tcp", src="any", dst="any",
    )

    assert "error" in result
    assert result["tool"] == "add_firewall_rule"


# ---------------------------------------------------------------------------
# delete_firewall_rule
# ---------------------------------------------------------------------------

async def test_delete_firewall_rule_success(monkeypatch):
    calls = []

    async def fake_request(method, path, **kw):
        calls.append(path)
        return make_response(200, {"result": "deleted"})

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.delete_firewall_rule(uuid="rule-uuid-1")

    assert any("rule-uuid-1" in c for c in calls)
    assert any("/apply" in c for c in calls)
    assert result["result"]["deleted"] is True


async def test_delete_firewall_rule_error(monkeypatch):
    async def fake_request(method, path, **kw):
        raise httpx.ConnectError("Connection refused")

    import mcp_opnsense.server as srv
    monkeypatch.setattr(srv, "_request", fake_request)
    result = await srv.delete_firewall_rule(uuid="rule-uuid-1")

    assert "error" in result
    assert result["tool"] == "delete_firewall_rule"
