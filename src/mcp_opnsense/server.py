"""mcp-opnsense: OPNsense firewall management MCP server."""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("opnsense")

_DEFAULT_HOST = "https://192.168.1.1"
_DEFAULT_TIMEOUT = 30.0


async def _request(method: str, path: str, **kwargs) -> httpx.Response:
    host = os.environ.get("OPNSENSE_HOST", _DEFAULT_HOST)
    key = os.environ.get("OPNSENSE_API_KEY")
    secret = os.environ.get("OPNSENSE_API_SECRET")
    if not key or not secret:
        raise ValueError("OPNSENSE_API_KEY and OPNSENSE_API_SECRET environment variables are required")
    timeout = float(os.environ.get("OPNSENSE_TIMEOUT", str(_DEFAULT_TIMEOUT)))
    verify = os.environ.get("OPNSENSE_VERIFY_SSL", "false").lower() == "true"
    async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
        resp = await client.request(method, f"{host}/api{path}", auth=(key, secret), **kwargs)
        return resp


@mcp.tool()
async def system_status() -> dict:
    """Get OPNsense system status: CPU, memory, uptime, and firmware version."""
    try:
        resp = await _request("GET", "/core/system/status")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "system_status", "detail": type(e).__name__}


@mcp.tool()
async def get_gateways() -> dict:
    """Get WAN gateway status including latency, packet loss, and online/offline state."""
    try:
        resp = await _request("GET", "/routes/gateway/status")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_gateways", "detail": type(e).__name__}


@mcp.tool()
async def list_interfaces() -> dict:
    """List all network interfaces with IP addresses and link state."""
    try:
        resp = await _request("GET", "/interfaces/overview/export")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_interfaces", "detail": type(e).__name__}


@mcp.tool()
async def list_services() -> dict:
    """List all OPNsense services and their running status."""
    try:
        resp = await _request("GET", "/core/service/")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_services", "detail": type(e).__name__}


@mcp.tool()
async def restart_service(name: str) -> dict:
    """Restart a named OPNsense service (e.g., 'unbound', 'haproxy', 'openvpn')."""
    try:
        resp = await _request("POST", f"/core/service/restart/{name}")
        resp.raise_for_status()
        return {"result": {"name": name, "restarted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "restart_service", "detail": type(e).__name__}


@mcp.tool()
async def apply_changes() -> dict:
    """Apply any pending firewall and configuration changes."""
    try:
        resp = await _request("POST", "/firewall/filter/apply")
        resp.raise_for_status()
        return {"result": {"applied": True}}
    except Exception as e:
        return {"error": str(e), "tool": "apply_changes", "detail": type(e).__name__}


@mcp.tool()
async def list_dhcp_leases() -> dict:
    """List all active and static DHCPv4 leases."""
    try:
        resp = await _request("GET", "/dhcpv4/leases/searchLease")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_dhcp_leases", "detail": type(e).__name__}


@mcp.tool()
async def add_static_lease(mac: str, ip: str, hostname: str = "") -> dict:
    """Add a static DHCPv4 lease mapping a MAC address to a fixed IP."""
    try:
        body: dict = {"staticmap": {"mac": mac, "ipaddr": ip}}
        if hostname:
            body["staticmap"]["hostname"] = hostname
        resp = await _request("POST", "/dhcpv4/settings/addStaticMap", json=body)
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "add_static_lease", "detail": type(e).__name__}


@mcp.tool()
async def list_dns_overrides() -> dict:
    """List all Unbound DNS host overrides."""
    try:
        resp = await _request("GET", "/unbound/host/searchHostOverride")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_dns_overrides", "detail": type(e).__name__}


@mcp.tool()
async def add_dns_override(hostname: str, domain: str, server: str) -> dict:
    """Add a DNS host override in Unbound and reconfigure immediately. server: target IP address."""
    try:
        resp = await _request(
            "POST",
            "/unbound/host/addHostOverride",
            json={"host": {"host": hostname, "domain": domain, "rr": "A", "server": server, "enabled": "1"}},
        )
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_dns_override", "detail": type(e).__name__}


@mcp.tool()
async def delete_dns_override(uuid: str) -> dict:
    """Delete a DNS host override by UUID and reconfigure Unbound immediately."""
    try:
        resp = await _request("POST", f"/unbound/host/delHostOverride/{uuid}")
        resp.raise_for_status()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_dns_override", "detail": type(e).__name__}


@mcp.tool()
async def list_firewall_rules() -> dict:
    """List all firewall filter rules."""
    try:
        resp = await _request("GET", "/firewall/filter/searchRule")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_firewall_rules", "detail": type(e).__name__}


@mcp.tool()
async def add_firewall_rule(
    action: str,
    interface: str,
    protocol: str,
    src: str,
    dst: str,
    description: str = "",
) -> dict:
    """Add a firewall filter rule and apply immediately. action: pass/block/reject. src/dst: network or 'any'."""
    try:
        resp = await _request(
            "POST",
            "/firewall/filter/addRule",
            json={"rule": {
                "action": action,
                "interface": interface,
                "protocol": protocol,
                "source_net": src,
                "destination_net": dst,
                "description": description,
                "enabled": "1",
            }},
        )
        resp.raise_for_status()
        result = resp.json()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_firewall_rule", "detail": type(e).__name__}


@mcp.tool()
async def delete_firewall_rule(uuid: str) -> dict:
    """Delete a firewall filter rule by UUID and apply changes immediately."""
    try:
        resp = await _request("POST", f"/firewall/filter/delRule/{uuid}")
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_firewall_rule", "detail": type(e).__name__}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
