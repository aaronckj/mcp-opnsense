"""mcp-opnsense: OPNsense firewall management MCP server."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("opnsense")

_DEFAULT_HOST = "https://192.168.1.1"
_DEFAULT_TIMEOUT = 30.0
_VALID_FIREWALL_ACTIONS = {"pass", "block", "reject"}
_VALID_PROTOCOLS = {
    "any", "tcp", "udp", "tcp/udp", "icmp", "esp", "ah", "gre",
    "igmp", "pim", "ospf", "pfsync", "carp",
}
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")


def _build_proxy_body(method: str, path: str, **kwargs: Any) -> dict:
    body: dict = {
        "service": os.environ.get("VAULT_PROXY_SERVICE", "opnsense"),
        "method": method,
        "path": f"/api{path}",
    }
    if "json" in kwargs:
        body["body"] = kwargs["json"]
    if kwargs.get("params"):
        body["query"] = {k: str(v) for k, v in kwargs["params"].items()}
    return body


async def _request(method: str, path: str, **kwargs: Any) -> httpx.Response:
    """Route through vaultproxy if VAULT_PROXY_URL is set, else use direct Basic auth."""
    timeout = float(os.environ.get("OPNSENSE_TIMEOUT", str(_DEFAULT_TIMEOUT)))
    proxy_url = os.environ.get("VAULT_PROXY_URL")

    if proxy_url:
        caller_id = os.environ.get("VAULT_PROXY_CALLER_ID", "mcp-opnsense")
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await client.post(
                f"{proxy_url}/proxy",
                json=_build_proxy_body(method, path, **kwargs),
                headers={"X-Caller-Id": caller_id},
            )

    host = os.environ.get("OPNSENSE_HOST", _DEFAULT_HOST)
    key = os.environ.get("OPNSENSE_API_KEY")
    secret = os.environ.get("OPNSENSE_API_SECRET")
    if not key or not secret:
        raise ValueError("OPNSENSE_API_KEY and OPNSENSE_API_SECRET environment variables are required")
    verify = os.environ.get("OPNSENSE_VERIFY_SSL", "false").lower() == "true"
    async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
        return await client.request(method, f"{host}/api{path}", auth=(key, secret), **kwargs)


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
async def start_service(name: str) -> dict:
    """Start a named OPNsense service (e.g., 'unbound', 'haproxy', 'openvpn')."""
    if not name or not name.strip():
        return {"error": "Service name must not be empty", "tool": "start_service"}
    try:
        resp = await _request("POST", f"/core/service/start/{name}")
        resp.raise_for_status()
        return {"result": {"name": name, "started": True}}
    except Exception as e:
        return {"error": str(e), "tool": "start_service", "detail": type(e).__name__}


@mcp.tool()
async def stop_service(name: str) -> dict:
    """Stop a named OPNsense service (e.g., 'unbound', 'haproxy', 'openvpn')."""
    if not name or not name.strip():
        return {"error": "Service name must not be empty", "tool": "stop_service"}
    try:
        resp = await _request("POST", f"/core/service/stop/{name}")
        resp.raise_for_status()
        return {"result": {"name": name, "stopped": True}}
    except Exception as e:
        return {"error": str(e), "tool": "stop_service", "detail": type(e).__name__}


@mcp.tool()
async def restart_service(name: str) -> dict:
    """Restart a named OPNsense service (e.g., 'unbound', 'haproxy', 'openvpn')."""
    if not name or not name.strip():
        return {"error": "Service name must not be empty", "tool": "restart_service"}
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
    """Add a static DHCPv4 lease mapping a MAC address to a fixed IP. Reconfigures DHCP immediately."""
    if not _MAC_RE.match(mac):
        return {
            "error": f"Invalid MAC address '{mac}'. Expected XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX",
            "tool": "add_static_lease",
        }
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return {"error": f"Invalid IPv4 address: '{ip}'", "tool": "add_static_lease"}
    try:
        body: dict = {"staticmap": {"mac": mac, "ipaddr": ip}}
        if hostname:
            body["staticmap"]["hostname"] = hostname
        resp = await _request("POST", "/dhcpv4/settings/addStaticMap", json=body)
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_static_lease", "detail": type(e).__name__}


@mcp.tool()
async def delete_static_lease(uuid: str) -> dict:
    """Delete a static DHCPv4 lease by UUID and reconfigure DHCP immediately."""
    try:
        resp = await _request("POST", f"/dhcpv4/settings/delStaticMap/{uuid}")
        resp.raise_for_status()

        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_static_lease", "detail": type(e).__name__}


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
async def add_dns_override(hostname: str, domain: str, server: str, record_type: str = "A") -> dict:
    """Add a DNS host override in Unbound and reconfigure immediately. server: target IP. record_type: A (IPv4) or AAAA (IPv6)."""
    record_type = record_type.upper()
    if record_type not in {"A", "AAAA"}:
        return {"error": f"Invalid record_type '{record_type}'. Must be 'A' or 'AAAA'", "tool": "add_dns_override"}
    try:
        resp = await _request(
            "POST",
            "/unbound/host/addHostOverride",
            json={"host": {"host": hostname, "domain": domain, "rr": record_type, "server": server, "enabled": "1"}},
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
    """Add a firewall filter rule and apply immediately. action: pass/block/reject. protocol: tcp/udp/any/icmp/etc. src/dst: network CIDR or 'any'."""
    if action not in _VALID_FIREWALL_ACTIONS:
        return {
            "error": f"Invalid action '{action}'. Must be one of: {', '.join(sorted(_VALID_FIREWALL_ACTIONS))}",
            "tool": "add_firewall_rule",
        }
    proto_lower = protocol.lower()
    if proto_lower not in _VALID_PROTOCOLS:
        return {
            "error": f"Invalid protocol '{protocol}'. Valid: {', '.join(sorted(_VALID_PROTOCOLS))}",
            "tool": "add_firewall_rule",
        }
    try:
        resp = await _request(
            "POST",
            "/firewall/filter/addRule",
            json={"rule": {
                "action": action,
                "interface": interface,
                "protocol": proto_lower,
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


@mcp.tool()
async def list_port_forwards() -> dict:
    """List all NAT port forward rules."""
    try:
        resp = await _request("GET", "/firewall/nat/searchRule")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_port_forwards", "detail": type(e).__name__}


@mcp.tool()
async def add_port_forward(
    interface: str,
    protocol: str,
    dst_port: str,
    target: str,
    target_port: str,
    description: str = "",
) -> dict:
    """Add a NAT port forward rule and apply immediately. interface: WAN interface name. target: internal IPv4 address."""
    try:
        ipaddress.IPv4Address(target)
    except ValueError:
        return {"error": f"Invalid target IPv4 address: '{target}'", "tool": "add_port_forward"}
    try:
        resp = await _request(
            "POST",
            "/firewall/nat/addRule",
            json={"rule": {
                "interface": interface,
                "protocol": protocol,
                "destination_port": dst_port,
                "target": target,
                "local_port": target_port,
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
        return {"error": str(e), "tool": "add_port_forward", "detail": type(e).__name__}


@mcp.tool()
async def delete_port_forward(uuid: str) -> dict:
    """Delete a NAT port forward rule by UUID and apply changes immediately."""
    try:
        resp = await _request("POST", f"/firewall/nat/delRule/{uuid}")
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_port_forward", "detail": type(e).__name__}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
