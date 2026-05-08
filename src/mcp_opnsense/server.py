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
async def list_vlans() -> dict:
    """List all configured VLAN interfaces with tag, parent interface, and description."""
    try:
        resp = await _request("GET", "/interfaces/vlan/searchItem")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_vlans", "detail": type(e).__name__}


@mcp.tool()
async def add_vlan(interface: str, tag: int, description: str = "") -> dict:
    """Create a VLAN on an OPNsense interface. interface: parent physical interface (e.g., 'em0', 'igb0'). tag: VLAN ID 1-4094. description: optional label. Changes require interface assignment and restart to take full effect."""
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_vlan"}
    if not 1 <= tag <= 4094:
        return {"error": "tag must be between 1 and 4094", "tool": "add_vlan"}
    try:
        resp = await _request(
            "POST",
            "/interfaces/vlan/addItem",
            json={"vlan": {
                "if": interface.strip(),
                "tag": str(tag),
                "descr": description.strip(),
                "pcp": "",
            }},
        )
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "add_vlan", "detail": type(e).__name__}


@mcp.tool()
async def get_vlan(uuid: str) -> dict:
    """Get a specific VLAN configuration entry by UUID. Returns interface, tag, description, and enabled state."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_vlan"}
    try:
        resp = await _request("GET", f"/interfaces/vlan/getItem/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_vlan", "detail": type(e).__name__}


@mcp.tool()
async def delete_vlan(uuid: str) -> dict:
    """Delete a VLAN configuration entry by UUID. Use list_vlans to find the UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_vlan"}
    try:
        resp = await _request("POST", f"/interfaces/vlan/delItem/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_vlan", "detail": type(e).__name__}


@mcp.tool()
async def update_vlan(uuid: str, description: str = "", tag: int = 0, interface: str = "") -> dict:
    """Update an existing VLAN entry by UUID. Only non-empty/non-zero fields are changed. description: optional label. tag: new VLAN ID 1-4094 (0 = keep existing). interface: parent interface (e.g. 'em0'). Use list_vlans to find the UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_vlan"}
    if tag != 0 and not 1 <= tag <= 4094:
        return {"error": "tag must be between 1 and 4094", "tool": "update_vlan"}
    if not description and not tag and not interface:
        return {"error": "At least one of description, tag, or interface must be specified", "tool": "update_vlan"}
    try:
        get_resp = await _request("GET", f"/interfaces/vlan/getItem/{uuid.strip()}")
        get_resp.raise_for_status()
        current = get_resp.json().get("vlan", {})
        if interface:
            current["if"] = interface.strip()
        if tag:
            current["tag"] = str(tag)
        if description:
            current["descr"] = description.strip()
        resp = await _request("POST", f"/interfaces/vlan/setItem/{uuid.strip()}", json={"vlan": current})
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_vlan", "detail": type(e).__name__}


@mcp.tool()
async def get_arp_table() -> dict:
    """Get the ARP table from OPNsense — IP-to-MAC mappings for all locally reachable hosts."""
    try:
        resp = await _request("GET", "/diagnostics/interface/getArp")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_arp_table", "detail": type(e).__name__}


@mcp.tool()
async def get_interface_stats() -> dict:
    """Get per-interface traffic statistics: bytes in/out, packets in/out, errors, and drops for all network interfaces."""
    try:
        resp = await _request("GET", "/diagnostics/traffic/interface")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_interface_stats", "detail": type(e).__name__}


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
    """Start a named OPNsense service."""
    if not name or not name.strip():
        return {"error": "Service name must not be empty", "tool": "start_service"}
    try:
        resp = await _request("POST", f"/core/service/start/{name.strip()}")
        resp.raise_for_status()
        return {"result": {"name": name.strip(), "started": True}}
    except Exception as e:
        return {"error": str(e), "tool": "start_service", "detail": type(e).__name__}


@mcp.tool()
async def stop_service(name: str) -> dict:
    """Stop a named OPNsense service."""
    if not name or not name.strip():
        return {"error": "Service name must not be empty", "tool": "stop_service"}
    try:
        resp = await _request("POST", f"/core/service/stop/{name.strip()}")
        resp.raise_for_status()
        return {"result": {"name": name.strip(), "stopped": True}}
    except Exception as e:
        return {"error": str(e), "tool": "stop_service", "detail": type(e).__name__}


@mcp.tool()
async def restart_service(name: str) -> dict:
    """Restart a named OPNsense service (e.g., 'unbound', 'haproxy', 'openvpn')."""
    if not name or not name.strip():
        return {"error": "Service name must not be empty", "tool": "restart_service"}
    try:
        resp = await _request("POST", f"/core/service/restart/{name.strip()}")
        resp.raise_for_status()
        return {"result": {"name": name.strip(), "restarted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "restart_service", "detail": type(e).__name__}


@mcp.tool()
async def get_system_log(log_type: str = "system", rows: int = 50) -> dict:
    """Fetch recent OPNsense log entries via the diagnostics API. log_type: 'system', 'firmware', 'dhcp', 'filter'. rows: 1-500."""
    _VALID_LOG_TYPES = {"system", "firmware", "dhcp", "filter"}
    if log_type not in _VALID_LOG_TYPES:
        return {"error": f"Invalid log_type '{log_type}'. Must be one of: {', '.join(sorted(_VALID_LOG_TYPES))}", "tool": "get_system_log"}
    rows = min(max(1, rows), 500)
    try:
        resp = await _request(
            "POST",
            "/diagnostics/log/core/log",
            json={"logfile": log_type, "limit": rows},
        )
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_system_log", "detail": type(e).__name__}


@mcp.tool()
async def list_cron_jobs() -> dict:
    """List all OPNsense scheduled cron jobs (maintenance tasks, scripts, etc.)."""
    try:
        resp = await _request("GET", "/cron/settings/searchJobs")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_cron_jobs", "detail": type(e).__name__}


@mcp.tool()
async def get_cron_job(uuid: str) -> dict:
    """Get a specific OPNsense cron job by UUID. Returns command, schedule fields, description, and enabled state."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_cron_job"}
    try:
        resp = await _request("GET", f"/cron/settings/getJob/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_cron_job", "detail": type(e).__name__}


@mcp.tool()
async def update_cron_job(uuid: str, command: str = "", description: str = "", minute: str = "", hour: str = "", dom: str = "", month: str = "", dow: str = "") -> dict:
    """Update an existing OPNsense cron job by UUID. Only non-empty fields are changed. Uses same field names as add_cron_job. Applies immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_cron_job"}
    fields: dict = {}
    if command:
        fields["command"] = command.strip()
    if description:
        fields["description"] = description.strip()
    if minute:
        fields["minutes"] = minute
    if hour:
        fields["hours"] = hour
    if dom:
        fields["dayofmonth"] = dom
    if month:
        fields["months"] = month
    if dow:
        fields["weekdays"] = dow
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_cron_job"}
    try:
        get_resp = await _request("GET", f"/cron/settings/getJob/{uuid.strip()}")
        get_resp.raise_for_status()
        current = get_resp.json().get("job", {})
        current.update(fields)
        resp = await _request("POST", f"/cron/settings/setJob/{uuid.strip()}", json={"job": current})
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/cron/settings/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "update_cron_job", "detail": type(e).__name__}


@mcp.tool()
async def add_cron_job(command: str, description: str = "", minute: str = "*", hour: str = "*", dom: str = "*", month: str = "*", dow: str = "*") -> dict:
    """Add an OPNsense scheduled cron job. command: full shell command or OPNsense task name to run. minute/hour/dom/month/dow: cron schedule fields (default '*' = every). Applies immediately."""
    if not command or not command.strip():
        return {"error": "command must not be empty", "tool": "add_cron_job"}
    try:
        resp = await _request(
            "POST",
            "/cron/settings/addJob",
            json={"job": {
                "command": command.strip(),
                "description": description.strip(),
                "minutes": minute.strip(),
                "hours": hour.strip(),
                "dayofmonth": dom.strip(),
                "months": month.strip(),
                "weekdays": dow.strip(),
                "enabled": "1",
            }},
        )
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/cron/settings/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_cron_job", "detail": type(e).__name__}


@mcp.tool()
async def delete_cron_job(uuid: str) -> dict:
    """Delete an OPNsense scheduled cron job by UUID. Applies immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_cron_job"}
    try:
        resp = await _request("POST", f"/cron/settings/delJob/{uuid.strip()}")
        resp.raise_for_status()
        reconf = await _request("POST", "/cron/settings/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_cron_job", "detail": type(e).__name__}


@mcp.tool()
async def toggle_cron_job(uuid: str, enabled: str) -> dict:
    """Enable or disable an OPNsense scheduled cron job without changing other fields. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_cron_job"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/cron/settings/getJob/{uuid.strip()}")
        get_resp.raise_for_status()
        current = get_resp.json().get("job", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/cron/settings/setJob/{uuid.strip()}", json={"job": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/cron/settings/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid.strip(), "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_cron_job", "detail": type(e).__name__}


@mcp.tool()
async def backup_config() -> dict:
    """Download the current OPNsense configuration as XML. Returns raw config.xml content for disaster recovery or migration."""
    try:
        resp = await _request("GET", "/core/backup/download/this")
        resp.raise_for_status()
        return {"result": {"config_xml": resp.text, "size_bytes": len(resp.content)}}
    except Exception as e:
        return {"error": str(e), "tool": "backup_config", "detail": type(e).__name__}


@mcp.tool()
async def apply_changes() -> dict:
    """Apply any pending firewall filter and NAT configuration changes."""
    errors = []
    try:
        resp = await _request("POST", "/firewall/filter/apply")
        resp.raise_for_status()
    except Exception as e:
        errors.append(f"filter: {e}")
    try:
        resp = await _request("POST", "/firewall/nat/apply")
        resp.raise_for_status()
    except Exception as e:
        errors.append(f"nat: {e}")
    if errors:
        return {"error": "; ".join(errors), "tool": "apply_changes"}
    return {"result": {"applied": True}}


@mcp.tool()
async def list_dhcp_leases() -> dict:
    """List all active and static DHCPv4 leases (live lease table, includes dynamically assigned IPs)."""
    try:
        resp = await _request("GET", "/dhcpv4/leases/searchLease")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_dhcp_leases", "detail": type(e).__name__}


@mcp.tool()
async def list_static_leases() -> dict:
    """List all configured static DHCPv4 reservations (MAC-to-IP mappings). Unlike list_dhcp_leases which shows active lease state, this returns the configured static maps regardless of whether the client is currently connected."""
    try:
        resp = await _request("GET", "/dhcpv4/settings/searchStaticMap")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_static_leases", "detail": type(e).__name__}




@mcp.tool()
async def list_dhcpv6_leases() -> dict:
    """List all active DHCPv6 leases (IPv6 DHCP). Includes prefix delegations and stateful addresses."""
    try:
        resp = await _request("GET", "/dhcpv6/leases/searchLease")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_dhcpv6_leases", "detail": type(e).__name__}


@mcp.tool()
async def get_static_lease(uuid: str) -> dict:
    """Get a specific static DHCPv4 lease by UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_static_lease"}
    try:
        resp = await _request("GET", f"/dhcpv4/settings/getStaticMap/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_static_lease", "detail": type(e).__name__}


@mcp.tool()
async def add_static_lease(mac: str, ip: str, hostname: str = "", description: str = "") -> dict:
    """Add a static DHCPv4 lease mapping a MAC address to a fixed IP. Reconfigures DHCP immediately. description: optional label shown in the OPNsense UI."""
    if not _MAC_RE.match(mac.strip()):
        return {"error": f"Invalid MAC address: '{mac}'", "tool": "add_static_lease"}
    try:
        ipaddress.IPv4Address(ip.strip())
    except ValueError:
        return {"error": f"Invalid IPv4 address: '{ip}'", "tool": "add_static_lease"}
    try:
        body: dict = {"staticmap": {"mac": mac.strip(), "ipaddr": ip.strip()}}
        if hostname:
            body["staticmap"]["hostname"] = hostname.strip()
        if description:
            body["staticmap"]["descr"] = description.strip()
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
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_static_lease"}
    try:
        resp = await _request("POST", f"/dhcpv4/settings/delStaticMap/{uuid.strip()}")
        resp.raise_for_status()

        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_static_lease", "detail": type(e).__name__}




@mcp.tool()
async def update_static_lease(uuid: str, mac: str = "", ip: str = "", hostname: str = "", description: str = "") -> dict:
    """Update an existing static DHCPv4 lease by UUID. Only non-empty fields are changed. Reconfigures DHCP immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_static_lease"}
    fields: dict = {}
    if mac:
        if not _MAC_RE.match(mac.strip()):
            return {"error": f"Invalid MAC address: '{mac}'", "tool": "update_static_lease"}
        fields["mac"] = mac.strip()
    if ip:
        try:
            ipaddress.IPv4Address(ip.strip())
        except ValueError:
            return {"error": f"Invalid IPv4 address: '{ip}'", "tool": "update_static_lease"}
        fields["ipaddr"] = ip.strip()
    if hostname:
        fields["hostname"] = hostname.strip()
    if description:
        fields["descr"] = description.strip()
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_static_lease"}
    try:
        resp = await _request("POST", f"/dhcpv4/settings/setStaticMap/{uuid.strip()}", json={"staticmap": fields})
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "update_static_lease", "detail": type(e).__name__}


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
async def get_dns_override(uuid: str) -> dict:
    """Get a specific Unbound DNS host override by UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_dns_override"}
    try:
        resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_dns_override", "detail": type(e).__name__}


@mcp.tool()
async def add_dns_override(hostname: str, domain: str, server: str, record_type: str = "A") -> dict:
    """Add a DNS host override in Unbound and reconfigure immediately. server: target IP. record_type: A (IPv4) or AAAA (IPv6)."""
    record_type = record_type.upper()
    if record_type not in {"A", "AAAA"}:
        return {"error": f"Invalid record_type '{record_type}'. Must be 'A' or 'AAAA'", "tool": "add_dns_override"}
    try:
        if record_type == "A":
            ipaddress.IPv4Address(server)
        else:
            ipaddress.IPv6Address(server)
    except ValueError:
        expected = "IPv4" if record_type == "A" else "IPv6"
        return {"error": f"Invalid {expected} address for server: '{server}'", "tool": "add_dns_override"}
    try:
        resp = await _request(
            "POST",
            "/unbound/host/addHostOverride",
            json={"host": {"host": hostname.strip(), "domain": domain.strip(), "rr": record_type, "server": server.strip(), "enabled": "1"}},
        )
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_dns_override", "detail": type(e).__name__}


@mcp.tool()
async def update_dns_override(
    uuid: str,
    hostname: str = "",
    domain: str = "",
    server: str = "",
    record_type: str = "",
) -> dict:
    """Update an existing Unbound DNS host override by UUID. Only non-empty fields are changed. Reconfigures Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_dns_override"}
    if server:
        try:
            ipaddress.ip_address(server.strip())
        except ValueError:
            return {"error": f"Invalid IP address for server: '{server}'", "tool": "update_dns_override"}
    if record_type:
        rt = record_type.upper()
        if rt not in {"A", "AAAA"}:
            return {"error": f"Invalid record_type '{record_type}'. Must be 'A' or 'AAAA'", "tool": "update_dns_override"}
    if not hostname and not domain and not server and not record_type:
        return {"error": "At least one field to update must be specified", "tool": "update_dns_override"}
    try:
        get_resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid.strip()}")
        get_resp.raise_for_status()
        current = get_resp.json().get("host", {})
        if hostname:
            current["host"] = hostname.strip()
        if domain:
            current["domain"] = domain.strip()
        if record_type:
            current["rr"] = record_type.upper()
        if server:
            current["server"] = server.strip()
        resp = await _request("POST", f"/unbound/host/setHostOverride/{uuid.strip()}", json={"host": current})
        resp.raise_for_status()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid.strip(), "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_dns_override", "detail": type(e).__name__}


@mcp.tool()
async def delete_dns_override(uuid: str) -> dict:
    """Delete a DNS host override by UUID and reconfigure Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_dns_override"}
    try:
        resp = await _request("POST", f"/unbound/host/delHostOverride/{uuid.strip()}")
        resp.raise_for_status()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_dns_override", "detail": type(e).__name__}


@mcp.tool()
async def list_static_routes() -> dict:
    """List all static routes configured in OPNsense."""
    try:
        resp = await _request("GET", "/routes/routes/searchRoute")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_static_routes", "detail": type(e).__name__}




@mcp.tool()
async def get_static_route(uuid: str) -> dict:
    """Get a specific static route by UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_static_route"}
    try:
        resp = await _request("GET", f"/routes/routes/getRoute/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_static_route", "detail": type(e).__name__}


@mcp.tool()
async def add_static_route(network: str, gateway: str, description: str = "") -> dict:
    """Add a static route. network: destination CIDR (e.g., '10.0.0.0/8'). gateway: gateway name as configured in OPNsense (e.g., 'WAN_DHCP'). Applies immediately."""
    if not network or not network.strip():
        return {"error": "network must not be empty", "tool": "add_static_route"}
    if not gateway or not gateway.strip():
        return {"error": "gateway must not be empty", "tool": "add_static_route"}
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        return {"error": f"Invalid network CIDR: '{network}'", "tool": "add_static_route"}
    try:
        resp = await _request(
            "POST",
            "/routes/routes/addRoute",
            json={"route": {
                "network": network.strip(),
                "gateway": gateway.strip(),
                "descr": description.strip(),
                "disabled": "0",
            }},
        )
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/routes/routes/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_static_route", "detail": type(e).__name__}


@mcp.tool()
async def delete_static_route(uuid: str) -> dict:
    """Delete a static route by UUID and apply routing changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_static_route"}
    try:
        resp = await _request("POST", f"/routes/routes/delRoute/{uuid.strip()}")
        resp.raise_for_status()

        reconf = await _request("POST", "/routes/routes/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_static_route", "detail": type(e).__name__}


@mcp.tool()
async def update_static_route(uuid: str, network: str = "", gateway: str = "", description: str = "") -> dict:
    """Update an existing static route by UUID. Only non-empty fields are changed. network: CIDR (e.g., '10.0.0.0/8'). gateway: gateway name. Applies routing changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_static_route"}
    fields: dict = {}
    if network:
        try:
            ipaddress.ip_network(network.strip(), strict=False)
        except ValueError:
            return {"error": f"Invalid network CIDR: '{network}'", "tool": "update_static_route"}
        fields["network"] = network.strip()
    if gateway:
        fields["gateway"] = gateway.strip()
    if description:
        fields["descr"] = description.strip()
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_static_route"}
    try:
        resp = await _request("POST", f"/routes/routes/setRoute/{uuid.strip()}", json={"route": fields})
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/routes/routes/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "update_static_route", "detail": type(e).__name__}


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
async def get_firewall_rule(uuid: str) -> dict:
    """Get a specific firewall filter rule by UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_firewall_rule"}
    try:
        resp = await _request("GET", f"/firewall/filter/getRule/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_firewall_rule", "detail": type(e).__name__}


@mcp.tool()
async def add_firewall_rule(
    action: str,
    interface: str,
    protocol: str,
    src: str,
    dst: str,
    src_port: str = "",
    dst_port: str = "",
    description: str = "",
) -> dict:
    """Add a firewall filter rule and apply immediately. action: pass/block/reject. protocol: any/tcp/udp/icmp/etc. src/dst: network or 'any'. src_port/dst_port: port number, range (e.g. '80:443'), or empty for any (only valid for tcp/udp)."""
    if action not in _VALID_FIREWALL_ACTIONS:
        return {
            "error": f"Invalid action '{action}'. Must be one of: {', '.join(sorted(_VALID_FIREWALL_ACTIONS))}",
            "tool": "add_firewall_rule",
        }
    if protocol not in _VALID_PROTOCOLS:
        return {
            "error": f"Invalid protocol '{protocol}'. Must be one of: {', '.join(sorted(_VALID_PROTOCOLS))}",
            "tool": "add_firewall_rule",
        }
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_firewall_rule"}
    if not src or not src.strip():
        return {"error": "src must not be empty (use 'any' to match all sources)", "tool": "add_firewall_rule"}
    if not dst or not dst.strip():
        return {"error": "dst must not be empty (use 'any' to match all destinations)", "tool": "add_firewall_rule"}
    try:
        resp = await _request(
            "POST",
            "/firewall/filter/addRule",
            json={"rule": {
                "action": action,
                "interface": interface,
                "protocol": protocol,
                "source_net": src,
                "source_port": src_port if src_port else "any",
                "destination_net": dst,
                "destination_port": dst_port if dst_port else "any",
                "description": description.strip(),
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
async def update_firewall_rule(
    uuid: str,
    action: str = "",
    interface: str = "",
    protocol: str = "",
    src: str = "",
    dst: str = "",
    src_port: str = "",
    dst_port: str = "",
    description: str = "",
    enabled: str = "",
) -> dict:
    """Update an existing firewall rule by UUID. Only non-empty fields are changed. src_port/dst_port: port number, range (e.g. '80:443'), or service name; leave empty to keep existing value. enabled: '1'/'true' or '0'/'false'. Applies changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_firewall_rule"}
    rule: dict = {}
    if action:
        if action not in _VALID_FIREWALL_ACTIONS:
            return {"error": f"Invalid action '{action}'. Must be one of: {', '.join(sorted(_VALID_FIREWALL_ACTIONS))}", "tool": "update_firewall_rule"}
        rule["action"] = action
    if interface:
        rule["interface"] = interface
    if protocol:
        if protocol not in _VALID_PROTOCOLS:
            return {"error": f"Invalid protocol '{protocol}'. Must be one of: {', '.join(sorted(_VALID_PROTOCOLS))}", "tool": "update_firewall_rule"}
        rule["protocol"] = protocol
    if src:
        rule["source_net"] = src
    if dst:
        rule["destination_net"] = dst
    if src_port:
        rule["source_port"] = src_port
    if dst_port:
        rule["destination_port"] = dst_port
    if description:
        rule["description"] = description.strip()
    if enabled:
        rule["enabled"] = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    if not rule:
        return {"error": "At least one field to update must be specified", "tool": "update_firewall_rule"}
    try:
        resp = await _request("POST", f"/firewall/filter/setRule/{uuid.strip()}", json={"rule": rule})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid.strip(), "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_firewall_rule", "detail": type(e).__name__}




@mcp.tool()
async def toggle_firewall_rule(uuid: str, enabled: str) -> dict:
    """Enable or disable a firewall rule by UUID. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies changes immediately without touching other rule fields."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_firewall_rule"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        resp = await _request("POST", f"/firewall/filter/setRule/{uuid.strip()}", json={"rule": {"enabled": enabled_val}})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid.strip(), "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_firewall_rule", "detail": type(e).__name__}


@mcp.tool()
async def delete_firewall_rule(uuid: str) -> dict:
    """Delete a firewall filter rule by UUID and apply changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_firewall_rule"}
    try:
        resp = await _request("POST", f"/firewall/filter/delRule/{uuid.strip()}")
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid.strip(), "deleted": True}}
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
async def get_port_forward(uuid: str) -> dict:
    """Get a specific NAT port forward rule by UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_port_forward"}
    try:
        resp = await _request("GET", f"/firewall/nat/getRule/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_port_forward", "detail": type(e).__name__}


@mcp.tool()
async def add_port_forward(
    interface: str,
    protocol: str,
    dst_port: str,
    target: str,
    target_port: str,
    description: str = "",
    src_ip: str = "",
) -> dict:
    """Add a NAT port forward rule and apply immediately. interface: WAN interface name (e.g. 'wan'). protocol: tcp, udp, or tcp/udp. dst_port: external port or range (e.g. '80' or '8000:8080'). target: internal IPv4 address. target_port: internal port. src_ip: optional source IP or CIDR to restrict who can use this forward (empty = any)."""
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_port_forward"}
    if not dst_port or not dst_port.strip():
        return {"error": "dst_port must not be empty", "tool": "add_port_forward"}
    if not target or not target.strip():
        return {"error": "target must not be empty", "tool": "add_port_forward"}
    if not target_port or not target_port.strip():
        return {"error": "target_port must not be empty", "tool": "add_port_forward"}
    _VALID_NAT_PROTOCOLS = {"tcp", "udp", "tcp/udp"}
    if protocol not in _VALID_NAT_PROTOCOLS:
        return {
            "error": f"Invalid protocol '{protocol}'. NAT supports: {', '.join(sorted(_VALID_NAT_PROTOCOLS))}",
            "tool": "add_port_forward",
        }
    try:
        ipaddress.IPv4Address(target)
    except ValueError:
        return {"error": f"Invalid IPv4 address for target: '{target}'", "tool": "add_port_forward"}
    if src_ip and src_ip.strip():
        try:
            ipaddress.ip_network(src_ip.strip(), strict=False)
        except ValueError:
            return {"error": f"Invalid source IP/CIDR: '{src_ip}'", "tool": "add_port_forward"}
    try:
        rule: dict = {
            "interface": interface,
            "protocol": protocol,
            "destination_port": dst_port,
            "target": target,
            "local_port": target_port,
            "description": description.strip(),
            "enabled": "1",
        }
        if src_ip and src_ip.strip():
            rule["source_net"] = src_ip.strip()
        resp = await _request(
            "POST",
            "/firewall/nat/addRule",
            json={"rule": rule},
        )
        resp.raise_for_status()
        result = resp.json()

        apply = await _request("POST", "/firewall/nat/apply")
        apply.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_port_forward", "detail": type(e).__name__}


@mcp.tool()
async def update_port_forward(
    uuid: str,
    interface: str = "",
    protocol: str = "",
    dst_port: str = "",
    target: str = "",
    target_port: str = "",
    description: str = "",
    enabled: str = "",
) -> dict:
    """Update an existing NAT port forward rule by UUID. Only non-empty fields are changed. protocol: tcp, udp, or tcp/udp. enabled: '1'/'true' or '0'/'false'. Applies immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_port_forward"}
    _nat_protocols = {"tcp", "udp", "tcp/udp"}
    rule: dict = {}
    if interface:
        rule["interface"] = interface
    if protocol:
        if protocol.lower() not in _nat_protocols:
            return {"error": f"Invalid protocol '{protocol}'. Must be one of: {', '.join(sorted(_nat_protocols))}", "tool": "update_port_forward"}
        rule["protocol"] = protocol.lower()
    if dst_port:
        rule["destination_port"] = dst_port
    if target:
        try:
            ipaddress.IPv4Address(target)
        except ValueError:
            return {"error": f"Invalid IPv4 address for target: '{target}'", "tool": "update_port_forward"}
        rule["target"] = target
    if target_port:
        rule["local_port"] = target_port
    if description:
        rule["description"] = description.strip()
    if enabled:
        rule["enabled"] = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    if not rule:
        return {"error": "At least one field to update must be specified", "tool": "update_port_forward"}
    try:
        resp = await _request("POST", f"/firewall/nat/setRule/{uuid.strip()}", json={"rule": rule})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/nat/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid.strip(), "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_port_forward", "detail": type(e).__name__}


@mcp.tool()
async def delete_port_forward(uuid: str) -> dict:
    """Delete a NAT port forward rule by UUID and apply changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_port_forward"}
    try:
        resp = await _request("POST", f"/firewall/nat/delRule/{uuid.strip()}")
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/nat/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid.strip(), "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_port_forward", "detail": type(e).__name__}


@mcp.tool()
async def list_aliases() -> dict:
    """List all firewall aliases (groups of IPs, networks, or ports used in firewall rules)."""
    try:
        resp = await _request("GET", "/firewall/alias/searchItem")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_aliases", "detail": type(e).__name__}




@mcp.tool()
async def get_alias(uuid: str) -> dict:
    """Get a specific firewall alias by UUID. Returns name, type, content, and description."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_alias"}
    try:
        resp = await _request("GET", f"/firewall/alias/getItem/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_alias", "detail": type(e).__name__}


@mcp.tool()
async def update_alias(uuid: str, alias_type: str = "", content: str = "", description: str = "") -> dict:
    """Update an existing firewall alias by UUID. Only non-empty fields are changed. alias_type: host/network/port/url. content: newline or comma-separated entries. Reconfigures immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_alias"}
    fields: dict = {}
    if alias_type:
        _valid_alias_types = {"host", "network", "port", "url"}
        if alias_type not in _valid_alias_types:
            return {"error": f"Invalid alias_type '{alias_type}'. Must be one of: {', '.join(sorted(_valid_alias_types))}", "tool": "update_alias"}
        fields["type"] = alias_type
    if content:
        fields["content"] = content.strip()
    if description:
        fields["description"] = description.strip()
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_alias"}
    try:
        resp = await _request("POST", f"/firewall/alias/setItem/{uuid.strip()}", json={"alias": fields})
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/firewall/alias/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "update_alias", "detail": type(e).__name__}


@mcp.tool()
async def add_alias(name: str, alias_type: str, content: str, description: str = "") -> dict:
    """Create a firewall alias. alias_type: 'host' (IPs/hostnames), 'network' (CIDRs), 'port' (port numbers/ranges), 'url' (URL table). content: newline or comma-separated entries. Reconfigures immediately."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_alias"}
    _valid_alias_types = {"host", "network", "port", "url"}
    if alias_type not in _valid_alias_types:
        return {"error": f"Invalid alias_type '{alias_type}'. Must be one of: {', '.join(sorted(_valid_alias_types))}", "tool": "add_alias"}
    if not content or not content.strip():
        return {"error": "content must not be empty", "tool": "add_alias"}
    try:
        resp = await _request(
            "POST",
            "/firewall/alias/addItem",
            json={"alias": {
                "name": name.strip(),
                "type": alias_type,
                "content": content.strip(),
                "description": description.strip(),
                "enabled": "1",
            }},
        )
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/firewall/alias/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_alias", "detail": type(e).__name__}


@mcp.tool()
async def delete_alias(uuid: str) -> dict:
    """Delete a firewall alias by UUID. Note: rules referencing this alias will stop matching. Reconfigures immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_alias"}
    try:
        resp = await _request("POST", f"/firewall/alias/delItem/{uuid.strip()}")
        resp.raise_for_status()

        reconf = await _request("POST", "/firewall/alias/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_alias", "detail": type(e).__name__}



@mcp.tool()
async def list_unbound_domains() -> dict:
    """List all Unbound DNS domain overrides — entries that forward all queries for a domain to a specific nameserver."""
    try:
        resp = await _request("GET", "/unbound/domain/searchDomainOverride")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_unbound_domains", "detail": type(e).__name__}




@mcp.tool()
async def get_unbound_domain(uuid: str) -> dict:
    """Get a specific Unbound DNS domain override by UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_unbound_domain"}
    try:
        resp = await _request("GET", f"/unbound/domain/getDomainOverride/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_unbound_domain", "detail": type(e).__name__}


@mcp.tool()
async def add_unbound_domain(domain: str, server: str, description: str = "") -> dict:
    """Add a DNS domain override in Unbound — forward all queries for a domain to a specific resolver. domain: e.g. 'internal.corp'. server: resolver IP. Reconfigures Unbound immediately."""
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "add_unbound_domain"}
    if not server or not server.strip():
        return {"error": "server must not be empty", "tool": "add_unbound_domain"}
    try:
        ipaddress.ip_address(server.strip())
    except ValueError:
        return {"error": f"Invalid IP address for server: '{server}'", "tool": "add_unbound_domain"}
    try:
        resp = await _request(
            "POST",
            "/unbound/domain/addDomainOverride",
            json={"domain": {"domain": domain.strip(), "server": server.strip(), "description": description, "enabled": "1"}},
        )
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_unbound_domain", "detail": type(e).__name__}


@mcp.tool()
async def delete_unbound_domain(uuid: str) -> dict:
    """Delete a Unbound DNS domain override by UUID and reconfigure Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_unbound_domain"}
    try:
        resp = await _request("POST", f"/unbound/domain/delDomainOverride/{uuid.strip()}")
        resp.raise_for_status()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_unbound_domain", "detail": type(e).__name__}

@mcp.tool()
async def update_unbound_domain(uuid: str, domain: str = "", server: str = "", description: str = "") -> dict:
    """Update an existing Unbound DNS domain override by UUID. Only non-empty fields are changed. server must be a valid IP address. Reconfigures Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_unbound_domain"}
    if server:
        try:
            ipaddress.ip_address(server.strip())
        except ValueError:
            return {"error": f"Invalid IP address for server: '{server}'", "tool": "update_unbound_domain"}
    if not domain and not server and not description:
        return {"error": "At least one field to update must be specified", "tool": "update_unbound_domain"}
    try:
        get_resp = await _request("GET", f"/unbound/domain/getDomainOverride/{uuid.strip()}")
        get_resp.raise_for_status()
        current = get_resp.json().get("domain", {})
        if domain:
            current["domain"] = domain.strip()
        if server:
            current["server"] = server.strip()
        if description:
            current["description"] = description.strip()
        resp = await _request("POST", f"/unbound/domain/setDomainOverride/{uuid.strip()}", json={"domain": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid.strip(), "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_unbound_domain", "detail": type(e).__name__}


@mcp.tool()
async def list_unbound_hosts() -> dict:
    """List all Unbound DNS host overrides — entries that map a specific hostname to an IP address. Different from domain overrides which forward entire domains to a resolver."""
    try:
        resp = await _request("GET", "/unbound/host/searchHostOverride")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_unbound_hosts", "detail": type(e).__name__}


@mcp.tool()
async def add_unbound_host(hostname: str, domain: str, ip: str, description: str = "") -> dict:
    """Add a DNS host override in Unbound — map a specific hostname to an IP. hostname: host part (e.g., 'server1'). domain: domain part (e.g., 'local'). ip: IP address to resolve to. Reconfigures Unbound immediately."""
    if not hostname or not hostname.strip():
        return {"error": "hostname must not be empty", "tool": "add_unbound_host"}
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "add_unbound_host"}
    if not ip or not ip.strip():
        return {"error": "ip must not be empty", "tool": "add_unbound_host"}
    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        return {"error": f"Invalid IP address: '{ip}'", "tool": "add_unbound_host"}
    try:
        resp = await _request(
            "POST",
            "/unbound/host/addHostOverride",
            json={"host": {
                "enabled": "1",
                "host": hostname.strip(),
                "domain": domain.strip(),
                "rr": "AAAA" if ":" in ip.strip() else "A",
                "mxprio": "",
                "mx": "",
                "server": ip.strip(),
                "descr": description.strip(),
            }},
        )
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_unbound_host", "detail": type(e).__name__}


@mcp.tool()
async def get_unbound_host(uuid: str) -> dict:
    """Get a specific Unbound DNS host override by UUID. Returns hostname, domain, IP address, and record type."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_unbound_host"}
    try:
        resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_unbound_host", "detail": type(e).__name__}


@mcp.tool()
async def delete_unbound_host(uuid: str) -> dict:
    """Delete a Unbound DNS host override by UUID and reconfigure Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_unbound_host"}
    try:
        resp = await _request("POST", f"/unbound/host/delHostOverride/{uuid.strip()}")
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_unbound_host", "detail": type(e).__name__}


@mcp.tool()
async def update_unbound_host(uuid: str, hostname: str = "", domain: str = "", ip: str = "", description: str = "") -> dict:
    """Update an existing Unbound DNS host override by UUID. Only non-empty fields are changed. ip: IPv4 or IPv6 address (record type auto-detected). Reconfigures Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_unbound_host"}
    if ip:
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError:
            return {"error": f"Invalid IP address: '{ip}'", "tool": "update_unbound_host"}
    if not hostname and not domain and not ip and not description:
        return {"error": "At least one field to update must be specified", "tool": "update_unbound_host"}
    try:
        get_resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid.strip()}")
        get_resp.raise_for_status()
        current = get_resp.json().get("host", {})
        if hostname:
            current["host"] = hostname.strip()
        if domain:
            current["domain"] = domain.strip()
        if ip:
            current["server"] = ip.strip()
            current["rr"] = "AAAA" if ":" in ip.strip() else "A"
        if description:
            current["descr"] = description.strip()
        resp = await _request("POST", f"/unbound/host/setHostOverride/{uuid.strip()}", json={"host": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_unbound_host", "detail": type(e).__name__}


@mcp.tool()
async def get_firmware_status() -> dict:
    """Check OPNsense firmware update status — current version and available updates."""
    try:
        resp = await _request("GET", "/core/firmware/status")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_firmware_status", "detail": type(e).__name__}



@mcp.tool()
async def list_certificates() -> dict:
    """List all certificates in the OPNsense trust store: CA certificates, server certificates, and client certificates. Returns name, subject, issuer, expiry date, and CA flag for each."""
    try:
        resp = await _request("GET", "/trust/cert/searchCert")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_certificates", "detail": type(e).__name__}



@mcp.tool()
async def get_certificate(uuid: str) -> dict:
    """Get a specific certificate by UUID — returns PEM data, subject, issuer, and expiry. Use list_certificates to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_certificate"}
    try:
        resp = await _request("GET", f"/trust/cert/getCert/{uuid.strip()}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_certificate", "detail": type(e).__name__}


@mcp.tool()
async def reboot_system() -> dict:
    """Reboot the OPNsense system immediately. WARNING: all firewall connections will be interrupted and the system will be unreachable for 1-2 minutes during restart."""
    try:
        resp = await _request("POST", "/core/system/reboot")
        resp.raise_for_status()
        return {"result": {"rebooting": True, "warning": "System is rebooting — connections will drop for 1-2 minutes"}}
    except Exception as e:
        return {"error": str(e), "tool": "reboot_system", "detail": type(e).__name__}


@mcp.tool()
async def toggle_port_forward(uuid: str, enabled: str) -> dict:
    """Enable or disable a NAT port forward rule by UUID without changing other fields. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_port_forward"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        resp = await _request("POST", f"/firewall/nat/setRule/{uuid.strip()}", json={"rule": {"enabled": enabled_val}})
        resp.raise_for_status()
        apply = await _request("POST", "/firewall/nat/apply")
        apply.raise_for_status()
        return {"result": {"uuid": uuid.strip(), "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_port_forward", "detail": type(e).__name__}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
