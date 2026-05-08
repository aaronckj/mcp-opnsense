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
    interface = interface.strip()
    if not 1 <= tag <= 4094:
        return {"error": "tag must be between 1 and 4094", "tool": "add_vlan"}
    try:
        resp = await _request(
            "POST",
            "/interfaces/vlan/addItem",
            json={"vlan": {
                "if": interface,
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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/interfaces/vlan/getItem/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_vlan", "detail": type(e).__name__}


@mcp.tool()
async def delete_vlan(uuid: str) -> dict:
    """Delete a VLAN configuration entry by UUID. Use list_vlans to find the UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_vlan"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/interfaces/vlan/delItem/{uuid}")
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_vlan", "detail": type(e).__name__}


@mcp.tool()
async def update_vlan(uuid: str, description: str = "", tag: int = 0, interface: str = "") -> dict:
    """Update an existing VLAN entry by UUID. Only non-empty/non-zero fields are changed. description: optional label. tag: new VLAN ID 1-4094 (0 = keep existing). interface: parent interface (e.g. 'em0'). Use list_vlans to find the UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_vlan"}
    uuid = uuid.strip()
    if tag != 0 and not 1 <= tag <= 4094:
        return {"error": "tag must be between 1 and 4094", "tool": "update_vlan"}
    if not description and not tag and not interface:
        return {"error": "At least one of description, tag, or interface must be specified", "tool": "update_vlan"}
    try:
        get_resp = await _request("GET", f"/interfaces/vlan/getItem/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("vlan", {})
        if interface:
            current["if"] = interface.strip()
        if tag:
            current["tag"] = str(tag)
        if description:
            current["descr"] = description.strip()
        resp = await _request("POST", f"/interfaces/vlan/setItem/{uuid}", json={"vlan": current})
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
async def flush_arp_table() -> dict:
    """Flush (clear) the OPNsense ARP cache, removing all current IP-to-MAC mappings. Useful when a device changes its IP or MAC address and immediate re-resolution is needed."""
    try:
        resp = await _request("POST", "/diagnostics/interface/flushArp")
        resp.raise_for_status()
        return {"result": {"flushed": True}}
    except Exception as e:
        return {"error": str(e), "tool": "flush_arp_table", "detail": type(e).__name__}


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
    name = name.strip()
    try:
        resp = await _request("POST", f"/core/service/start/{name}")
        resp.raise_for_status()
        return {"result": {"name": name, "started": True}}
    except Exception as e:
        return {"error": str(e), "tool": "start_service", "detail": type(e).__name__}


@mcp.tool()
async def stop_service(name: str) -> dict:
    """Stop a named OPNsense service."""
    if not name or not name.strip():
        return {"error": "Service name must not be empty", "tool": "stop_service"}
    name = name.strip()
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
    name = name.strip()
    try:
        resp = await _request("POST", f"/core/service/restart/{name}")
        resp.raise_for_status()
        return {"result": {"name": name, "restarted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "restart_service", "detail": type(e).__name__}


@mcp.tool()
async def get_system_log(log_type: str = "system", rows: int = 50) -> dict:
    """Fetch recent OPNsense log entries via the diagnostics API. log_type: 'system', 'firmware', 'dhcp', 'filter'. rows: 1-500."""
    log_type = log_type.strip()
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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/cron/settings/getJob/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_cron_job", "detail": type(e).__name__}


@mcp.tool()
async def update_cron_job(uuid: str, command: str = "", description: str = "", minute: str = "", hour: str = "", dom: str = "", month: str = "", dow: str = "") -> dict:
    """Update an existing OPNsense cron job by UUID. Only non-empty fields are changed. Uses same field names as add_cron_job. Applies immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_cron_job"}
    uuid = uuid.strip()
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
        get_resp = await _request("GET", f"/cron/settings/getJob/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("job", {})
        current.update(fields)
        resp = await _request("POST", f"/cron/settings/setJob/{uuid}", json={"job": current})
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
    command = command.strip()
    try:
        resp = await _request(
            "POST",
            "/cron/settings/addJob",
            json={"job": {
                "command": command,
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
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/cron/settings/delJob/{uuid}")
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
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_cron_job"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/cron/settings/getJob/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("job", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/cron/settings/setJob/{uuid}", json={"job": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/cron/settings/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/dhcpv4/settings/getStaticMap/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_static_lease", "detail": type(e).__name__}


@mcp.tool()
async def add_static_lease(mac: str, ip: str, hostname: str = "", description: str = "") -> dict:
    """Add a static DHCPv4 lease mapping a MAC address to a fixed IP. Reconfigures DHCP immediately. description: optional label shown in the OPNsense UI."""
    if not mac or not mac.strip():
        return {"error": "mac must not be empty", "tool": "add_static_lease"}
    mac = mac.strip()
    if not ip or not ip.strip():
        return {"error": "ip must not be empty", "tool": "add_static_lease"}
    ip = ip.strip()
    if not _MAC_RE.match(mac):
        return {"error": f"Invalid MAC address: '{mac}'", "tool": "add_static_lease"}
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return {"error": f"Invalid IPv4 address: '{ip}'", "tool": "add_static_lease"}
    try:
        body: dict = {"staticmap": {"mac": mac, "ipaddr": ip}}
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
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/dhcpv4/settings/delStaticMap/{uuid}")
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
    uuid = uuid.strip()
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
        get_resp = await _request("GET", f"/dhcpv4/settings/getStaticMap/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("staticmap", {})
        current.update(fields)
        resp = await _request("POST", f"/dhcpv4/settings/setStaticMap/{uuid}", json={"staticmap": current})
        resp.raise_for_status()

        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_static_lease", "detail": type(e).__name__}


@mcp.tool()
async def list_dhcpv6_static_leases() -> dict:
    """List all configured static DHCPv6 reservations (prefix/address-to-DUID mappings). Returns configured static mappings regardless of whether the client is currently connected."""
    try:
        resp = await _request("GET", "/dhcpv6/settings/searchStaticMap")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_dhcpv6_static_leases", "detail": type(e).__name__}


@mcp.tool()
async def get_dhcpv6_static_lease(uuid: str) -> dict:
    """Get a specific static DHCPv6 lease by UUID. Returns DUID, IPv6 address, hostname, and description."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_dhcpv6_static_lease"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/dhcpv6/settings/getStaticMap/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_dhcpv6_static_lease", "detail": type(e).__name__}


@mcp.tool()
async def add_dhcpv6_static_lease(duid: str, ip6addr: str, hostname: str = "", description: str = "") -> dict:
    """Add a static DHCPv6 lease mapping a DUID to a fixed IPv6 address. Reconfigures DHCPv6 immediately. duid: client DUID (Device Unique Identifier). ip6addr: IPv6 address to assign."""
    if not duid or not duid.strip():
        return {"error": "duid must not be empty", "tool": "add_dhcpv6_static_lease"}
    duid = duid.strip()
    if not ip6addr or not ip6addr.strip():
        return {"error": "ip6addr must not be empty", "tool": "add_dhcpv6_static_lease"}
    ip6addr = ip6addr.strip()
    try:
        ipaddress.IPv6Address(ip6addr)
    except ValueError:
        return {"error": f"Invalid IPv6 address: '{ip6addr}'", "tool": "add_dhcpv6_static_lease"}
    try:
        body: dict = {"staticmap": {"duid": duid, "ipaddrv6": ip6addr}}
        if hostname:
            body["staticmap"]["hostname"] = hostname.strip()
        if description:
            body["staticmap"]["descr"] = description.strip()
        resp = await _request("POST", "/dhcpv6/settings/addStaticMap", json=body)
        resp.raise_for_status()
        reconf = await _request("POST", "/dhcpv6/service/reconfigure")
        reconf.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "add_dhcpv6_static_lease", "detail": type(e).__name__}


@mcp.tool()
async def delete_dhcpv6_static_lease(uuid: str) -> dict:
    """Delete a static DHCPv6 lease by UUID and reconfigure DHCPv6 immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_dhcpv6_static_lease"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/dhcpv6/settings/delStaticMap/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/dhcpv6/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_dhcpv6_static_lease", "detail": type(e).__name__}


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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_dns_override", "detail": type(e).__name__}


@mcp.tool()
async def add_dns_override(hostname: str, domain: str, server: str, record_type: str = "A") -> dict:
    """Add a DNS host override in Unbound and reconfigure immediately. server: target IP. record_type: A (IPv4) or AAAA (IPv6)."""
    if not hostname or not hostname.strip():
        return {"error": "hostname must not be empty", "tool": "add_dns_override"}
    hostname = hostname.strip()
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "add_dns_override"}
    domain = domain.strip()
    if not server or not server.strip():
        return {"error": "server must not be empty", "tool": "add_dns_override"}
    server = server.strip()
    record_type = record_type.strip().upper()
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
    uuid = uuid.strip()
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
        get_resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("host", {})
        if hostname:
            current["host"] = hostname.strip()
        if domain:
            current["domain"] = domain.strip()
        if record_type:
            current["rr"] = rt
        if server:
            current["server"] = server.strip()
        resp = await _request("POST", f"/unbound/host/setHostOverride/{uuid}", json={"host": current})
        resp.raise_for_status()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_dns_override", "detail": type(e).__name__}


@mcp.tool()
async def delete_dns_override(uuid: str) -> dict:
    """Delete a DNS host override by UUID and reconfigure Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_dns_override"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/unbound/host/delHostOverride/{uuid}")
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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/routes/routes/getRoute/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_static_route", "detail": type(e).__name__}


@mcp.tool()
async def add_static_route(network: str, gateway: str, description: str = "") -> dict:
    """Add a static route. network: destination CIDR (e.g., '10.0.0.0/8'). gateway: gateway name as configured in OPNsense (e.g., 'WAN_DHCP'). Applies immediately."""
    if not network or not network.strip():
        return {"error": "network must not be empty", "tool": "add_static_route"}
    network = network.strip()
    if not gateway or not gateway.strip():
        return {"error": "gateway must not be empty", "tool": "add_static_route"}
    gateway = gateway.strip()
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        return {"error": f"Invalid network CIDR: '{network}'", "tool": "add_static_route"}
    try:
        resp = await _request(
            "POST",
            "/routes/routes/addRoute",
            json={"route": {
                "network": network,
                "gateway": gateway,
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
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/routes/routes/delRoute/{uuid}")
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
    uuid = uuid.strip()
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
        get_resp = await _request("GET", f"/routes/routes/getRoute/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("route", {})
        current.update(fields)
        resp = await _request("POST", f"/routes/routes/setRoute/{uuid}", json={"route": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/routes/routes/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_static_route", "detail": type(e).__name__}


@mcp.tool()
async def toggle_static_route(uuid: str, enabled: str) -> dict:
    """Enable or disable a static route by UUID without changing other fields. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies routing changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_static_route"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_static_route"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/routes/routes/getRoute/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("route", {})
        current["disabled"] = "0" if enabled_val == "1" else "1"
        resp = await _request("POST", f"/routes/routes/setRoute/{uuid}", json={"route": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/routes/routes/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_static_route", "detail": type(e).__name__}


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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/firewall/filter/getRule/{uuid}")
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
    if not action or not action.strip():
        return {"error": "action must not be empty. Use: pass, block, or reject", "tool": "add_firewall_rule"}
    action = action.strip()
    if not protocol or not protocol.strip():
        return {"error": "protocol must not be empty. Use: any, tcp, udp, tcp/udp, icmp, etc.", "tool": "add_firewall_rule"}
    protocol = protocol.strip()
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
    interface = interface.strip()
    if not src or not src.strip():
        return {"error": "src must not be empty (use 'any' to match all sources)", "tool": "add_firewall_rule"}
    src = src.strip()
    if not dst or not dst.strip():
        return {"error": "dst must not be empty (use 'any' to match all destinations)", "tool": "add_firewall_rule"}
    dst = dst.strip()
    _PORT_PROTOCOLS = {"tcp", "udp", "tcp/udp"}
    try:
        rule_body: dict = {
            "action": action,
            "interface": interface,
            "protocol": protocol,
            "source_net": src,
            "destination_net": dst,
            "description": description.strip(),
            "enabled": "1",
        }
        if protocol in _PORT_PROTOCOLS:
            if src_port and src_port.strip():
                rule_body["source_port"] = src_port.strip()
            if dst_port and dst_port.strip():
                rule_body["destination_port"] = dst_port.strip()
        resp = await _request(
            "POST",
            "/firewall/filter/addRule",
            json={"rule": rule_body},
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
    uuid = uuid.strip()
    rule: dict = {}
    if action:
        if action.strip() not in _VALID_FIREWALL_ACTIONS:
            return {"error": f"Invalid action '{action}'. Must be one of: {', '.join(sorted(_VALID_FIREWALL_ACTIONS))}", "tool": "update_firewall_rule"}
        rule["action"] = action.strip()
    if interface:
        rule["interface"] = interface.strip()
    if protocol:
        if protocol.strip() not in _VALID_PROTOCOLS:
            return {"error": f"Invalid protocol '{protocol}'. Must be one of: {', '.join(sorted(_VALID_PROTOCOLS))}", "tool": "update_firewall_rule"}
        rule["protocol"] = protocol.strip()
    if src:
        rule["source_net"] = src.strip()
    if dst:
        rule["destination_net"] = dst.strip()
    if src_port:
        rule["source_port"] = src_port.strip()
    if dst_port:
        rule["destination_port"] = dst_port.strip()
    if description:
        rule["description"] = description.strip()
    if enabled:
        rule["enabled"] = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    if not rule:
        return {"error": "At least one field to update must be specified", "tool": "update_firewall_rule"}
    try:
        get_resp = await _request("GET", f"/firewall/filter/getRule/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("rule", {})
        current.update(rule)
        resp = await _request("POST", f"/firewall/filter/setRule/{uuid}", json={"rule": current})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_firewall_rule", "detail": type(e).__name__}




@mcp.tool()
async def toggle_firewall_rule(uuid: str, enabled: str) -> dict:
    """Enable or disable a firewall rule by UUID. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies changes immediately without touching other rule fields."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_firewall_rule"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_firewall_rule"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/firewall/filter/getRule/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("rule", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/firewall/filter/setRule/{uuid}", json={"rule": current})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_firewall_rule", "detail": type(e).__name__}


@mcp.tool()
async def delete_firewall_rule(uuid: str) -> dict:
    """Delete a firewall filter rule by UUID and apply changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_firewall_rule"}
    uuid = uuid.strip()
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
async def get_port_forward(uuid: str) -> dict:
    """Get a specific NAT port forward rule by UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_port_forward"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/firewall/nat/getRule/{uuid}")
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
    interface = interface.strip()
    if not dst_port or not dst_port.strip():
        return {"error": "dst_port must not be empty", "tool": "add_port_forward"}
    dst_port = dst_port.strip()
    if not target or not target.strip():
        return {"error": "target must not be empty", "tool": "add_port_forward"}
    target = target.strip()
    if not target_port or not target_port.strip():
        return {"error": "target_port must not be empty", "tool": "add_port_forward"}
    target_port = target_port.strip()
    if not protocol or not protocol.strip():
        return {"error": "protocol must not be empty (tcp, udp, or tcp/udp)", "tool": "add_port_forward"}
    protocol = protocol.strip()
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
    uuid = uuid.strip()
    _nat_protocols = {"tcp", "udp", "tcp/udp"}
    rule: dict = {}
    if interface:
        rule["interface"] = interface.strip()
    if protocol:
        if protocol.strip().lower() not in _nat_protocols:
            return {"error": f"Invalid protocol '{protocol}'. Must be one of: {', '.join(sorted(_nat_protocols))}", "tool": "update_port_forward"}
        rule["protocol"] = protocol.strip().lower()
    if dst_port:
        rule["destination_port"] = dst_port.strip()
    if target:
        try:
            ipaddress.IPv4Address(target.strip())
        except ValueError:
            return {"error": f"Invalid IPv4 address for target: '{target}'", "tool": "update_port_forward"}
        rule["target"] = target.strip()
    if target_port:
        rule["local_port"] = target_port.strip()
    if description:
        rule["description"] = description.strip()
    if enabled:
        rule["enabled"] = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    if not rule:
        return {"error": "At least one field to update must be specified", "tool": "update_port_forward"}
    try:
        get_resp = await _request("GET", f"/firewall/nat/getRule/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("rule", {})
        current.update(rule)
        resp = await _request("POST", f"/firewall/nat/setRule/{uuid}", json={"rule": current})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/nat/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_port_forward", "detail": type(e).__name__}


@mcp.tool()
async def delete_port_forward(uuid: str) -> dict:
    """Delete a NAT port forward rule by UUID and apply changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_port_forward"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/firewall/nat/delRule/{uuid}")
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/nat/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
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
async def get_alias_by_name(name: str) -> dict:
    """Find a firewall alias by its name (e.g., 'LAN_HOSTS', 'BLOCKED_IPS'). Returns the alias UUID, type, content, and description. Useful when you know the alias name but need its UUID for update/delete/toggle operations."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "get_alias_by_name"}
    name = name.strip()
    try:
        resp = await _request("GET", "/firewall/alias/searchItem", params={"searchPhrase": name})
        resp.raise_for_status()
        data = resp.json()
        rows = data.get("rows", [])
        matches = [r for r in rows if r.get("name") == name]
        if not matches:
            return {"error": f"No alias named '{name}' found. Use list_aliases to see all aliases.", "tool": "get_alias_by_name"}
        return {"result": matches[0] if len(matches) == 1 else matches}
    except Exception as e:
        return {"error": str(e), "tool": "get_alias_by_name", "detail": type(e).__name__}




@mcp.tool()
async def get_alias(uuid: str) -> dict:
    """Get a specific firewall alias by UUID. Returns name, type, content, and description."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_alias"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/firewall/alias/getItem/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_alias", "detail": type(e).__name__}


@mcp.tool()
async def update_alias(uuid: str, alias_type: str = "", content: str = "", description: str = "") -> dict:
    """Update an existing firewall alias by UUID. Only non-empty fields are changed. alias_type: host/network/port/url. content: newline or comma-separated entries. Reconfigures immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_alias"}
    uuid = uuid.strip()
    if alias_type:
        _valid_alias_types = {"host", "network", "port", "url"}
        if alias_type.strip() not in _valid_alias_types:
            return {"error": f"Invalid alias_type '{alias_type}'. Must be one of: {', '.join(sorted(_valid_alias_types))}", "tool": "update_alias"}
    if not alias_type and not content and not description:
        return {"error": "At least one field to update must be specified", "tool": "update_alias"}
    try:
        get_resp = await _request("GET", f"/firewall/alias/getItem/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("alias", {})
        if alias_type:
            current["type"] = alias_type.strip()
        if content:
            current["content"] = content.strip()
        if description:
            current["description"] = description.strip()
        resp = await _request("POST", f"/firewall/alias/setItem/{uuid}", json={"alias": current})
        resp.raise_for_status()

        reconf = await _request("POST", "/firewall/alias/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_alias", "detail": type(e).__name__}


@mcp.tool()
async def add_alias(name: str, alias_type: str, content: str, description: str = "") -> dict:
    """Create a firewall alias. alias_type: 'host' (IPs/hostnames), 'network' (CIDRs), 'port' (port numbers/ranges), 'url' (URL table). content: newline or comma-separated entries. Reconfigures immediately."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_alias"}
    name = name.strip()
    alias_type = alias_type.strip()
    _valid_alias_types = {"host", "network", "port", "url"}
    if alias_type not in _valid_alias_types:
        return {"error": f"Invalid alias_type '{alias_type}'. Must be one of: {', '.join(sorted(_valid_alias_types))}", "tool": "add_alias"}
    if not content or not content.strip():
        return {"error": "content must not be empty", "tool": "add_alias"}
    content = content.strip()
    try:
        resp = await _request(
            "POST",
            "/firewall/alias/addItem",
            json={"alias": {
                "name": name,
                "type": alias_type,
                "content": content,
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
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/firewall/alias/delItem/{uuid}")
        resp.raise_for_status()

        reconf = await _request("POST", "/firewall/alias/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_alias", "detail": type(e).__name__}


@mcp.tool()
async def toggle_alias(uuid: str, enabled: str) -> dict:
    """Enable or disable a firewall alias by UUID without modifying any other fields. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Reconfigures firewall immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_alias"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_alias"}
    enabled = enabled.strip()
    enabled_val = "1" if enabled.lower() in {"1", "true", "yes"} else "0"
    try:
        resp = await _request("POST", f"/firewall/alias/toggleItem/{uuid}/{enabled_val}")
        resp.raise_for_status()

        reconf = await _request("POST", "/firewall/alias/reconfigure")
        reconf.raise_for_status()

        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_alias", "detail": type(e).__name__}


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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/unbound/domain/getDomainOverride/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_unbound_domain", "detail": type(e).__name__}


@mcp.tool()
async def add_unbound_domain(domain: str, server: str, description: str = "") -> dict:
    """Add a DNS domain override in Unbound — forward all queries for a domain to a specific resolver. domain: e.g. 'internal.corp'. server: resolver IP. Reconfigures Unbound immediately."""
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "add_unbound_domain"}
    domain = domain.strip()
    if not server or not server.strip():
        return {"error": "server must not be empty", "tool": "add_unbound_domain"}
    server = server.strip()
    try:
        ipaddress.ip_address(server)
    except ValueError:
        return {"error": f"Invalid IP address for server: '{server}'", "tool": "add_unbound_domain"}
    try:
        resp = await _request(
            "POST",
            "/unbound/domain/addDomainOverride",
            json={"domain": {"domain": domain, "server": server, "description": description.strip(), "enabled": "1"}},
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
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/unbound/domain/delDomainOverride/{uuid}")
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
    uuid = uuid.strip()
    if server:
        try:
            ipaddress.ip_address(server.strip())
        except ValueError:
            return {"error": f"Invalid IP address for server: '{server}'", "tool": "update_unbound_domain"}
    if not domain and not server and not description:
        return {"error": "At least one field to update must be specified", "tool": "update_unbound_domain"}
    try:
        get_resp = await _request("GET", f"/unbound/domain/getDomainOverride/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("domain", {})
        if domain:
            current["domain"] = domain.strip()
        if server:
            current["server"] = server.strip()
        if description:
            current["description"] = description.strip()
        resp = await _request("POST", f"/unbound/domain/setDomainOverride/{uuid}", json={"domain": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_unbound_domain", "detail": type(e).__name__}


@mcp.tool()
async def toggle_unbound_domain(uuid: str, enabled: str) -> dict:
    """Enable or disable an Unbound DNS domain override by UUID without changing other fields. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Reconfigures Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_unbound_domain"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_unbound_domain"}
    enabled = enabled.strip()
    enabled_val = "1" if enabled.lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/unbound/domain/getDomainOverride/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("domain", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/unbound/domain/setDomainOverride/{uuid}", json={"domain": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_unbound_domain", "detail": type(e).__name__}


@mcp.tool()
async def add_unbound_host(hostname: str, domain: str, ip: str, description: str = "") -> dict:
    """Add a DNS host override in Unbound — map a specific hostname to an IP. hostname: host part (e.g., 'server1'). domain: domain part (e.g., 'local'). ip: IP address to resolve to. Reconfigures Unbound immediately."""
    if not hostname or not hostname.strip():
        return {"error": "hostname must not be empty", "tool": "add_unbound_host"}
    hostname = hostname.strip()
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "add_unbound_host"}
    domain = domain.strip()
    if not ip or not ip.strip():
        return {"error": "ip must not be empty", "tool": "add_unbound_host"}
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"Invalid IP address: '{ip}'", "tool": "add_unbound_host"}
    try:
        resp = await _request(
            "POST",
            "/unbound/host/addHostOverride",
            json={"host": {
                "enabled": "1",
                "host": hostname,
                "domain": domain,
                "rr": "AAAA" if ":" in ip else "A",
                "mxprio": "",
                "mx": "",
                "server": ip,
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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_unbound_host", "detail": type(e).__name__}


@mcp.tool()
async def delete_unbound_host(uuid: str) -> dict:
    """Delete a Unbound DNS host override by UUID and reconfigure Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_unbound_host"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/unbound/host/delHostOverride/{uuid}")
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
    uuid = uuid.strip()
    if ip:
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError:
            return {"error": f"Invalid IP address: '{ip}'", "tool": "update_unbound_host"}
    if not hostname and not domain and not ip and not description:
        return {"error": "At least one field to update must be specified", "tool": "update_unbound_host"}
    try:
        get_resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid}")
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
        resp = await _request("POST", f"/unbound/host/setHostOverride/{uuid}", json={"host": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_unbound_host", "detail": type(e).__name__}


@mcp.tool()
async def toggle_unbound_host(uuid: str, enabled: str) -> dict:
    """Enable or disable an Unbound DNS host override by UUID without changing other fields. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Reconfigures Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_unbound_host"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_unbound_host"}
    enabled = enabled.strip()
    enabled_val = "1" if enabled.lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("host", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/unbound/host/setHostOverride/{uuid}", json={"host": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_unbound_host", "detail": type(e).__name__}


@mcp.tool()
async def flush_dns_cache() -> dict:
    """Flush the Unbound DNS resolver cache — forces re-resolution of all cached records. Useful after DNS changes to ensure OPNsense immediately picks up new values without waiting for TTL expiry."""
    try:
        resp = await _request("POST", "/unbound/service/flush_cache")
        resp.raise_for_status()
        return {"result": {"flushed": True}}
    except Exception as e:
        return {"error": str(e), "tool": "flush_dns_cache", "detail": type(e).__name__}


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
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/trust/cert/getCert/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_certificate", "detail": type(e).__name__}


@mcp.tool()
async def delete_certificate(uuid: str) -> dict:
    """Delete a certificate from the OPNsense trust store by UUID. Use list_certificates to find UUIDs. WARNING: deleting a certificate in use by a service may break that service."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_certificate"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/trust/cert/delCert/{uuid}")
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_certificate", "detail": type(e).__name__}


@mcp.tool()
async def get_traffic(interface: str = "") -> dict:
    """Get real-time traffic statistics for a specific interface or all interfaces: bytes/packets in/out, error counts. interface: interface name (e.g. 'em0', 'igb1') or empty for all."""
    try:
        if interface and interface.strip():
            resp = await _request("GET", f"/diagnostics/traffic/interface/{interface.strip()}")
        else:
            resp = await _request("GET", "/diagnostics/traffic/interface")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_traffic", "detail": type(e).__name__}


@mcp.tool()
async def get_ipsec_status() -> dict:
    """Get IPsec VPN status — running state, active SA (Security Associations), and tunnel uptime."""
    try:
        resp = await _request("GET", "/ipsec/service/status")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ipsec_status", "detail": type(e).__name__}


@mcp.tool()
async def list_ipsec_tunnels() -> dict:
    """List all configured IPsec Phase 1 (IKE) tunnel entries. Each entry represents one VPN connection with its remote peer, encryption settings, and enabled state."""
    try:
        resp = await _request("GET", "/ipsec/tunnels/searchPhase1")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_ipsec_tunnels", "detail": type(e).__name__}


@mcp.tool()
async def get_ipsec_tunnel(uuid: str) -> dict:
    """Get a specific IPsec Phase 1 (IKE) tunnel configuration by UUID. Returns all settings including remote peer, authentication method, and encryption proposals. Use list_ipsec_tunnels to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_ipsec_tunnel"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/ipsec/tunnels/getPhase1/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ipsec_tunnel", "detail": type(e).__name__}


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
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_port_forward"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/firewall/nat/getRule/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("rule", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/firewall/nat/setRule/{uuid}", json={"rule": current})
        resp.raise_for_status()
        apply = await _request("POST", "/firewall/nat/apply")
        apply.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_port_forward", "detail": type(e).__name__}


@mcp.tool()
async def get_ndp_table() -> dict:
    """Get the IPv6 Neighbor Discovery Protocol (NDP) table — IPv6 address to MAC mappings for locally reachable hosts. The IPv6 equivalent of the ARP table."""
    try:
        resp = await _request("GET", "/diagnostics/interface/getNdp")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ndp_table", "detail": type(e).__name__}


@mcp.tool()
async def get_openvpn_status() -> dict:
    """Get the status of all configured OpenVPN instances — whether each is running, connected clients, bytes transferred. Useful for monitoring VPN health without logging into the OPNsense UI."""
    try:
        resp = await _request("GET", "/openvpn/service/searchSessions")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_openvpn_status", "detail": type(e).__name__}


@mcp.tool()
async def get_routing_table() -> dict:
    """Get the active system routing table from OPNsense — all currently active routes including dynamic (DHCP/BGP), connected, and static routes. Different from list_static_routes which only shows configured static routes."""
    try:
        resp = await _request("GET", "/diagnostics/routes/getroutes")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_routing_table", "detail": type(e).__name__}


@mcp.tool()
async def shutdown_system() -> dict:
    """Initiate a graceful system shutdown (poweroff) of the OPNsense appliance. This is irreversible — the system will power off and require physical/IPMI access to restart."""
    try:
        resp = await _request("POST", "/core/system/halt")
        resp.raise_for_status()
        return {"result": {"shutdown_initiated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "shutdown_system", "detail": type(e).__name__}


@mcp.tool()
async def list_nat_outbound() -> dict:
    """List outbound NAT (source NAT/masquerade) rules. Returns both manual rules and the current mode (automatic, hybrid, manual, disabled)."""
    try:
        resp = await _request("GET", "/firewall/nat/outbound")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_nat_outbound", "detail": type(e).__name__}


@mcp.tool()
async def get_nat_outbound(uuid: str) -> dict:
    """Get a specific outbound NAT rule by UUID. Returns interface, source/destination networks, target, and enabled state. Use list_nat_outbound to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_nat_outbound"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/firewall/nat/getOutboundRule/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_nat_outbound", "detail": type(e).__name__}


@mcp.tool()
async def add_nat_outbound(interface: str, source_net: str, destination_net: str = "any", target: str = "", description: str = "") -> dict:
    """Add an outbound NAT rule. interface: WAN interface name (e.g. 'wan'). source_net: source network in CIDR notation (e.g. '192.168.1.0/24'). destination_net: destination network (default 'any'). target: NAT target IP (empty = interface address). description: rule description."""
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_nat_outbound"}
    interface = interface.strip()
    if not source_net or not source_net.strip():
        return {"error": "source_net must not be empty", "tool": "add_nat_outbound"}
    source_net = source_net.strip()
    try:
        ipaddress.ip_network(source_net, strict=False)
    except ValueError:
        return {"error": f"Invalid source_net CIDR: '{source_net}'", "tool": "add_nat_outbound"}
    try:
        rule = {
            "rule": {
                "interface": interface,
                "ipprotocol": "inet",
                "protocol": "any",
                "source": {"network": source_net},
                "destination": {"network": destination_net.strip() or "any"},
                "target": target.strip(),
                "descr": description.strip(),
                "disabled": "0",
                "nonat": "0",
            }
        }
        resp = await _request("POST", "/firewall/nat/addOutboundRule", json=rule)
        resp.raise_for_status()
        data = resp.json()
        uuid = data.get("uuid", "")
        if uuid:
            sp = await _request("POST", "/firewall/nat/savepoint")
            sp.raise_for_status()
            ap = await _request("POST", "/firewall/filter/apply")
            ap.raise_for_status()
        return {"result": {"uuid": uuid, "interface": interface, "source_net": source_net}}
    except Exception as e:
        return {"error": str(e), "tool": "add_nat_outbound", "detail": type(e).__name__}


@mcp.tool()
async def delete_nat_outbound(uuid: str) -> dict:
    """Delete an outbound NAT rule by UUID. Use list_nat_outbound to find UUIDs. Changes are applied immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_nat_outbound"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/firewall/nat/delOutboundRule/{uuid}")
        resp.raise_for_status()
        sp = await _request("POST", "/firewall/nat/savepoint")
        sp.raise_for_status()
        ap = await _request("POST", "/firewall/filter/apply")
        ap.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_nat_outbound", "detail": type(e).__name__}


@mcp.tool()
async def toggle_nat_outbound(uuid: str, enabled: str) -> dict:
    """Enable or disable an outbound NAT rule by UUID without changing other fields. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Changes are applied immediately. Note: outbound NAT rules use a 'disabled' flag internally — this tool abstracts that detail."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_nat_outbound"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_nat_outbound"}
    is_enabled = enabled.strip().lower() in {"1", "true", "yes"}
    try:
        get_resp = await _request("GET", f"/firewall/nat/getOutboundRule/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("rule", {})
        current["disabled"] = "0" if is_enabled else "1"
        resp = await _request("POST", f"/firewall/nat/setOutboundRule/{uuid}", json={"rule": current})
        resp.raise_for_status()
        sp = await _request("POST", "/firewall/nat/savepoint")
        sp.raise_for_status()
        ap = await _request("POST", "/firewall/filter/apply")
        ap.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": is_enabled}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_nat_outbound", "detail": type(e).__name__}


@mcp.tool()
async def get_intrusion_detection_status() -> dict:
    """Get the Intrusion Detection System (IDS/IPS) status — whether Suricata is running, the current mode (IDS/IPS), and installed ruleset stats."""
    try:
        resp = await _request("GET", "/ids/service/getStatus")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_intrusion_detection_status", "detail": type(e).__name__}


@mcp.tool()
async def list_ipsec_phase2() -> dict:
    """List all IPsec Phase 2 (Child SA / ESP) entries. Each entry defines the traffic selectors, encryption, and PFS settings for one tunnel's data channel. Use together with list_ipsec_tunnels (Phase 1)."""
    try:
        resp = await _request("GET", "/ipsec/tunnels/searchPhase2")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_ipsec_phase2", "detail": type(e).__name__}


@mcp.tool()
async def get_ipsec_phase2(uuid: str) -> dict:
    """Get a specific IPsec Phase 2 (Child SA) entry by UUID. Returns traffic selectors, encryption algorithms, and PFS settings. Use list_ipsec_phase2 to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_ipsec_phase2"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/ipsec/tunnels/getPhase2/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ipsec_phase2", "detail": type(e).__name__}


@mcp.tool()
async def toggle_ipsec_tunnel(uuid: str, enabled: str) -> dict:
    """Enable or disable an IPsec Phase 1 tunnel by UUID without changing other fields. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Use list_ipsec_tunnels to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_ipsec_tunnel"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_ipsec_tunnel"}
    enabled = enabled.strip()
    enabled_val = "1" if enabled.lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/ipsec/tunnels/getPhase1/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("tunnel", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/ipsec/tunnels/setPhase1/{uuid}", json={"tunnel": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/ipsec/tunnels/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_ipsec_tunnel", "detail": type(e).__name__}


@mcp.tool()
async def update_nat_outbound(uuid: str, interface: str = "", source_net: str = "", destination_net: str = "", target: str = "", description: str = "") -> dict:
    """Update an existing outbound NAT rule by UUID. Only non-empty fields are changed. Use list_nat_outbound to find UUIDs. Changes are applied immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_nat_outbound"}
    uuid = uuid.strip()
    if not any([interface, source_net, destination_net, target, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_nat_outbound"}
    if source_net and source_net.strip():
        try:
            ipaddress.ip_network(source_net.strip(), strict=False)
        except ValueError:
            return {"error": f"Invalid source_net CIDR: '{source_net}'", "tool": "update_nat_outbound"}
    try:
        get_resp = await _request("GET", f"/firewall/nat/getOutboundRule/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("rule", {})
        if interface:
            current["interface"] = interface.strip()
        if source_net:
            current.setdefault("source", {})["network"] = source_net.strip()
        if destination_net:
            current.setdefault("destination", {})["network"] = destination_net.strip()
        if target:
            current["target"] = target.strip()
        if description:
            current["descr"] = description.strip()
        resp = await _request("POST", f"/firewall/nat/setOutboundRule/{uuid}", json={"rule": current})
        resp.raise_for_status()
        sp = await _request("POST", "/firewall/nat/savepoint")
        sp.raise_for_status()
        ap = await _request("POST", "/firewall/filter/apply")
        ap.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_nat_outbound", "detail": type(e).__name__}


@mcp.tool()
async def get_haproxy_status() -> dict:
    """Get HAProxy service status — whether the service is running. Returns error if HAProxy plugin is not installed."""
    try:
        resp = await _request("GET", "/haproxy/service/running")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_haproxy_status", "detail": type(e).__name__}


@mcp.tool()
async def get_wireguard_status() -> dict:
    """Get WireGuard VPN status — running state, active peers, and their last handshake/transfer stats. Returns empty result if WireGuard plugin is not installed."""
    try:
        resp = await _request("GET", "/wireguard/service/show")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_wireguard_status", "detail": type(e).__name__}


@mcp.tool()
async def list_wireguard_servers() -> dict:
    """List all configured WireGuard VPN server instances with their peers, public keys, and listen ports."""
    try:
        resp = await _request("GET", "/wireguard/server/searchServer")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_wireguard_servers", "detail": type(e).__name__}


@mcp.tool()
async def get_wireguard_server(uuid: str) -> dict:
    """Get a specific WireGuard VPN server instance by UUID. Returns public key, listen port, tunnel addresses, and peer list. Use list_wireguard_servers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_wireguard_server"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/wireguard/server/getServer/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_wireguard_server", "detail": type(e).__name__}


@mcp.tool()
async def list_wireguard_peers() -> dict:
    """List all configured WireGuard VPN peers (clients) with their public keys, allowed IPs, and endpoint settings."""
    try:
        resp = await _request("GET", "/wireguard/client/searchClient")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_wireguard_peers", "detail": type(e).__name__}


@mcp.tool()
async def get_wireguard_peer(uuid: str) -> dict:
    """Get a specific WireGuard VPN peer (client) by UUID. Returns public key, allowed IPs, endpoint address, and keepalive settings. Use list_wireguard_peers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_wireguard_peer"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/wireguard/client/getClient/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_wireguard_peer", "detail": type(e).__name__}


@mcp.tool()
async def list_haproxy_servers() -> dict:
    """List all HAProxy real server (backend server) entries configured in OPNsense. Returns empty if HAProxy plugin is not installed."""
    try:
        resp = await _request("GET", "/haproxy/server/searchServer")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_haproxy_servers", "detail": type(e).__name__}


@mcp.tool()
async def get_haproxy_server(uuid: str) -> dict:
    """Get a specific HAProxy real server entry by UUID. Returns address, port, health check settings, and weight. Use list_haproxy_servers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_haproxy_server"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/haproxy/server/getServer/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_haproxy_server", "detail": type(e).__name__}


@mcp.tool()
async def list_haproxy_backends() -> dict:
    """List all HAProxy backend pools configured in OPNsense, including load balancing algorithm, health check settings, and member servers."""
    try:
        resp = await _request("GET", "/haproxy/backend/searchBackend")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_haproxy_backends", "detail": type(e).__name__}


@mcp.tool()
async def get_haproxy_backend(uuid: str) -> dict:
    """Get a specific HAProxy backend pool by UUID. Returns load balancing algorithm, servers, health check settings, and sticky session configuration. Use list_haproxy_backends to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_haproxy_backend"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/haproxy/backend/getBackend/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_haproxy_backend", "detail": type(e).__name__}


@mcp.tool()
async def get_haproxy_frontend(uuid: str) -> dict:
    """Get a specific HAProxy frontend listener by UUID. Returns bind address, default backend, ACLs, and SSL settings. Use list_haproxy_frontends to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_haproxy_frontend"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/haproxy/frontend/getFrontend/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_haproxy_frontend", "detail": type(e).__name__}


@mcp.tool()
async def list_haproxy_frontends() -> dict:
    """List all HAProxy frontend listeners configured in OPNsense — bind addresses, ACLs, and backend associations."""
    try:
        resp = await _request("GET", "/haproxy/frontend/searchFrontend")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_haproxy_frontends", "detail": type(e).__name__}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
