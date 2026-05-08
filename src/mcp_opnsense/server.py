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


def _validate_cron_field(value: str, min_val: int, max_val: int, field: str) -> str | None:
    """Validate a cron field value. Returns error string or None if valid."""
    value = value.strip()
    if value == "*":
        return None
    for part in value.split(","):
        part = part.strip()
        if "/" in part:
            range_part, step_str = part.rsplit("/", 1)
            try:
                step = int(step_str)
                if step < 1:
                    return f"{field}: step must be >= 1, got {step_str!r}"
            except ValueError:
                return f"{field}: invalid step {step_str!r}"
            part = range_part
        if part == "*":
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                return f"{field}: invalid range {part!r}"
            if not (min_val <= lo_i <= max_val and min_val <= hi_i <= max_val):
                return f"{field}: range {lo}-{hi} out of {min_val}-{max_val}"
            if lo_i > hi_i:
                return f"{field}: range start {lo_i} > end {hi_i}"
        else:
            try:
                v = int(part)
            except ValueError:
                return f"{field}: invalid value {part!r}"
            if not (min_val <= v <= max_val):
                return f"{field}: value {v} out of range {min_val}-{max_val}"
    return None


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
        return {"error": str(e), "tool": "get_vlan", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_vlan", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "update_vlan", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_vlan(uuid: str, enabled: str) -> dict:
    """Enable or disable a VLAN interface without changing other configuration. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Use list_vlans to find the UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_vlan"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_vlan"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/interfaces/vlan/getItem/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("vlan", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/interfaces/vlan/setItem/{uuid}", json={"vlan": current})
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_vlan", "uuid": uuid, "detail": type(e).__name__}


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
    """Fetch recent OPNsense log entries via the diagnostics API. log_type: 'system', 'firmware', 'dhcp', 'filter', 'openvpn', 'ids', 'dhcp6'. rows: 1-500."""
    log_type = log_type.strip()
    _VALID_LOG_TYPES = {"system", "firmware", "dhcp", "filter", "openvpn", "ids", "dhcp6"}
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
        return {"error": str(e), "tool": "get_cron_job", "uuid": uuid, "detail": type(e).__name__}


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
        fields["minutes"] = minute.strip()
    if hour:
        fields["hours"] = hour.strip()
    if dom:
        fields["dayofmonth"] = dom.strip()
    if month:
        fields["months"] = month.strip()
    if dow:
        fields["weekdays"] = dow.strip()
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_cron_job"}
    for raw_val, lo, hi, name in [
        (minute, 0, 59, "minute"), (hour, 0, 23, "hour"),
        (dom, 1, 31, "dom"), (month, 1, 12, "month"), (dow, 0, 6, "dow"),
    ]:
        if raw_val:
            err = _validate_cron_field(raw_val, lo, hi, name)
            if err:
                return {"error": err, "tool": "update_cron_job"}
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
        return {"error": str(e), "tool": "update_cron_job", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_cron_job(command: str, description: str = "", minute: str = "*", hour: str = "*", dom: str = "*", month: str = "*", dow: str = "*") -> dict:
    """Add an OPNsense scheduled cron job. command: full shell command or OPNsense task name to run. minute/hour/dom/month/dow: cron schedule fields (default '*' = every). Applies immediately."""
    if not command or not command.strip():
        return {"error": "command must not be empty", "tool": "add_cron_job"}
    command = command.strip()
    for val, lo, hi, name in [
        (minute, 0, 59, "minute"), (hour, 0, 23, "hour"),
        (dom, 1, 31, "dom"), (month, 1, 12, "month"), (dow, 0, 6, "dow"),
    ]:
        err = _validate_cron_field(val, lo, hi, name)
        if err:
            return {"error": err, "tool": "add_cron_job"}
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
        return {"error": str(e), "tool": "delete_cron_job", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "toggle_cron_job", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_static_lease", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_static_lease", "uuid": uuid, "detail": type(e).__name__}




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
        return {"error": str(e), "tool": "update_static_lease", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_static_lease(uuid: str, enabled: str) -> dict:
    """Enable or disable a static DHCPv4 lease without changing other configuration. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Reconfigures DHCP immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_static_lease"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_static_lease"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/dhcpv4/settings/getStaticMap/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("staticmap", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/dhcpv4/settings/setStaticMap/{uuid}", json={"staticmap": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_static_lease", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_dhcpv6_static_lease", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_dhcpv6_static_lease", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_dhcpv6_static_lease(uuid: str, duid: str = "", ip6addr: str = "", hostname: str = "", description: str = "") -> dict:
    """Update an existing static DHCPv6 lease by UUID. Only non-empty fields are changed. Reconfigures DHCPv6 immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_dhcpv6_static_lease"}
    uuid = uuid.strip()
    fields: dict = {}
    if duid:
        fields["duid"] = duid.strip()
    if ip6addr:
        try:
            ipaddress.IPv6Address(ip6addr.strip())
        except ValueError:
            return {"error": f"Invalid IPv6 address: '{ip6addr}'", "tool": "update_dhcpv6_static_lease"}
        fields["ipaddrv6"] = ip6addr.strip()
    if hostname:
        fields["hostname"] = hostname.strip()
    if description:
        fields["descr"] = description.strip()
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_dhcpv6_static_lease"}
    try:
        get_resp = await _request("GET", f"/dhcpv6/settings/getStaticMap/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("staticmap", {})
        current.update(fields)
        resp = await _request("POST", f"/dhcpv6/settings/setStaticMap/{uuid}", json={"staticmap": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/dhcpv6/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_dhcpv6_static_lease", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_dhcpv6_static_lease(uuid: str, enabled: str) -> dict:
    """Enable or disable a static DHCPv6 lease without changing other configuration. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Reconfigures DHCPv6 immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_dhcpv6_static_lease"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_dhcpv6_static_lease"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/dhcpv6/settings/getStaticMap/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("staticmap", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/dhcpv6/settings/setStaticMap/{uuid}", json={"staticmap": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/dhcpv6/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_dhcpv6_static_lease", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_dns_override(uuid: str, enabled: str) -> dict:
    """Enable or disable a DNS host override in Unbound without changing other settings. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Reconfigures Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_dns_override"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_dns_override"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
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
        return {"error": str(e), "tool": "toggle_dns_override", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_dns_override", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_dns_override(hostname: str, domain: str, server: str, record_type: str = "A", description: str = "") -> dict:
    """Add a DNS host override in Unbound and reconfigure immediately. server: target IP. record_type: A (IPv4) or AAAA (IPv6). description: optional label shown in the OPNsense UI."""
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
            json={"host": {"host": hostname, "domain": domain, "rr": record_type, "server": server, "descr": description.strip(), "enabled": "1"}},
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
        return {"error": str(e), "tool": "update_dns_override", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_dns_override", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_static_route", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_static_route", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "update_static_route", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "toggle_static_route", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_firewall_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_firewall_rule(
    action: str,
    interface: str,
    protocol: str,
    src: str,
    dst: str,
    src_port: str = "",
    dst_port: str = "",
    direction: str = "in",
    description: str = "",
    log: bool = False,
    quick: bool = True,
) -> dict:
    """Add a firewall filter rule and apply immediately. action: pass/block/reject. protocol: any/tcp/udp/icmp/etc. src/dst: network or 'any'. src_port/dst_port: port number, range (e.g. '80:443'), or empty for any (only valid for tcp/udp). direction: 'in' (default, ingress) or 'out' (egress). log: enable packet logging for this rule (default False). quick: stop rule evaluation after first match (default True, OPNsense default behavior)."""
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
    direction = direction.strip().lower()
    if direction not in {"in", "out"}:
        return {"error": f"direction must be 'in' or 'out', got '{direction}'", "tool": "add_firewall_rule"}
    _PORT_PROTOCOLS = {"tcp", "udp", "tcp/udp"}
    try:
        rule_body: dict = {
            "action": action,
            "interface": interface,
            "direction": direction,
            "protocol": protocol,
            "source_net": src,
            "destination_net": dst,
            "description": description.strip(),
            "enabled": "1",
            "log": "1" if log else "0",
            "quick": "1" if quick else "0",
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
        return {"error": str(e), "tool": "add_firewall_rule", "action": action, "interface": interface, "protocol": protocol, "src": src, "dst": dst, "detail": type(e).__name__}


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
    direction: str = "",
    log: str = "",
    quick: str = "",
) -> dict:
    """Update an existing firewall rule by UUID. Only non-empty/specified fields are changed. src_port/dst_port: port number, range (e.g. '80:443'), or service name; leave empty to keep existing value. enabled/log/quick: '1'/'true'/'yes' or '0'/'false'/'no'. direction: 'in' or 'out'. Applies changes immediately."""
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
    if direction:
        d = direction.strip().lower()
        if d not in {"in", "out"}:
            return {"error": f"direction must be 'in' or 'out', got '{direction}'", "tool": "update_firewall_rule"}
        rule["direction"] = d
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
    if log:
        rule["log"] = "1" if log.strip().lower() in {"1", "true", "yes"} else "0"
    if quick:
        rule["quick"] = "1" if quick.strip().lower() in {"1", "true", "yes"} else "0"
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
        return {"error": str(e), "tool": "update_firewall_rule", "uuid": uuid, "detail": type(e).__name__}




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
        return {"error": str(e), "tool": "toggle_firewall_rule", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_firewall_rule", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_port_forward", "uuid": uuid, "detail": type(e).__name__}


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
    def _valid_port_or_range(s: str) -> bool:
        parts = s.split(":")
        try:
            return all(1 <= int(p) <= 65535 for p in parts) and len(parts) in (1, 2)
        except ValueError:
            return False
    if not _valid_port_or_range(dst_port):
        return {"error": f"dst_port must be a port (1-65535) or range (e.g. '8000:8080'), got '{dst_port}'", "tool": "add_port_forward"}
    if not _valid_port_or_range(target_port):
        return {"error": f"target_port must be a port (1-65535) or range, got '{target_port}'", "tool": "add_port_forward"}
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
        return {"error": str(e), "tool": "add_port_forward", "interface": interface, "dst_port": dst_port, "target": target, "target_port": target_port, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "update_port_forward", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_port_forward", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_alias", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_alias(uuid: str, alias_type: str = "", content: str = "", description: str = "") -> dict:
    """Update an existing firewall alias by UUID. Only non-empty fields are changed. alias_type: host/network/port/url/urltable/urltable_ports/geoip/asn. content: newline or comma-separated entries. Reconfigures immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_alias"}
    uuid = uuid.strip()
    if alias_type:
        _valid_alias_types = {"host", "network", "port", "url", "urltable", "urltable_ports", "geoip", "asn"}
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
        return {"error": str(e), "tool": "update_alias", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_alias(name: str, alias_type: str, content: str, description: str = "") -> dict:
    """Create a firewall alias. alias_type: 'host' (IPs/hostnames), 'network' (CIDRs), 'port' (port numbers/ranges), 'url' (URL-based host list), 'urltable' (URL table of IPs/nets), 'urltable_ports' (URL table of ports), 'geoip' (country code), 'asn' (BGP ASN). content: newline or comma-separated entries. Reconfigures immediately."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_alias"}
    name = name.strip()
    if not re.match(r'^[a-zA-Z0-9_]+$', name):
        return {"error": f"Invalid alias name '{name}'. OPNsense alias names must contain only letters, digits, and underscores (no spaces or hyphens).", "tool": "add_alias"}
    alias_type = alias_type.strip()
    _valid_alias_types = {"host", "network", "port", "url", "urltable", "urltable_ports", "geoip", "asn"}
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
        return {"error": str(e), "tool": "delete_alias", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "toggle_alias", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_unbound_hosts() -> dict:
    """List all Unbound DNS host overrides — specific hostname-to-IP mappings configured in OPNsense. Companion list tool for add_unbound_host, get_unbound_host, update_unbound_host, delete_unbound_host, and toggle_unbound_host."""
    try:
        resp = await _request("GET", "/unbound/host/searchHostOverride")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_unbound_hosts", "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_unbound_domain", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_unbound_domain", "uuid": uuid, "detail": type(e).__name__}

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
        return {"error": str(e), "tool": "update_unbound_domain", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "toggle_unbound_domain", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_unbound_host", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_unbound_host", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "update_unbound_host", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "toggle_unbound_host", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_certificate", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "delete_certificate", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_ipsec_tunnel", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "toggle_port_forward", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_nat_outbound", "uuid": uuid, "detail": type(e).__name__}


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
    destination_net = destination_net.strip() if destination_net else "any"
    if destination_net != "any":
        try:
            ipaddress.ip_network(destination_net, strict=False)
        except ValueError:
            return {"error": f"Invalid destination_net CIDR: '{destination_net}' (use 'any' for all destinations)", "tool": "add_nat_outbound"}
    try:
        rule = {
            "rule": {
                "interface": interface,
                "ipprotocol": "inet",
                "protocol": "any",
                "source": {"network": source_net},
                "destination": {"network": destination_net},
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
            ap = await _request("POST", "/firewall/nat/apply")
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
        ap = await _request("POST", "/firewall/nat/apply")
        ap.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_nat_outbound", "uuid": uuid, "detail": type(e).__name__}


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
        ap = await _request("POST", "/firewall/nat/apply")
        ap.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": is_enabled}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_nat_outbound", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_ipsec_phase2", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "toggle_ipsec_tunnel", "uuid": uuid, "detail": type(e).__name__}


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
        ap = await _request("POST", "/firewall/nat/apply")
        ap.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_nat_outbound", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_wireguard_server", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_wireguard_peer", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_wireguard_peer(name: str, public_key: str, tunnel_address: str, server_address: str = "", server_port: str = "51820", psk: str = "", keepalive: int = 25, description: str = "") -> dict:
    """Add a WireGuard peer (client) to OPNsense and reconfigure WireGuard immediately. name: peer name. public_key: peer's WireGuard public key. tunnel_address: allowed IP or CIDR for this peer inside the tunnel (e.g. '10.0.0.2/32'). server_address: endpoint address (IP or hostname) of the remote WireGuard server, if this is a client-mode peer. server_port: WireGuard UDP port (default 51820). psk: optional pre-shared key. keepalive: persistent keepalive seconds (0 = disabled)."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_wireguard_peer"}
    name = name.strip()
    if not public_key or not public_key.strip():
        return {"error": "public_key must not be empty", "tool": "add_wireguard_peer"}
    public_key = public_key.strip()
    if not tunnel_address or not tunnel_address.strip():
        return {"error": "tunnel_address must not be empty", "tool": "add_wireguard_peer"}
    tunnel_address = tunnel_address.strip()
    try:
        ipaddress.ip_network(tunnel_address, strict=False)
    except ValueError:
        return {"error": f"Invalid tunnel_address CIDR: '{tunnel_address}'", "tool": "add_wireguard_peer"}
    try:
        resp = await _request(
            "POST",
            "/wireguard/client/addClient",
            json={"client": {
                "enabled": "1",
                "name": name,
                "pubkey": public_key,
                "psk": psk.strip() if psk else "",
                "tunneladdress": tunnel_address,
                "serveraddress": server_address.strip() if server_address else "",
                "serverport": server_port.strip() if server_port else "51820",
                "keepalive": str(keepalive),
                "descr": description.strip(),
            }},
        )
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/wireguard/service/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_wireguard_peer", "detail": type(e).__name__}


@mcp.tool()
async def delete_wireguard_peer(uuid: str) -> dict:
    """Delete a WireGuard peer (client) by UUID and reconfigure WireGuard immediately. Use list_wireguard_peers to find the UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_wireguard_peer"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/wireguard/client/delClient/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/wireguard/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_wireguard_peer", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_wireguard_peer(uuid: str, name: str = "", public_key: str = "", tunnel_address: str = "", server_address: str = "", server_port: str = "", psk: str = "", keepalive: int = -1, description: str = "") -> dict:
    """Update an existing WireGuard peer (client) by UUID. Only non-empty/non-default fields are changed. keepalive: -1 = keep existing, 0 = disable keepalive, positive integer = seconds. Reconfigures WireGuard immediately. Use list_wireguard_peers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_wireguard_peer"}
    uuid = uuid.strip()
    if not any([name, public_key, tunnel_address, server_address, server_port, psk, keepalive >= 0, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_wireguard_peer"}
    if tunnel_address and tunnel_address.strip():
        try:
            ipaddress.ip_network(tunnel_address.strip(), strict=False)
        except ValueError:
            return {"error": f"Invalid tunnel_address CIDR: '{tunnel_address}'", "tool": "update_wireguard_peer"}
    if keepalive >= 0 and not (0 <= keepalive <= 3600):
        return {"error": f"keepalive must be 0-3600 seconds, got {keepalive}", "tool": "update_wireguard_peer"}
    try:
        get_resp = await _request("GET", f"/wireguard/client/getClient/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("client", {})
        if name:
            current["name"] = name.strip()
        if public_key:
            current["pubkey"] = public_key.strip()
        if tunnel_address:
            current["tunneladdress"] = tunnel_address.strip()
        if server_address:
            current["serveraddress"] = server_address.strip()
        if server_port:
            current["serverport"] = server_port.strip()
        if psk:
            current["psk"] = psk.strip()
        if keepalive >= 0:
            current["keepalive"] = str(keepalive)
        if description:
            current["descr"] = description.strip()
        resp = await _request("POST", f"/wireguard/client/setClient/{uuid}", json={"client": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/wireguard/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_wireguard_peer", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_wireguard_peer(uuid: str, enabled: str) -> dict:
    """Enable or disable a WireGuard peer (client) by UUID without changing other settings. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Reconfigures WireGuard immediately. Use list_wireguard_peers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_wireguard_peer"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_wireguard_peer"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/wireguard/client/getClient/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("client", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/wireguard/client/setClient/{uuid}", json={"client": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/wireguard/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_wireguard_peer", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_haproxy_server", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_haproxy_backend", "uuid": uuid, "detail": type(e).__name__}


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
        return {"error": str(e), "tool": "get_haproxy_frontend", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_haproxy_frontends() -> dict:
    """List all HAProxy frontend listeners configured in OPNsense — bind addresses, ACLs, and backend associations."""
    try:
        resp = await _request("GET", "/haproxy/frontend/searchFrontend")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_haproxy_frontends", "detail": type(e).__name__}


@mcp.tool()
async def add_haproxy_server(name: str, address: str, port: int, check_enabled: bool = True, weight: int = 1, description: str = "") -> dict:
    """Add a new HAProxy real server (backend member). name: server name. address: IP or hostname of the backend. port: backend port (1-65535). check_enabled: enable health checks (default True). weight: load balancing weight 1-256 (default 1). description: optional label. Reconfigures HAProxy immediately. Use list_haproxy_servers to verify and get the new UUID."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_haproxy_server"}
    if not address or not address.strip():
        return {"error": "address must not be empty", "tool": "add_haproxy_server"}
    if not (1 <= port <= 65535):
        return {"error": f"port must be 1-65535, got {port}", "tool": "add_haproxy_server"}
    if not (1 <= weight <= 256):
        return {"error": f"weight must be 1-256, got {weight}", "tool": "add_haproxy_server"}
    try:
        body: dict = {
            "server": {
                "name": name.strip(),
                "address": address.strip(),
                "port": str(port),
                "checkport": str(port),
                "check": "1" if check_enabled else "0",
                "weight": str(weight),
            }
        }
        if description:
            body["server"]["description"] = description.strip()
        resp = await _request("POST", "/haproxy/server/addServer", json=body)
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_haproxy_server", "detail": type(e).__name__}


@mcp.tool()
async def delete_haproxy_server(uuid: str) -> dict:
    """Delete a HAProxy real server entry by UUID and reconfigure HAProxy immediately. Remove the server from any backend pools first to avoid reference errors. Use list_haproxy_servers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_haproxy_server"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/haproxy/server/delServer/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_haproxy_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_haproxy_backend(name: str, algorithm: str = "round_robin", server_uuids: str = "", description: str = "") -> dict:
    """Create a new HAProxy backend pool. name: backend name. algorithm: load balancing — round_robin (default), leastconn, source, random. server_uuids: comma-separated real server UUIDs to add as members (use list_haproxy_servers; can be empty to add servers later via get_haproxy_backend + update). description: optional label. Reconfigures HAProxy immediately."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_haproxy_backend"}
    _VALID_ALGOS = {"round_robin", "leastconn", "source", "random"}
    algo = algorithm.strip().lower()
    if algo not in _VALID_ALGOS:
        return {"error": f"Invalid algorithm '{algo}'. Valid: {', '.join(sorted(_VALID_ALGOS))}", "tool": "add_haproxy_backend"}
    try:
        body: dict = {
            "backend": {
                "name": name.strip(),
                "algorithm": algo,
            }
        }
        if server_uuids and server_uuids.strip():
            uuids = [u.strip() for u in server_uuids.split(",") if u.strip()]
            body["backend"]["Servers"] = ",".join(uuids)
        if description:
            body["backend"]["description"] = description.strip()
        resp = await _request("POST", "/haproxy/backend/addBackend", json=body)
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_haproxy_backend", "detail": type(e).__name__}


@mcp.tool()
async def delete_haproxy_backend(uuid: str) -> dict:
    """Delete a HAProxy backend pool by UUID and reconfigure HAProxy immediately. Remove any frontend associations first to avoid reference errors. Use list_haproxy_backends to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_haproxy_backend"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/haproxy/backend/delBackend/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_haproxy_backend", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_haproxy_server(uuid: str, name: str = "", address: str = "", port: str = "", check_enabled: str = "", weight: str = "", description: str = "") -> dict:
    """Update an existing HAProxy real server by UUID. Only non-empty fields are changed. check_enabled: '1'/'true' to enable or '0'/'false' to disable health checks. Use list_haproxy_servers to find UUIDs. Reconfigures HAProxy immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_haproxy_server"}
    uuid = uuid.strip()
    if not any([name, address, port, check_enabled, weight, description]):
        return {"error": "At least one field must be specified", "tool": "update_haproxy_server"}
    if port and port.strip():
        try:
            p = int(port.strip())
            if not (1 <= p <= 65535):
                return {"error": f"port must be 1-65535, got {p}", "tool": "update_haproxy_server"}
        except ValueError:
            return {"error": f"port must be a number, got '{port}'", "tool": "update_haproxy_server"}
    if weight and weight.strip():
        try:
            w = int(weight.strip())
            if not (1 <= w <= 256):
                return {"error": f"weight must be 1-256, got {w}", "tool": "update_haproxy_server"}
        except ValueError:
            return {"error": f"weight must be a number, got '{weight}'", "tool": "update_haproxy_server"}
    try:
        get_resp = await _request("GET", f"/haproxy/server/getServer/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("server", {})
        if name: current["name"] = name.strip()
        if address: current["address"] = address.strip()
        if port: current["port"] = port.strip()
        if check_enabled:
            current["check"] = "1" if check_enabled.strip().lower() in ("1", "true", "yes") else "0"
        if weight: current["weight"] = weight.strip()
        if description: current["description"] = description.strip()
        resp = await _request("POST", f"/haproxy/server/setServer/{uuid}", json={"server": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_haproxy_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_haproxy_backend(uuid: str, name: str = "", algorithm: str = "", server_uuids: str = "", description: str = "") -> dict:
    """Update an existing HAProxy backend pool by UUID. Only non-empty fields are changed. algorithm: round_robin, leastconn, source, random. server_uuids: comma-separated real server UUIDs — replaces current member list; omit to keep existing servers. Use list_haproxy_backends to find UUIDs. Reconfigures HAProxy immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_haproxy_backend"}
    uuid = uuid.strip()
    if not any([name, algorithm, server_uuids, description]):
        return {"error": "At least one field must be specified", "tool": "update_haproxy_backend"}
    _VALID_ALGOS = {"round_robin", "leastconn", "source", "random"}
    if algorithm and algorithm.strip().lower() not in _VALID_ALGOS:
        return {"error": f"Invalid algorithm '{algorithm}'. Valid: {', '.join(sorted(_VALID_ALGOS))}", "tool": "update_haproxy_backend"}
    try:
        get_resp = await _request("GET", f"/haproxy/backend/getBackend/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("backend", {})
        if name: current["name"] = name.strip()
        if algorithm: current["algorithm"] = algorithm.strip().lower()
        if server_uuids:
            uuids = [u.strip() for u in server_uuids.split(",") if u.strip()]
            current["Servers"] = ",".join(uuids)
        if description: current["description"] = description.strip()
        resp = await _request("POST", f"/haproxy/backend/setBackend/{uuid}", json={"backend": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_haproxy_backend", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_haproxy_frontend(name: str, bind: str, default_backend_uuid: str = "", mode: str = "http", description: str = "") -> dict:
    """Add a new HAProxy frontend listener. name: frontend name. bind: listen address:port (e.g. '0.0.0.0:80' or '0.0.0.0:443'). default_backend_uuid: UUID of the default backend pool (use list_haproxy_backends; can be empty). mode: 'http' (default) or 'tcp'. description: optional label. Reconfigures HAProxy immediately."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_haproxy_frontend"}
    if not bind or not bind.strip():
        return {"error": "bind must not be empty", "tool": "add_haproxy_frontend"}
    mode_val = mode.strip().lower()
    if mode_val not in ("http", "tcp"):
        return {"error": "mode must be 'http' or 'tcp'", "tool": "add_haproxy_frontend"}
    try:
        body: dict = {
            "frontend": {
                "name": name.strip(),
                "bind": bind.strip(),
                "mode": mode_val,
            }
        }
        if default_backend_uuid and default_backend_uuid.strip():
            body["frontend"]["defaultBackend"] = default_backend_uuid.strip()
        if description:
            body["frontend"]["description"] = description.strip()
        resp = await _request("POST", "/haproxy/frontend/addFrontend", json=body)
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_haproxy_frontend", "detail": type(e).__name__}


@mcp.tool()
async def delete_haproxy_frontend(uuid: str) -> dict:
    """Delete a HAProxy frontend listener by UUID and reconfigure HAProxy immediately. Use list_haproxy_frontends to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_haproxy_frontend"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/haproxy/frontend/delFrontend/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_haproxy_frontend", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_haproxy_frontend(uuid: str, name: str = "", bind: str = "", default_backend_uuid: str = "", mode: str = "", description: str = "") -> dict:
    """Update an existing HAProxy frontend listener by UUID. Only non-empty fields are changed. mode: 'http' or 'tcp'. default_backend_uuid: UUID of default backend (use list_haproxy_backends). Use list_haproxy_frontends to find UUIDs. Reconfigures HAProxy immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_haproxy_frontend"}
    uuid = uuid.strip()
    if not any([name, bind, default_backend_uuid, mode, description]):
        return {"error": "At least one field must be specified", "tool": "update_haproxy_frontend"}
    if mode and mode.strip().lower() not in ("http", "tcp"):
        return {"error": "mode must be 'http' or 'tcp'", "tool": "update_haproxy_frontend"}
    try:
        get_resp = await _request("GET", f"/haproxy/frontend/getFrontend/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("frontend", {})
        if name: current["name"] = name.strip()
        if bind: current["bind"] = bind.strip()
        if default_backend_uuid: current["defaultBackend"] = default_backend_uuid.strip()
        if mode: current["mode"] = mode.strip().lower()
        if description: current["description"] = description.strip()
        resp = await _request("POST", f"/haproxy/frontend/setFrontend/{uuid}", json={"frontend": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_haproxy_frontend", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_haproxy_frontend(uuid: str, enabled: str) -> dict:
    """Enable or disable a HAProxy frontend listener by UUID without changing other settings. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Use list_haproxy_frontends to find UUIDs. Reconfigures HAProxy immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_haproxy_frontend"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_haproxy_frontend"}
    enabled_val = "1" if enabled.strip().lower() in ("1", "true", "yes") else "0"
    try:
        get_resp = await _request("GET", f"/haproxy/frontend/getFrontend/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("frontend", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/haproxy/frontend/setFrontend/{uuid}", json={"frontend": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_haproxy_frontend", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_wireguard_server(name: str, tunnel_address: str, port: int = 51820, dns: str = "", mtu: int = 1420, description: str = "") -> dict:
    """Create a new WireGuard VPN server instance. name: server name. tunnel_address: server tunnel address/CIDR (e.g. '10.0.0.1/24'). port: UDP listen port (default 51820). dns: optional comma-separated DNS server IPs for connected peers. mtu: interface MTU (default 1420). OPNsense auto-generates the server keypair — retrieve the public key via get_wireguard_server. Reconfigures WireGuard immediately."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_wireguard_server"}
    name = name.strip()
    if not tunnel_address or not tunnel_address.strip():
        return {"error": "tunnel_address must not be empty", "tool": "add_wireguard_server"}
    tunnel_address = tunnel_address.strip()
    try:
        ipaddress.ip_network(tunnel_address, strict=False)
    except ValueError:
        return {"error": f"Invalid tunnel_address CIDR: '{tunnel_address}'", "tool": "add_wireguard_server"}
    if not 1 <= port <= 65535:
        return {"error": f"Invalid port {port}: must be 1-65535", "tool": "add_wireguard_server"}
    if not 576 <= mtu <= 9000:
        return {"error": f"Invalid mtu {mtu}: must be 576-9000", "tool": "add_wireguard_server"}
    try:
        resp = await _request(
            "POST",
            "/wireguard/server/addServer",
            json={"server": {
                "enabled": "1",
                "name": name,
                "port": str(port),
                "mtu": str(mtu),
                "tunneladdress": tunnel_address,
                "dns": dns.strip() if dns else "",
                "descr": description.strip(),
                "disableroutes": "0",
                "peers": "",
            }},
        )
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/wireguard/service/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_wireguard_server", "detail": type(e).__name__}


@mcp.tool()
async def delete_wireguard_server(uuid: str) -> dict:
    """Delete a WireGuard VPN server instance by UUID and reconfigure WireGuard immediately. Use list_wireguard_servers to find the UUID."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_wireguard_server"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/wireguard/server/delServer/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/wireguard/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_wireguard_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_wireguard_server(uuid: str, enabled: str) -> dict:
    """Enable or disable a WireGuard VPN server instance by UUID without changing other settings. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Reconfigures WireGuard immediately. Use list_wireguard_servers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_wireguard_server"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_wireguard_server"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/wireguard/server/getServer/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("server", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/wireguard/server/setServer/{uuid}", json={"server": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/wireguard/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_wireguard_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_wireguard_server(uuid: str, name: str = "", tunnel_address: str = "", port: str = "", dns: str = "", mtu: str = "", description: str = "") -> dict:
    """Update an existing WireGuard VPN server by UUID. Only non-empty fields are changed. port: UDP listen port as string. mtu: MTU as string. Use list_wireguard_servers to find UUIDs. Reconfigures WireGuard immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_wireguard_server"}
    uuid = uuid.strip()
    if not any([name, tunnel_address, port, dns, mtu, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_wireguard_server"}
    if tunnel_address and tunnel_address.strip():
        try:
            ipaddress.ip_network(tunnel_address.strip(), strict=False)
        except ValueError:
            return {"error": f"Invalid tunnel_address CIDR: '{tunnel_address}'", "tool": "update_wireguard_server"}
    if port and port.strip():
        try:
            p = int(port.strip())
            if not 1 <= p <= 65535:
                raise ValueError
        except ValueError:
            return {"error": f"Invalid port '{port}': must be 1-65535", "tool": "update_wireguard_server"}
    if mtu and mtu.strip():
        try:
            m = int(mtu.strip())
            if not 576 <= m <= 9000:
                raise ValueError
        except ValueError:
            return {"error": f"Invalid mtu '{mtu}': must be 576-9000", "tool": "update_wireguard_server"}
    try:
        get_resp = await _request("GET", f"/wireguard/server/getServer/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("server", {})
        if name:
            current["name"] = name.strip()
        if tunnel_address:
            current["tunneladdress"] = tunnel_address.strip()
        if port:
            current["port"] = port.strip()
        if dns:
            current["dns"] = dns.strip()
        if mtu:
            current["mtu"] = mtu.strip()
        if description:
            current["descr"] = description.strip()
        resp = await _request("POST", f"/wireguard/server/setServer/{uuid}", json={"server": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/wireguard/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_wireguard_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_dhcp_ranges() -> dict:
    """List all configured DHCPv4 address pool ranges. Returns the start/end address range, associated interface, and enabled state for each pool. Complements list_static_leases and list_dhcp_leases with the configured pool definitions."""
    try:
        resp = await _request("GET", "/dhcpv4/settings/searchRange")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_dhcp_ranges", "detail": type(e).__name__}


@mcp.tool()
async def get_dhcp_range(uuid: str) -> dict:
    """Get a specific DHCPv4 address pool range by UUID. Returns start IP, end IP, interface, enabled state, and description. Use list_dhcp_ranges to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_dhcp_range"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/dhcpv4/settings/getRange/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_dhcp_range", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_dhcp_range(from_ip: str, to_ip: str, interface: str, description: str = "") -> dict:
    """Add a new DHCPv4 address pool range. from_ip: first IP in the pool (e.g. '192.168.1.100'). to_ip: last IP in the pool (e.g. '192.168.1.200'). interface: OPNsense interface name (e.g. 'lan'). description: optional label. Reconfigures DHCP immediately."""
    if not from_ip or not from_ip.strip():
        return {"error": "from_ip must not be empty", "tool": "add_dhcp_range"}
    if not to_ip or not to_ip.strip():
        return {"error": "to_ip must not be empty", "tool": "add_dhcp_range"}
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_dhcp_range"}
    from_ip = from_ip.strip()
    to_ip = to_ip.strip()
    interface = interface.strip()
    try:
        from_addr = ipaddress.IPv4Address(from_ip)
    except ValueError:
        return {"error": f"Invalid IPv4 address: '{from_ip}'", "tool": "add_dhcp_range"}
    try:
        to_addr = ipaddress.IPv4Address(to_ip)
    except ValueError:
        return {"error": f"Invalid IPv4 address: '{to_ip}'", "tool": "add_dhcp_range"}
    if from_addr >= to_addr:
        return {"error": f"from_ip ({from_ip}) must be less than to_ip ({to_ip})", "tool": "add_dhcp_range"}
    try:
        body: dict = {"range": {"from": from_ip, "to": to_ip, "interface": interface}}
        if description:
            body["range"]["description"] = description.strip()
        resp = await _request("POST", "/dhcpv4/settings/addRange", json=body)
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "add_dhcp_range", "detail": type(e).__name__}


@mcp.tool()
async def update_dhcp_range(uuid: str, from_ip: str = "", to_ip: str = "", interface: str = "", description: str = "") -> dict:
    """Update an existing DHCPv4 address pool range by UUID. Only non-empty fields are changed. Use list_dhcp_ranges to find UUIDs. Reconfigures DHCP immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_dhcp_range"}
    uuid = uuid.strip()
    if not any([from_ip, to_ip, interface, description]):
        return {"error": "At least one field must be specified", "tool": "update_dhcp_range"}
    if from_ip:
        try:
            ipaddress.IPv4Address(from_ip.strip())
        except ValueError:
            return {"error": f"Invalid IPv4 address: '{from_ip}'", "tool": "update_dhcp_range"}
    if to_ip:
        try:
            ipaddress.IPv4Address(to_ip.strip())
        except ValueError:
            return {"error": f"Invalid IPv4 address: '{to_ip}'", "tool": "update_dhcp_range"}
    try:
        get_resp = await _request("GET", f"/dhcpv4/settings/getRange/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("range", {})
        if from_ip:
            current["from"] = from_ip.strip()
        if to_ip:
            current["to"] = to_ip.strip()
        if interface:
            current["interface"] = interface.strip()
        if description:
            current["description"] = description.strip()
        resp = await _request("POST", f"/dhcpv4/settings/setRange/{uuid}", json={"range": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_dhcp_range", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def delete_dhcp_range(uuid: str) -> dict:
    """Delete a DHCPv4 address pool range by UUID and reconfigure DHCP immediately. Use list_dhcp_ranges to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_dhcp_range"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/dhcpv4/settings/delRange/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/dhcpv4/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_dhcp_range", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def flush_states() -> dict:
    """Flush the OPNsense firewall connection state table, removing all active NAT/firewall state entries. Useful after firewall rule changes that should affect established connections immediately. WARNING: this interrupts all active TCP sessions passing through the firewall."""
    try:
        resp = await _request("POST", "/diagnostics/firewall/flushStates")
        resp.raise_for_status()
        return {"result": {"flushed": True}}
    except Exception as e:
        return {"error": str(e), "tool": "flush_states", "detail": type(e).__name__}


@mcp.tool()
async def get_unbound_stats() -> dict:
    """Get Unbound DNS resolver statistics: total queries, cache hits, cache misses, prefetch counts, and uptime. Useful for monitoring DNS resolver performance and cache effectiveness."""
    try:
        resp = await _request("GET", "/unbound/diagnostics/stats")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_unbound_stats", "detail": type(e).__name__}


@mcp.tool()
async def toggle_ipsec_phase2(uuid: str, enabled: str) -> dict:
    """Enable or disable an IPsec Phase 2 (child SA / traffic selector) entry without changing encryption or selector settings. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Use list_ipsec_phase2 to find UUIDs. Reconfigures IPsec immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_ipsec_phase2"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_ipsec_phase2"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/ipsec/tunnels/getPhase2/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("phase2", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/ipsec/tunnels/setPhase2/{uuid}", json={"phase2": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/ipsec/tunnels/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_ipsec_phase2", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_ipsec_phase2(
    uuid: str,
    local_address: str = "",
    remote_address: str = "",
    protocol: str = "",
    proposal: str = "",
    lifetime: str = "",
    description: str = "",
) -> dict:
    """Update an existing IPsec Phase 2 (child SA / traffic selector) entry. Only provided fields are changed. Use list_ipsec_phase2 to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_ipsec_phase2"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/ipsec/tunnels/getPhase2/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("phase2", {})
        if local_address:
            if "localid" not in current:
                current["localid"] = {}
            current["localid"]["address"] = local_address.strip()
        if remote_address:
            if "remoteid" not in current:
                current["remoteid"] = {}
            current["remoteid"]["address"] = remote_address.strip()
        if protocol:
            current["protocol"] = protocol
        if proposal:
            current["proposal"] = proposal
        if lifetime:
            current["lifetime"] = lifetime
        if description:
            current["descr"] = description
        resp = await _request("POST", f"/ipsec/tunnels/setPhase2/{uuid}", json={"phase2": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/ipsec/tunnels/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_ipsec_phase2", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_openvpn_instance(
    role: str,
    description: str = "",
    protocol: str = "UDP4",
    port: int = 1194,
    tunnel_network: str = "",
    tunnel_network_v6: str = "",
    remote_network: str = "",
    server_cert_uuid: str = "",
    ca_uuid: str = "",
    dev_type: str = "tun",
) -> dict:
    """Add a new OpenVPN server or client instance. role: 'server' or 'client'. protocol: UDP4, UDP6, TCP4, TCP6. dev_type: tun (routed) or tap (bridged). server_cert_uuid / ca_uuid: certificate UUIDs from list_certificates. Returns UUID of created instance."""
    if not role or role.strip().lower() not in {"server", "client"}:
        return {"error": "role must be 'server' or 'client'", "tool": "add_openvpn_instance"}
    try:
        body = {
            "instance": {
                "role": role.strip().lower(),
                "description": description,
                "proto": protocol,
                "port": str(port),
                "dev_type": dev_type,
                "enabled": "1",
            }
        }
        if tunnel_network:
            body["instance"]["tunnel_network"] = tunnel_network.strip()
        if tunnel_network_v6:
            body["instance"]["tunnel_network_v6"] = tunnel_network_v6.strip()
        if remote_network:
            body["instance"]["remote_network"] = remote_network.strip()
        if server_cert_uuid:
            body["instance"]["cert"] = server_cert_uuid.strip()
        if ca_uuid:
            body["instance"]["ca"] = ca_uuid.strip()
        resp = await _request("POST", "/openvpn/instances/addInstance", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/openvpn/service/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_openvpn_instance", "detail": type(e).__name__}


@mcp.tool()
async def update_openvpn_instance(
    uuid: str,
    description: str = "",
    protocol: str = "",
    port: str = "",
    tunnel_network: str = "",
    remote_network: str = "",
    server_cert_uuid: str = "",
) -> dict:
    """Update an existing OpenVPN instance. Only provided fields are changed; others keep current values. Use list_openvpn_instances to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_openvpn_instance"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/openvpn/instances/getInstance/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("instance", {})
        if description:
            current["description"] = description
        if protocol:
            current["proto"] = protocol
        if port:
            current["port"] = port
        if tunnel_network:
            current["tunnel_network"] = tunnel_network.strip()
        if remote_network:
            current["remote_network"] = remote_network.strip()
        if server_cert_uuid:
            current["cert"] = server_cert_uuid.strip()
        resp = await _request("POST", f"/openvpn/instances/setInstance/{uuid}", json={"instance": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/openvpn/service/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_openvpn_instance", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_users() -> dict:
    """List all OPNsense system user accounts, including username, full name, scope, and enabled state."""
    try:
        resp = await _request("GET", "/core/user/searchUsers")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_users", "detail": type(e).__name__}


@mcp.tool()
async def get_user(uuid: str) -> dict:
    """Get the full configuration of an OPNsense system user account by UUID, including group memberships, certificates, and authentication settings. Use list_users to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_user"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/core/user/getUser/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_user", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_user(
    username: str,
    password: str,
    full_name: str = "",
    email: str = "",
    scope: str = "user",
    description: str = "",
) -> dict:
    """Add a new OPNsense system user account. username: login name (alphanumeric + underscore). password: plain text (stored hashed). scope: 'user' (standard) or 'system'. Returns UUID of created user."""
    if not username or not username.strip():
        return {"error": "username must not be empty", "tool": "add_user"}
    if not password:
        return {"error": "password must not be empty", "tool": "add_user"}
    try:
        body = {
            "user": {
                "name": username.strip(),
                "password": password,
                "full_name": full_name,
                "email": email,
                "scope": scope,
                "descr": description,
                "disabled": "0",
            }
        }
        resp = await _request("POST", "/core/user/addUser", json=body)
        resp.raise_for_status()
        data = resp.json()
        return {"result": {"uuid": data.get("uuid"), "response": data}}
    except Exception as e:
        return {"error": str(e), "tool": "add_user", "detail": type(e).__name__}


@mcp.tool()
async def delete_user(uuid: str) -> dict:
    """Delete an OPNsense system user account by UUID. WARNING: this is irreversible. Use list_users to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_user"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/core/user/delUser/{uuid}")
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_user", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_haproxy_server(uuid: str, enabled: str) -> dict:
    """Enable or disable an HAProxy real server entry. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies changes immediately. Use list_haproxy_servers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_haproxy_server"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_haproxy_server"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/haproxy/server/getServer/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("server", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/haproxy/server/setServer/{uuid}", json={"server": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1", "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_haproxy_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_haproxy_backend(uuid: str, enabled: str) -> dict:
    """Enable or disable an HAProxy backend pool. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies changes immediately. Use list_haproxy_backends to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_haproxy_backend"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_haproxy_backend"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/haproxy/backend/getBackend/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("backend", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/haproxy/backend/setBackend/{uuid}", json={"backend": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/haproxy/service/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1", "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_haproxy_backend", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_nat_binat() -> dict:
    """List all 1:1 NAT (bidirectional NAT / NAT reflection) rules configured in OPNsense. 1:1 NAT maps an external IP directly to an internal IP for both inbound and outbound traffic."""
    try:
        resp = await _request("GET", "/firewall/nat/oneToOne")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_nat_binat", "detail": type(e).__name__}


@mcp.tool()
async def list_openvpn_instances() -> dict:
    """List all configured OpenVPN server and client instances in OPNsense, including instance type, description, enabled state, device, and tunnel network. Different from get_openvpn_status which shows live session data."""
    try:
        resp = await _request("GET", "/openvpn/instances/searchInstances")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_openvpn_instances", "detail": type(e).__name__}


@mcp.tool()
async def get_openvpn_instance(uuid: str) -> dict:
    """Get the full configuration of a specific OpenVPN server or client instance by UUID. Returns protocol, port, tunnel network, device, certificate, cipher settings, and all other instance parameters. Use list_openvpn_instances to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_openvpn_instance"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/openvpn/instances/getInstance/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_openvpn_instance", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_ipsec_tunnel(
    remote_gateway: str,
    authentication_method: str = "pre_shared_key",
    ike_type: str = "ikev2",
    proposal: str = "aes256-sha256-modp2048",
    lifetime: int = 28800,
    description: str = "",
) -> dict:
    """Add a new IPsec Phase 1 (IKE) tunnel entry. remote_gateway: IP or hostname of the VPN peer. authentication_method: pre_shared_key or cert. ike_type: ikev1, ikev2, or ike. Returns the UUID of the created tunnel."""
    if not remote_gateway or not remote_gateway.strip():
        return {"error": "remote_gateway must not be empty", "tool": "add_ipsec_tunnel"}
    try:
        body = {
            "phase1": {
                "remote-gateway": remote_gateway.strip(),
                "authentication_method": authentication_method,
                "iketype": ike_type,
                "proposal": proposal,
                "lifetime": str(lifetime),
                "descr": description,
                "enabled": "1",
            }
        }
        resp = await _request("POST", "/ipsec/tunnels/addPhase1", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/ipsec/tunnels/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_ipsec_tunnel", "detail": type(e).__name__}


@mcp.tool()
async def update_ipsec_tunnel(
    uuid: str,
    remote_gateway: str = "",
    authentication_method: str = "",
    ike_type: str = "",
    proposal: str = "",
    lifetime: str = "",
    description: str = "",
) -> dict:
    """Update an existing IPsec Phase 1 tunnel. Only provided fields are changed; others keep their current values. Use list_ipsec_tunnels to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_ipsec_tunnel"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/ipsec/tunnels/getPhase1/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("phase1", {})
        if remote_gateway:
            current["remote-gateway"] = remote_gateway.strip()
        if authentication_method:
            current["authentication_method"] = authentication_method
        if ike_type:
            current["iketype"] = ike_type
        if proposal:
            current["proposal"] = proposal
        if lifetime:
            current["lifetime"] = lifetime
        if description:
            current["descr"] = description
        resp = await _request("POST", f"/ipsec/tunnels/setPhase1/{uuid}", json={"phase1": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/ipsec/tunnels/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_ipsec_tunnel", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_ipsec_phase2(
    phase1_uuid: str,
    local_address: str,
    remote_address: str,
    protocol: str = "esp",
    proposal: str = "aes256-sha256",
    lifetime: int = 3600,
    description: str = "",
) -> dict:
    """Add an IPsec Phase 2 (child SA / traffic selector) entry linked to a Phase 1 tunnel. phase1_uuid: UUID of the parent Phase 1 tunnel from list_ipsec_tunnels. local_address / remote_address: subnet CIDRs (e.g. 192.168.1.0/24). protocol: esp or ah."""
    if not phase1_uuid or not phase1_uuid.strip():
        return {"error": "phase1_uuid must not be empty", "tool": "add_ipsec_phase2"}
    if not local_address or not local_address.strip():
        return {"error": "local_address must not be empty", "tool": "add_ipsec_phase2"}
    if not remote_address or not remote_address.strip():
        return {"error": "remote_address must not be empty", "tool": "add_ipsec_phase2"}
    try:
        body = {
            "phase2": {
                "ikeid": phase1_uuid.strip(),
                "localid": {"address": local_address.strip()},
                "remoteid": {"address": remote_address.strip()},
                "protocol": protocol,
                "proposal": proposal,
                "lifetime": str(lifetime),
                "descr": description,
                "enabled": "1",
            }
        }
        resp = await _request("POST", "/ipsec/tunnels/addPhase2", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/ipsec/tunnels/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_ipsec_phase2", "detail": type(e).__name__}


@mcp.tool()
async def toggle_openvpn_instance(uuid: str, enabled: str) -> dict:
    """Enable or disable an OpenVPN server or client instance. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_openvpn_instance"}
    uuid = uuid.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_openvpn_instance"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        get_resp = await _request("GET", f"/openvpn/instances/getInstance/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("instance", {})
        current["enabled"] = enabled_val
        resp = await _request("POST", f"/openvpn/instances/setInstance/{uuid}", json={"instance": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/openvpn/service/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1", "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_openvpn_instance", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def delete_openvpn_instance(uuid: str) -> dict:
    """Delete an OpenVPN server or client instance by UUID and apply changes. WARNING: active connections will be dropped. Use list_openvpn_instances to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_openvpn_instance"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/openvpn/instances/delInstance/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/openvpn/service/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_openvpn_instance", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def delete_ipsec_tunnel(uuid: str) -> dict:
    """Delete an IPsec Phase 1 (IKE) tunnel configuration entry by UUID and apply changes immediately. This also removes any associated Phase 2 (child SA) entries. Use list_ipsec_tunnels to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_ipsec_tunnel"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/ipsec/tunnels/delPhase1/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/ipsec/tunnels/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_ipsec_tunnel", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def delete_ipsec_phase2(uuid: str) -> dict:
    """Delete an IPsec Phase 2 (child SA / traffic selector) entry by UUID and apply changes immediately. Use list_ipsec_phase2 to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_ipsec_phase2"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/ipsec/tunnels/delPhase2/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/ipsec/tunnels/reconfigure")
        reconf.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_ipsec_phase2", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_user(
    uuid: str,
    full_name: str = "",
    email: str = "",
    password: str = "",
    description: str = "",
) -> dict:
    """Update an existing OPNsense system user account. Only provided fields are changed. Use list_users to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_user"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/core/user/getUser/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("user", {})
        if full_name:
            current["full_name"] = full_name
        if email:
            current["email"] = email
        if password:
            current["password"] = password
        if description:
            current["descr"] = description
        resp = await _request("POST", f"/core/user/setUser/{uuid}", json={"user": current})
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "update_user", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_groups() -> dict:
    """List all OPNsense system user groups, including group name, scope, and member count. Groups control which users have access to which parts of the system."""
    try:
        resp = await _request("GET", "/core/user/searchGroups")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_groups", "detail": type(e).__name__}


@mcp.tool()
async def add_nat_binat(
    external_ip: str,
    internal_ip: str,
    interface: str,
    description: str = "",
) -> dict:
    """Add a 1:1 NAT (bidirectional NAT) rule that maps a single external IP to a single internal IP. external_ip: public IP address. internal_ip: private IP address. interface: WAN interface name (e.g. 'wan'). Applies changes immediately."""
    if not external_ip or not external_ip.strip():
        return {"error": "external_ip must not be empty", "tool": "add_nat_binat"}
    external_ip = external_ip.strip()
    if not internal_ip or not internal_ip.strip():
        return {"error": "internal_ip must not be empty", "tool": "add_nat_binat"}
    internal_ip = internal_ip.strip()
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_nat_binat"}
    try:
        ipaddress.IPv4Address(external_ip)
    except ValueError:
        return {"error": f"Invalid external_ip: '{external_ip}' is not a valid IPv4 address", "tool": "add_nat_binat"}
    try:
        ipaddress.IPv4Address(internal_ip)
    except ValueError:
        return {"error": f"Invalid internal_ip: '{internal_ip}' is not a valid IPv4 address", "tool": "add_nat_binat"}
    try:
        body = {
            "rule": {
                "interface": interface.strip(),
                "external": external_ip.strip(),
                "internal": internal_ip.strip(),
                "descr": description,
                "enabled": "1",
            }
        }
        resp = await _request("POST", "/firewall/nat/addOneToOne", json=body)
        resp.raise_for_status()
        data = resp.json()
        apply = await _request("POST", "/firewall/nat/apply")
        return {"result": {"uuid": data.get("uuid"), "response": data, "applied": apply.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_nat_binat", "detail": type(e).__name__}


@mcp.tool()
async def delete_nat_binat(uuid: str) -> dict:
    """Delete a 1:1 NAT rule by UUID and apply changes immediately. Use list_nat_binat to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_nat_binat"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/firewall/nat/delOneToOne/{uuid}")
        resp.raise_for_status()
        apply = await _request("POST", "/firewall/nat/apply")
        return {"result": {"uuid": uuid, "deleted": True, "applied": apply.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_nat_binat", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_plugins() -> dict:
    """List all available OPNsense plugins/packages with their installation status, version, and description. Use this to discover what can be installed or to check which plugins are currently active."""
    try:
        resp = await _request("GET", "/core/firmware/plugins")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_plugins", "detail": type(e).__name__}


@mcp.tool()
async def check_firmware_updates() -> dict:
    """Trigger a live check for available OPNsense firmware updates. Unlike get_firmware_status which returns cached data, this actively contacts the update server. May take several seconds. Returns current version and list of available updates."""
    try:
        resp = await _request("POST", "/core/firmware/check")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "check_firmware_updates", "detail": type(e).__name__}


@mcp.tool()
async def install_plugin(package_name: str) -> dict:
    """Install an OPNsense plugin/package by name (e.g. 'os-nginx', 'os-haproxy', 'os-wireguard'). Use list_plugins to see available package names. The installation runs in the background; use get_firmware_status to monitor progress."""
    if not package_name or not package_name.strip():
        return {"error": "package_name must not be empty", "tool": "install_plugin"}
    package_name = package_name.strip()
    try:
        resp = await _request("POST", f"/core/firmware/install/{package_name}")
        resp.raise_for_status()
        return {"result": {"package": package_name, "response": resp.json(), "note": "Installation runs in background — use get_firmware_status to monitor"}}
    except Exception as e:
        return {"error": str(e), "tool": "install_plugin", "detail": type(e).__name__}


@mcp.tool()
async def remove_plugin(package_name: str) -> dict:
    """Remove an installed OPNsense plugin/package by name (e.g. 'os-nginx'). Use list_plugins to find installed package names. Removal runs in the background."""
    if not package_name or not package_name.strip():
        return {"error": "package_name must not be empty", "tool": "remove_plugin"}
    package_name = package_name.strip()
    try:
        resp = await _request("POST", f"/core/firmware/remove/{package_name}")
        resp.raise_for_status()
        return {"result": {"package": package_name, "response": resp.json(), "note": "Removal runs in background — use get_firmware_status to monitor"}}
    except Exception as e:
        return {"error": str(e), "tool": "remove_plugin", "detail": type(e).__name__}


@mcp.tool()
async def add_group(name: str, description: str = "") -> dict:
    """Add a new OPNsense system user group. name: group name used in privilege assignments. Returns UUID of created group."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_group"}
    try:
        body = {"group": {"name": name.strip(), "description": description, "scope": "system"}}
        resp = await _request("POST", "/core/user/addGroup", json=body)
        resp.raise_for_status()
        data = resp.json()
        return {"result": {"uuid": data.get("uuid"), "response": data}}
    except Exception as e:
        return {"error": str(e), "tool": "add_group", "detail": type(e).__name__}


@mcp.tool()
async def delete_group(uuid: str) -> dict:
    """Delete an OPNsense system user group by UUID. WARNING: users in this group will lose any group-based privileges. Use list_groups to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_group"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/core/user/delGroup/{uuid}")
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_group", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_group(uuid: str) -> dict:
    """Get the full configuration of an OPNsense user group by UUID, including name, scope, and member privileges. Use list_groups to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_group"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/core/user/getGroup/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_group", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_group(uuid: str, name: str = "", description: str = "") -> dict:
    """Update an OPNsense user group name or description. Only provided fields are changed. Use list_groups to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_group"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/core/user/getGroup/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("group", {})
        if name:
            current["name"] = name.strip()
        if description:
            current["description"] = description
        resp = await _request("POST", f"/core/user/setGroup/{uuid}", json={"group": current})
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "update_group", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_nat_binat(uuid: str) -> dict:
    """Get the full configuration of a 1:1 NAT rule by UUID. Returns interface, external IP, internal IP, and enabled state. Use list_nat_binat to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_nat_binat"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/firewall/nat/getOneToOne/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_nat_binat", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_ids_rulesets() -> dict:
    """List all IDS/IPS (Suricata) rule sets available in OPNsense, including whether each ruleset is enabled and its description. Use this to discover which threat intelligence feeds and rule collections are available."""
    try:
        resp = await _request("GET", "/ids/settings/listRulesets")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_ids_rulesets", "detail": type(e).__name__}


@mcp.tool()
async def toggle_ids_ruleset(filename: str, enabled: str) -> dict:
    """Enable or disable an IDS/IPS (Suricata) rule set by its filename (e.g. 'emerging-malware.rules'). enabled: '1'/'true'/'yes' or '0'/'false'/'no'. Use list_ids_rulesets to find filenames. Requires IDS service restart to take effect."""
    if not filename or not filename.strip():
        return {"error": "filename must not be empty", "tool": "toggle_ids_ruleset"}
    filename = filename.strip()
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_ids_ruleset"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        resp = await _request("POST", f"/ids/settings/toggleRuleset/{filename}", json={"enabled": enabled_val})
        resp.raise_for_status()
        return {"result": {"filename": filename, "enabled": enabled_val == "1", "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_ids_ruleset", "detail": type(e).__name__}


@mcp.tool()
async def update_nat_binat(
    uuid: str,
    external_ip: str = "",
    internal_ip: str = "",
    interface: str = "",
    description: str = "",
) -> dict:
    """Update an existing 1:1 NAT rule. Only provided fields are changed. Use list_nat_binat to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_nat_binat"}
    uuid = uuid.strip()
    if external_ip and external_ip.strip():
        try:
            ipaddress.IPv4Address(external_ip.strip())
        except ValueError:
            return {"error": f"Invalid external_ip: '{external_ip}' is not a valid IPv4 address", "tool": "update_nat_binat"}
    if internal_ip and internal_ip.strip():
        try:
            ipaddress.IPv4Address(internal_ip.strip())
        except ValueError:
            return {"error": f"Invalid internal_ip: '{internal_ip}' is not a valid IPv4 address", "tool": "update_nat_binat"}
    try:
        get_resp = await _request("GET", f"/firewall/nat/getOneToOne/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("rule", {})
        if external_ip:
            current["external"] = external_ip.strip()
        if internal_ip:
            current["internal"] = internal_ip.strip()
        if interface:
            current["interface"] = interface.strip()
        if description:
            current["descr"] = description
        resp = await _request("POST", f"/firewall/nat/setOneToOne/{uuid}", json={"rule": current})
        resp.raise_for_status()
        apply = await _request("POST", "/firewall/nat/apply")
        return {"result": {"uuid": uuid, "response": resp.json(), "applied": apply.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_nat_binat", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def restart_ids() -> dict:
    """Restart the Intrusion Detection System (Suricata). Required after enabling/disabling rule sets with toggle_ids_ruleset to apply the changes. Also useful to recover from IDS crashes."""
    try:
        resp = await _request("POST", "/ids/service/restart")
        resp.raise_for_status()
        return {"result": {"restarted": True, "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "restart_ids", "detail": type(e).__name__}


@mcp.tool()
async def list_syslog_destinations() -> dict:
    """List all remote syslog destinations configured in OPNsense. Each destination is a remote server that receives forwarded log messages."""
    try:
        resp = await _request("GET", "/syslog/settings/searchDestinations")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_syslog_destinations", "detail": type(e).__name__}


@mcp.tool()
async def add_syslog_destination(
    hostname: str,
    port: int = 514,
    transport: str = "udp4",
    level: str = "debug",
    program: str = "",
    description: str = "",
) -> dict:
    """Add a remote syslog destination. hostname: IP or hostname of syslog server. transport: udp4, udp6, tcp4, tcp6, tls4, or tls6. level: minimum severity (debug, info, notice, warning, err, crit, alert, emerg). program: optional filter by program name."""
    if not hostname or not hostname.strip():
        return {"error": "hostname must not be empty", "tool": "add_syslog_destination"}
    valid_transports = {"udp4", "udp6", "tcp4", "tcp6", "tls4", "tls6"}
    if transport not in valid_transports:
        return {"error": f"transport must be one of: {', '.join(sorted(valid_transports))}", "tool": "add_syslog_destination"}
    try:
        body = {
            "destination": {
                "hostname": hostname.strip(),
                "port": str(port),
                "transport": transport,
                "level": level,
                "program": program,
                "description": description,
                "enabled": "1",
            }
        }
        resp = await _request("POST", "/syslog/settings/addDestination", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/syslog/service/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_syslog_destination", "detail": type(e).__name__}


@mcp.tool()
async def delete_syslog_destination(uuid: str) -> dict:
    """Delete a remote syslog destination by UUID and apply changes immediately. Use list_syslog_destinations to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_syslog_destination"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/syslog/settings/delDestination/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/syslog/service/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_syslog_destination", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_syslog_destination(uuid: str) -> dict:
    """Get the full configuration of a remote syslog destination by UUID. Use list_syslog_destinations to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_syslog_destination"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/syslog/settings/getDestination/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_syslog_destination", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_syslog_destination(
    uuid: str,
    hostname: str = "",
    port: str = "",
    transport: str = "",
    level: str = "",
    description: str = "",
) -> dict:
    """Update an existing remote syslog destination. Only provided fields are changed. Use list_syslog_destinations to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_syslog_destination"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/syslog/settings/getDestination/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("destination", {})
        if hostname:
            current["hostname"] = hostname.strip()
        if port:
            current["port"] = port
        if transport:
            current["transport"] = transport
        if level:
            current["level"] = level
        if description:
            current["description"] = description
        resp = await _request("POST", f"/syslog/settings/setDestination/{uuid}", json={"destination": current})
        resp.raise_for_status()
        reconf = await _request("POST", "/syslog/service/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_syslog_destination", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_ntp_servers() -> dict:
    """List all NTP servers configured in OPNsense for time synchronization. Returns hostname, poll interval, and peer status for each server."""
    try:
        resp = await _request("GET", "/ntp/settings/searchServer")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_ntp_servers", "detail": type(e).__name__}


@mcp.tool()
async def add_ntp_server(
    hostname: str,
    prefer: bool = False,
    iburst: bool = True,
    minpoll: int = 6,
    maxpoll: int = 10,
) -> dict:
    """Add an NTP server for time synchronization. hostname: NTP server hostname or IP (e.g. 'pool.ntp.org', '0.opnsense.pool.ntp.org'). prefer: treat as preferred source. iburst: send burst of 8 packets on startup for faster sync. minpoll/maxpoll: minimum/maximum polling interval as power of 2 (seconds = 2^n)."""
    if not hostname or not hostname.strip():
        return {"error": "hostname must not be empty", "tool": "add_ntp_server"}
    try:
        body = {
            "server": {
                "hostname": hostname.strip(),
                "prefer": "1" if prefer else "0",
                "iburst": "1" if iburst else "0",
                "minpoll": str(minpoll),
                "maxpoll": str(maxpoll),
                "type": "server",
            }
        }
        resp = await _request("POST", "/ntp/settings/addServer", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/ntp/service/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_ntp_server", "detail": type(e).__name__}


@mcp.tool()
async def delete_ntp_server(uuid: str) -> dict:
    """Delete an NTP server by UUID and apply changes immediately. Use list_ntp_servers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_ntp_server"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/ntp/settings/delServer/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/ntp/service/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_ntp_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def import_certificate(
    name: str,
    crt_pem: str,
    prv_pem: str = "",
    ca_pem: str = "",
) -> dict:
    """Import a certificate into the OPNsense trust store from PEM-encoded strings. name: display name. crt_pem: PEM certificate (-----BEGIN CERTIFICATE-----). prv_pem: PEM private key (required for server certificates). ca_pem: optional PEM CA chain to include."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "import_certificate"}
    if not crt_pem or not crt_pem.strip():
        return {"error": "crt_pem must not be empty", "tool": "import_certificate"}
    try:
        body = {
            "cert": {
                "descr": name.strip(),
                "crt": crt_pem.strip(),
                "type": "server",
            }
        }
        if prv_pem:
            body["cert"]["prv"] = prv_pem.strip()
        if ca_pem:
            body["cert"]["ca_crt"] = ca_pem.strip()
        resp = await _request("POST", "/trust/cert/addCert", json=body)
        resp.raise_for_status()
        data = resp.json()
        return {"result": {"uuid": data.get("uuid"), "response": data}}
    except Exception as e:
        return {"error": str(e), "tool": "import_certificate", "detail": type(e).__name__}


@mcp.tool()
async def get_ntp_server(uuid: str) -> dict:
    """Get configuration for a specific NTP server by UUID. Returns hostname, poll intervals, and flags. Use list_ntp_servers to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_ntp_server"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/ntp/settings/getServer/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ntp_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_ntp_server(
    uuid: str,
    hostname: str = "",
    prefer: bool = False,
    iburst: bool = True,
    minpoll: int = 6,
    maxpoll: int = 10,
) -> dict:
    """Update an NTP server configuration and apply immediately. Fetches current config first and merges changes. uuid: from list_ntp_servers. hostname: leave empty to keep current. prefer: treat as preferred time source. iburst: send burst on startup for faster sync. minpoll/maxpoll: polling interval as power-of-2 exponent (2^n seconds)."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_ntp_server"}
    uuid = uuid.strip()
    try:
        cur_resp = await _request("GET", f"/ntp/settings/getServer/{uuid}")
        cur_resp.raise_for_status()
        cur = cur_resp.json().get("server", {})
        body = {
            "server": {
                "hostname": hostname.strip() if hostname.strip() else cur.get("hostname", ""),
                "prefer": "1" if prefer else "0",
                "iburst": "1" if iburst else "0",
                "minpoll": str(minpoll),
                "maxpoll": str(maxpoll),
                "type": cur.get("type", "server"),
            }
        }
        resp = await _request("POST", f"/ntp/settings/setServer/{uuid}", json=body)
        resp.raise_for_status()
        reconf = await _request("POST", "/ntp/service/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_ntp_server", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def generate_self_signed_cert(
    name: str,
    common_name: str,
    lifetime_days: int = 397,
    key_type: str = "RSA",
    key_length: int = 2048,
    digest_alg: str = "sha256",
    san: str = "",
) -> dict:
    """Generate a self-signed certificate in the OPNsense trust store. name: display name. common_name: CN field (e.g. 'myserver.local'). lifetime_days: validity period (default 397 = ~13 months, browser-trust max). key_type: RSA or ECDSA. key_length: RSA key size in bits (2048 or 4096). digest_alg: sha256 or sha512. san: space-separated Subject Alternative Names (e.g. 'DNS:myserver.local IP:192.168.1.1')."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "generate_self_signed_cert"}
    if not common_name or not common_name.strip():
        return {"error": "common_name must not be empty", "tool": "generate_self_signed_cert"}
    key_type = key_type.strip().upper()
    if key_type not in ("RSA", "ECDSA"):
        return {"error": "key_type must be RSA or ECDSA", "tool": "generate_self_signed_cert"}
    try:
        body: dict = {
            "cert": {
                "descr": name.strip(),
                "type": "self-signed",
                "keytype": key_type,
                "keylen": str(key_length),
                "digest_alg": digest_alg.lower().strip(),
                "lifetime": str(lifetime_days),
                "dn_commonname": common_name.strip(),
            }
        }
        if san.strip():
            body["cert"]["altnames"] = san.strip()
        resp = await _request("POST", "/trust/cert/addCert", json=body)
        resp.raise_for_status()
        data = resp.json()
        return {"result": {"uuid": data.get("uuid"), "response": data}}
    except Exception as e:
        return {"error": str(e), "tool": "generate_self_signed_cert", "detail": type(e).__name__}


@mcp.tool()
async def start_ids() -> dict:
    """Start the IDS/IPS (Suricata) service. Use restart_ids to restart or stop_ids to stop."""
    try:
        resp = await _request("POST", "/ids/service/start")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "start_ids", "detail": type(e).__name__}


@mcp.tool()
async def stop_ids() -> dict:
    """Stop the IDS/IPS (Suricata) service. Use start_ids to start or restart_ids to restart."""
    try:
        resp = await _request("POST", "/ids/service/stop")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "stop_ids", "detail": type(e).__name__}


@mcp.tool()
async def list_gateway_groups() -> dict:
    """List all gateway groups configured for failover and load balancing. Returns group name, trigger level, and member gateways with their priority tiers."""
    try:
        resp = await _request("GET", "/routes/gateway/searchGatewayGroup")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_gateway_groups", "detail": type(e).__name__}


@mcp.tool()
async def list_captive_portal_zones() -> dict:
    """List all captive portal zones configured in OPNsense. Returns zone name, interface, authentication method, and enabled state."""
    try:
        resp = await _request("GET", "/captiveportal/zones/searchZone")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_captive_portal_zones", "detail": type(e).__name__}


@mcp.tool()
async def list_captive_portal_sessions(zone_id: str = "") -> dict:
    """List active captive portal sessions (authenticated clients). zone_id: optional zone UUID to filter (from list_captive_portal_zones); omit to list all zones' sessions."""
    try:
        path = f"/captiveportal/session/searchSession"
        params: dict = {}
        if zone_id.strip():
            params["zoneid"] = zone_id.strip()
        resp = await _request("GET", path, params=params if params else None)
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_captive_portal_sessions", "detail": type(e).__name__}


@mcp.tool()
async def disconnect_captive_portal_client(session_id: str, zone_id: str) -> dict:
    """Disconnect a client from the captive portal, revoking their internet access. session_id: session ID from list_captive_portal_sessions. zone_id: zone UUID the session belongs to."""
    if not session_id or not session_id.strip():
        return {"error": "session_id must not be empty", "tool": "disconnect_captive_portal_client"}
    if not zone_id or not zone_id.strip():
        return {"error": "zone_id must not be empty", "tool": "disconnect_captive_portal_client"}
    try:
        body = {"sessionId": session_id.strip(), "zoneid": zone_id.strip()}
        resp = await _request("POST", "/captiveportal/session/disconnect", json=body)
        resp.raise_for_status()
        return {"result": {"session_id": session_id, "disconnected": True, "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "disconnect_captive_portal_client", "detail": type(e).__name__}


@mcp.tool()
async def get_ids_settings() -> dict:
    """Get global IDS/IPS (Suricata) settings: enabled state, detection mode (IDS vs IPS), interface, log settings, and pattern matcher."""
    try:
        resp = await _request("GET", "/ids/settings/getSettings")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ids_settings", "detail": type(e).__name__}


@mcp.tool()
async def toggle_ids_service(enable: bool) -> dict:
    """Enable or disable the IDS/IPS (Suricata) service globally. Fetches current settings and toggles the enabled flag, then reconfigures. enable: True to enable, False to disable."""
    try:
        cur_resp = await _request("GET", "/ids/settings/getSettings")
        cur_resp.raise_for_status()
        settings = cur_resp.json()
        if "ids" not in settings:
            settings = {"ids": settings}
        settings["ids"]["enabled"] = "1" if enable else "0"
        resp = await _request("POST", "/ids/settings/setSettings", json=settings)
        resp.raise_for_status()
        reconf = await _request("POST", "/ids/service/reconfigure")
        return {"result": {"enabled": enable, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_ids_service", "detail": type(e).__name__}


@mcp.tool()
async def get_captive_portal_zone(uuid: str) -> dict:
    """Get configuration for a specific captive portal zone by UUID. Returns interface, authentication method, idle/session timeouts, and bandwidth limits. Use list_captive_portal_zones to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_captive_portal_zone"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/captiveportal/zones/getZone/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_captive_portal_zone", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_traffic_shaper_pipes() -> dict:
    """List all traffic shaper pipes (bandwidth limiters). Pipes define maximum bandwidth for a traffic class and are referenced by queues and rules."""
    try:
        resp = await _request("GET", "/trafficshaper/pipe/searchPipe")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_traffic_shaper_pipes", "detail": type(e).__name__}


@mcp.tool()
async def list_traffic_shaper_queues() -> dict:
    """List all traffic shaper queues. Queues subdivide pipe bandwidth into priority classes and are applied to specific traffic flows via shaper rules."""
    try:
        resp = await _request("GET", "/trafficshaper/queue/searchQueue")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_traffic_shaper_queues", "detail": type(e).__name__}


@mcp.tool()
async def get_traffic_shaper_pipe(uuid: str) -> dict:
    """Get details of a single traffic shaper pipe by UUID. Returns full config including bandwidth, metric, delay, and description. Use list_traffic_shaper_pipes to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_traffic_shaper_pipe"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/trafficshaper/pipe/getPipe/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_traffic_shaper_pipe", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_traffic_shaper_queue(uuid: str) -> dict:
    """Get details of a single traffic shaper queue by UUID. Returns full config including parent pipe UUID, weight, and description. Use list_traffic_shaper_queues to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_traffic_shaper_queue"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/trafficshaper/queue/getQueue/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_traffic_shaper_queue", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_ids_alerts(
    search: str = "",
    page: int = 1,
    limit: int = 50,
) -> dict:
    """List IDS/IPS (Suricata) alerts and detections. search: optional filter string. page: result page number. limit: results per page (max 200)."""
    limit = min(max(1, limit), 200)
    try:
        params: dict = {
            "current": page,
            "rowCount": limit,
        }
        if search.strip():
            params["searchPhrase"] = search.strip()
        resp = await _request("GET", "/ids/alerts/searchAlert", params=params)
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_ids_alerts", "detail": type(e).__name__}


@mcp.tool()
async def flush_ids_alerts() -> dict:
    """Clear all IDS/IPS (Suricata) alerts from the log. This is irreversible. Use list_ids_alerts to review before flushing."""
    try:
        resp = await _request("POST", "/ids/alerts/flushAlerts")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "flush_ids_alerts", "detail": type(e).__name__}


@mcp.tool()
async def add_traffic_shaper_pipe(
    bandwidth: int,
    bandwidth_metric: str = "Mbit",
    delay: int = 0,
    description: str = "",
) -> dict:
    """Add a traffic shaper pipe (bandwidth limiter). bandwidth: maximum throughput value. bandwidth_metric: Kbit, Mbit, or Gbit. delay: artificial delay in milliseconds (0 = none). Apply rules after adding to take effect."""
    if bandwidth <= 0:
        return {"error": "bandwidth must be > 0", "tool": "add_traffic_shaper_pipe"}
    bandwidth_metric = bandwidth_metric.strip()
    if bandwidth_metric not in ("Kbit", "Mbit", "Gbit"):
        return {"error": "bandwidth_metric must be Kbit, Mbit, or Gbit", "tool": "add_traffic_shaper_pipe"}
    try:
        body = {
            "pipe": {
                "bandwidth": str(bandwidth),
                "bandwidthmetric": bandwidth_metric,
                "delay": str(delay),
                "plr": "0",
                "description": description.strip(),
            }
        }
        resp = await _request("POST", "/trafficshaper/pipe/addPipe", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_traffic_shaper_pipe", "detail": type(e).__name__}


@mcp.tool()
async def delete_traffic_shaper_pipe(uuid: str) -> dict:
    """Delete a traffic shaper pipe by UUID. Removes the bandwidth limiter and all associated queues. Use list_traffic_shaper_pipes to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_traffic_shaper_pipe"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/trafficshaper/pipe/delPipe/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_traffic_shaper_pipe", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_traffic_shaper_rules() -> dict:
    """List all traffic shaper rules that classify traffic to pipes and queues. Returns match criteria (protocol, source/dest IP/port) and the assigned pipe or queue for each rule."""
    try:
        resp = await _request("GET", "/trafficshaper/rules/searchRule")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_traffic_shaper_rules", "detail": type(e).__name__}


@mcp.tool()
async def get_traffic_shaper_rule(uuid: str) -> dict:
    """Get details of a single traffic shaper classification rule by UUID. Returns match criteria (protocol, src/dst IP/port) and assigned pipe/queue. Use list_traffic_shaper_rules to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_traffic_shaper_rule"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/trafficshaper/rules/getRule/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_traffic_shaper_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_traffic_shaper_queue(
    pipe_uuid: str,
    weight: int = 100,
    description: str = "",
) -> dict:
    """Add a traffic shaper queue under an existing pipe. Queues subdivide pipe bandwidth by weight for priority traffic classes. pipe_uuid: UUID of the parent pipe from list_traffic_shaper_pipes. weight: relative priority weight (higher = more bandwidth share)."""
    if not pipe_uuid or not pipe_uuid.strip():
        return {"error": "pipe_uuid must not be empty", "tool": "add_traffic_shaper_queue"}
    if weight <= 0:
        return {"error": "weight must be > 0", "tool": "add_traffic_shaper_queue"}
    try:
        body = {
            "queue": {
                "pipe": pipe_uuid.strip(),
                "weight": str(weight),
                "description": description.strip(),
            }
        }
        resp = await _request("POST", "/trafficshaper/queue/addQueue", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_traffic_shaper_queue", "detail": type(e).__name__}


@mcp.tool()
async def delete_traffic_shaper_queue(uuid: str) -> dict:
    """Delete a traffic shaper queue by UUID. Use list_traffic_shaper_queues to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_traffic_shaper_queue"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/trafficshaper/queue/delQueue/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_traffic_shaper_queue", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_traffic_shaper_queue(
    uuid: str,
    weight: int = 0,
    pipe_uuid: str = "",
    description: str = "",
) -> dict:
    """Update a traffic shaper queue. Fetches current config and merges provided changes. uuid: from list_traffic_shaper_queues. weight: new priority weight (0 = keep current). pipe_uuid: move queue to a different pipe (empty = keep current). description: empty = keep current."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_traffic_shaper_queue"}
    uuid = uuid.strip()
    try:
        cur_resp = await _request("GET", f"/trafficshaper/queue/getQueue/{uuid}")
        cur_resp.raise_for_status()
        cur = cur_resp.json().get("queue", {})
        body = {
            "queue": {
                "pipe": pipe_uuid.strip() if pipe_uuid.strip() else cur.get("pipe", ""),
                "weight": str(weight) if weight > 0 else cur.get("weight", "100"),
                "description": description.strip() if description.strip() else cur.get("description", ""),
            }
        }
        resp = await _request("POST", f"/trafficshaper/queue/setQueue/{uuid}", json=body)
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_traffic_shaper_queue", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_traffic_shaper_rule(
    interface: str,
    pipe_uuid: str = "",
    queue_uuid: str = "",
    protocol: str = "ip",
    src: str = "any",
    dst: str = "any",
    src_port: str = "",
    dst_port: str = "",
    description: str = "",
) -> dict:
    """Add a traffic shaper rule to classify matching traffic into a pipe or queue. interface: network interface (e.g. 'wan', 'lan'). pipe_uuid or queue_uuid: target for matched traffic (at least one required). protocol: ip, tcp, udp, icmp, etc. src/dst: source/destination IP or network ('any' for all). src_port/dst_port: port or port range (e.g. '80', '8000-8080')."""
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_traffic_shaper_rule"}
    if not pipe_uuid.strip() and not queue_uuid.strip():
        return {"error": "pipe_uuid or queue_uuid must be provided", "tool": "add_traffic_shaper_rule"}
    try:
        body: dict = {
            "rule": {
                "interface": interface.strip(),
                "proto": protocol.strip(),
                "src": src.strip(),
                "dst": dst.strip(),
                "description": description.strip(),
            }
        }
        if pipe_uuid.strip():
            body["rule"]["pipe"] = pipe_uuid.strip()
        if queue_uuid.strip():
            body["rule"]["queue"] = queue_uuid.strip()
        if src_port.strip():
            body["rule"]["srcport"] = src_port.strip()
        if dst_port.strip():
            body["rule"]["dstport"] = dst_port.strip()
        resp = await _request("POST", "/trafficshaper/rules/addRule", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_traffic_shaper_rule", "detail": type(e).__name__}


@mcp.tool()
async def delete_traffic_shaper_rule(uuid: str) -> dict:
    """Delete a traffic shaper classification rule by UUID. Use list_traffic_shaper_rules to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_traffic_shaper_rule"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/trafficshaper/rules/delRule/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_traffic_shaper_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_traffic_shaper_pipe(
    uuid: str,
    bandwidth: int = 0,
    bandwidth_metric: str = "",
    delay: int = -1,
    description: str = "",
) -> dict:
    """Update a traffic shaper pipe (bandwidth limiter). Fetches current config and merges provided changes. uuid: from list_traffic_shaper_pipes. bandwidth: new limit (0 = keep current). bandwidth_metric: Kbit, Mbit, or Gbit (empty = keep current). delay: artificial delay ms (-1 = keep current). description: empty = keep current."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_traffic_shaper_pipe"}
    uuid = uuid.strip()
    try:
        cur_resp = await _request("GET", f"/trafficshaper/pipe/getPipe/{uuid}")
        cur_resp.raise_for_status()
        cur = cur_resp.json().get("pipe", {})
        body = {
            "pipe": {
                "bandwidth": str(bandwidth) if bandwidth > 0 else cur.get("bandwidth", "100"),
                "bandwidthmetric": bandwidth_metric.strip() if bandwidth_metric.strip() else cur.get("bandwidthmetric", "Mbit"),
                "delay": str(delay) if delay >= 0 else cur.get("delay", "0"),
                "plr": cur.get("plr", "0"),
                "description": description.strip() if description.strip() else cur.get("description", ""),
            }
        }
        resp = await _request("POST", f"/trafficshaper/pipe/setPipe/{uuid}", json=body)
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_traffic_shaper_pipe", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_traffic_shaper_rule(
    uuid: str,
    pipe_uuid: str = "",
    queue_uuid: str = "",
    src: str = "",
    dst: str = "",
    src_port: str = "",
    dst_port: str = "",
    description: str = "",
) -> dict:
    """Update a traffic shaper classification rule. Fetches current config and merges provided changes. uuid: from list_traffic_shaper_rules. Leave fields empty to keep current values. pipe_uuid or queue_uuid: update target pipe/queue. src/dst: source/destination address. src_port/dst_port: port or range."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_traffic_shaper_rule"}
    uuid = uuid.strip()
    try:
        cur_resp = await _request("GET", f"/trafficshaper/rules/getRule/{uuid}")
        cur_resp.raise_for_status()
        cur = cur_resp.json().get("rule", {})
        body: dict = {
            "rule": {
                "interface": cur.get("interface", "wan"),
                "proto": cur.get("proto", "ip"),
                "src": src.strip() if src.strip() else cur.get("src", "any"),
                "dst": dst.strip() if dst.strip() else cur.get("dst", "any"),
                "description": description.strip() if description.strip() else cur.get("description", ""),
            }
        }
        if pipe_uuid.strip():
            body["rule"]["pipe"] = pipe_uuid.strip()
        elif cur.get("pipe"):
            body["rule"]["pipe"] = cur["pipe"]
        if queue_uuid.strip():
            body["rule"]["queue"] = queue_uuid.strip()
        elif cur.get("queue"):
            body["rule"]["queue"] = cur["queue"]
        if src_port.strip():
            body["rule"]["srcport"] = src_port.strip()
        if dst_port.strip():
            body["rule"]["dstport"] = dst_port.strip()
        resp = await _request("POST", f"/trafficshaper/rules/setRule/{uuid}", json=body)
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_traffic_shaper_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_system_logs(
    scope: str = "general",
    limit: int = 100,
) -> dict:
    """Fetch system log entries from OPNsense. scope: log category — 'general' (system), 'backend' (configd), or 'api' (API calls). limit: number of entries to return (max 1000)."""
    limit = min(max(1, limit), 1000)
    valid_scopes = {"general", "backend", "api"}
    if scope not in valid_scopes:
        return {"error": f"scope must be one of: {', '.join(sorted(valid_scopes))}", "tool": "list_system_logs"}
    try:
        resp = await _request("GET", f"/core/log/access/{scope}", params={"limit": limit})
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_system_logs", "detail": type(e).__name__}


@mcp.tool()
async def add_captive_portal_zone(
    interface: str,
    zone_id: str,
    description: str = "",
    auth_mode: str = "none",
    idle_timeout: int = 0,
    session_timeout: int = 0,
) -> dict:
    """Add a captive portal zone to an interface. interface: interface name (e.g. 'lan'). zone_id: unique numeric zone identifier. description: display name. auth_mode: 'none' (no auth), 'Local Database', 'LDAP', 'RADIUS'. idle_timeout: disconnect inactive users after N seconds (0 = never). session_timeout: force re-auth after N seconds (0 = never)."""
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_captive_portal_zone"}
    if not zone_id or not zone_id.strip():
        return {"error": "zone_id must not be empty", "tool": "add_captive_portal_zone"}
    try:
        body = {
            "zone": {
                "interface": interface.strip(),
                "zoneid": zone_id.strip(),
                "description": description.strip(),
                "authmode": auth_mode.strip(),
                "idletimeout": str(idle_timeout),
                "hardtimeout": str(session_timeout),
            }
        }
        resp = await _request("POST", "/captiveportal/zones/addZone", json=body)
        resp.raise_for_status()
        data = resp.json()
        return {"result": {"uuid": data.get("uuid"), "response": data}}
    except Exception as e:
        return {"error": str(e), "tool": "add_captive_portal_zone", "detail": type(e).__name__}


@mcp.tool()
async def delete_captive_portal_zone(uuid: str) -> dict:
    """Delete a captive portal zone by UUID. WARNING: removes the zone and stops enforcing the portal on that interface. Use list_captive_portal_zones to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_captive_portal_zone"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/captiveportal/zones/delZone/{uuid}")
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "deleted": True, "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_captive_portal_zone", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_captive_portal_zone(
    uuid: str,
    description: str = "",
    auth_mode: str = "",
    idle_timeout: int = -1,
    session_timeout: int = -1,
) -> dict:
    """Update a captive portal zone configuration. Fetches current config and merges changes. uuid: from list_captive_portal_zones. description: display name. auth_mode: 'none', 'Local Database', 'LDAP', 'RADIUS'. idle_timeout/session_timeout: seconds (0 = never, -1 = keep current)."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_captive_portal_zone"}
    uuid = uuid.strip()
    try:
        cur_resp = await _request("GET", f"/captiveportal/zones/getZone/{uuid}")
        cur_resp.raise_for_status()
        cur = cur_resp.json().get("zone", {})
        body: dict = {
            "zone": {
                "interface": cur.get("interface", ""),
                "zoneid": cur.get("zoneid", ""),
                "description": description.strip() if description.strip() else cur.get("description", ""),
                "authmode": auth_mode.strip() if auth_mode.strip() else cur.get("authmode", "none"),
                "idletimeout": str(idle_timeout) if idle_timeout >= 0 else cur.get("idletimeout", "0"),
                "hardtimeout": str(session_timeout) if session_timeout >= 0 else cur.get("hardtimeout", "0"),
            }
        }
        resp = await _request("POST", f"/captiveportal/zones/setZone/{uuid}", json=body)
        resp.raise_for_status()
        return {"result": {"uuid": uuid, "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "update_captive_portal_zone", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_unbound_settings() -> dict:
    """Get global Unbound DNS resolver settings: enabled state, DNSSEC, DNS-over-TLS, query forwarding, logging, and cache configuration."""
    try:
        resp = await _request("GET", "/unbound/settings/get")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_unbound_settings", "detail": type(e).__name__}


@mcp.tool()
async def toggle_nat_binat(uuid: str, enabled: str) -> dict:
    """Enable or disable a 1:1 NAT (bidirectional NAT) rule. uuid: from list_nat_binat. enabled: '1' to enable, '0' to disable. Applies changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_nat_binat"}
    if enabled not in ("0", "1"):
        return {"error": "enabled must be '0' or '1'", "tool": "toggle_nat_binat"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/firewall/nat/toggleOneToOne/{uuid}/{enabled}")
        resp.raise_for_status()
        apply = await _request("POST", "/firewall/nat/apply")
        return {"result": {"uuid": uuid, "enabled": enabled == "1", "applied": apply.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_nat_binat", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_unbound_settings(
    enabled: str = "",
    dnssec: str = "",
    dns64: str = "",
    forward_tls_upstream: str = "",
    log_level: str = "",
) -> dict:
    """Update global Unbound DNS resolver settings. Fetches current config and merges changes. Only non-empty params are changed. enabled: '1'/'0'. dnssec: '1'/'0' DNSSEC validation. dns64: '1'/'0' DNS64. forward_tls_upstream: '1'/'0' DNS-over-TLS for forwarding. log_level: 0-5 verbosity. Apply takes effect after reconfigure."""
    try:
        cur_resp = await _request("GET", "/unbound/settings/get")
        cur_resp.raise_for_status()
        settings = cur_resp.json()
        unbound = settings.get("unbound", settings)
        if enabled in ("0", "1"):
            unbound["enabled"] = enabled
        if dnssec in ("0", "1"):
            unbound["dnssec"] = dnssec
        if dns64 in ("0", "1"):
            unbound["dns64"] = dns64
        if forward_tls_upstream in ("0", "1"):
            unbound["forward_tls_upstream"] = forward_tls_upstream
        if log_level.strip():
            unbound["log_level"] = log_level.strip()
        body = {"unbound": unbound} if "unbound" not in settings else settings
        resp = await _request("POST", "/unbound/settings/set", json=body)
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        return {"result": {"response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_unbound_settings", "detail": type(e).__name__}


@mcp.tool()
async def restart_unbound() -> dict:
    """Restart the Unbound DNS resolver service. Use after configuration changes that require a full service restart rather than reconfigure."""
    try:
        resp = await _request("POST", "/unbound/service/restart")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "restart_unbound", "detail": type(e).__name__}


@mcp.tool()
async def list_openvpn_cso() -> dict:
    """List OpenVPN client-specific overrides (CSOs). CSOs allow per-client IP assignments, routes, and options pushed to individual VPN clients identified by their common name."""
    try:
        resp = await _request("GET", "/openvpn/clients/searchClient")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_openvpn_cso", "detail": type(e).__name__}


@mcp.tool()
async def get_openvpn_cso(uuid: str) -> dict:
    """Get an OpenVPN client-specific override (CSO) by UUID. Returns common name, tunnel address, push routes, and server association. Use list_openvpn_cso to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_openvpn_cso"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/openvpn/clients/getClient/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_openvpn_cso", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_openvpn_cso(
    common_name: str,
    server_uuid: str,
    tunnel_network: str = "",
    push_routes: str = "",
    description: str = "",
) -> dict:
    """Add an OpenVPN client-specific override (CSO) to assign a fixed IP or push routes to a specific client. common_name: exact CN from the client's certificate. server_uuid: OpenVPN instance UUID from list_openvpn_instances. tunnel_network: fixed client IP in CIDR (e.g. '10.8.0.10/32'). push_routes: comma-separated networks to push to this client (e.g. '192.168.10.0/24,10.0.0.0/8'). Reconfigures OpenVPN after adding."""
    if not common_name or not common_name.strip():
        return {"error": "common_name must not be empty", "tool": "add_openvpn_cso"}
    if not server_uuid or not server_uuid.strip():
        return {"error": "server_uuid must not be empty", "tool": "add_openvpn_cso"}
    try:
        body: dict = {
            "client": {
                "common_name": common_name.strip(),
                "server": server_uuid.strip(),
                "description": description.strip(),
            }
        }
        if tunnel_network.strip():
            body["client"]["tunnel_network"] = tunnel_network.strip()
        if push_routes.strip():
            body["client"]["push_routes"] = [r.strip() for r in push_routes.split(",") if r.strip()]
        resp = await _request("POST", "/openvpn/clients/addClient", json=body)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/openvpn/service/reconfigure")
        return {"result": {"uuid": data.get("uuid"), "response": data, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_openvpn_cso", "detail": type(e).__name__}


@mcp.tool()
async def delete_openvpn_cso(uuid: str) -> dict:
    """Delete an OpenVPN client-specific override by UUID and reconfigure. Use list_openvpn_cso to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_openvpn_cso"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/openvpn/clients/delClient/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/openvpn/service/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_openvpn_cso", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_firmware_info() -> dict:
    """Get detailed OPNsense firmware information: current running version, architecture, release type (production/business), and available packages count."""
    try:
        resp = await _request("POST", "/core/firmware/info")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_firmware_info", "detail": type(e).__name__}


@mcp.tool()
async def update_openvpn_cso(
    uuid: str,
    tunnel_network: str = "",
    push_routes: str = "",
    description: str = "",
) -> dict:
    """Update an OpenVPN client-specific override (CSO). Fetches current config and merges changes. uuid: from list_openvpn_cso. tunnel_network: fixed client IP in CIDR (e.g. '10.8.0.10/32'). push_routes: comma-separated networks to push (replaces existing). description: display name."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_openvpn_cso"}
    uuid = uuid.strip()
    try:
        cur_resp = await _request("GET", f"/openvpn/clients/getClient/{uuid}")
        cur_resp.raise_for_status()
        cur = cur_resp.json().get("client", {})
        body: dict = {"client": dict(cur)}
        if tunnel_network.strip():
            body["client"]["tunnel_network"] = tunnel_network.strip()
        if push_routes.strip():
            body["client"]["push_routes"] = [r.strip() for r in push_routes.split(",") if r.strip()]
        if description.strip():
            body["client"]["description"] = description.strip()
        resp = await _request("POST", f"/openvpn/clients/setClient/{uuid}", json=body)
        resp.raise_for_status()
        reconf = await _request("POST", "/openvpn/service/reconfigure")
        return {"result": {"uuid": uuid, "response": resp.json(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_openvpn_cso", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_traffic_shaper_rule(uuid: str, enabled: str) -> dict:
    """Enable or disable a traffic shaper classification rule without deleting it. uuid: from list_traffic_shaper_rules. enabled: '1' to enable, '0' to disable. Applies traffic shaper configuration immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_traffic_shaper_rule"}
    if enabled not in ("0", "1"):
        return {"error": "enabled must be '0' or '1'", "tool": "toggle_traffic_shaper_rule"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/trafficshaper/rules/toggleRule/{uuid}/{enabled}")
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled == "1", "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_traffic_shaper_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_ipsec_sa() -> dict:
    """List active IPsec security associations (SAs) — currently established tunnel sessions with their peer addresses, encryption algorithms, bytes transferred, and expiry times."""
    try:
        resp = await _request("POST", "/ipsec/service/listSaStats")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_ipsec_sa", "detail": type(e).__name__}


@mcp.tool()
async def get_haproxy_stats() -> dict:
    """Get HAProxy runtime statistics: frontend/backend request rates, session counts, server health status, bytes in/out, and error rates. Useful for monitoring load balancer performance."""
    try:
        resp = await _request("GET", "/haproxy/service/stats")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_haproxy_stats", "detail": type(e).__name__}


@mcp.tool()
async def toggle_traffic_shaper_pipe(uuid: str, enabled: str) -> dict:
    """Enable or disable a traffic shaper pipe (bandwidth limiter) without deleting it. uuid: from list_traffic_shaper_pipes. enabled: '1' to enable, '0' to disable. Applies traffic shaper configuration immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_traffic_shaper_pipe"}
    if enabled not in ("0", "1"):
        return {"error": "enabled must be '0' or '1'", "tool": "toggle_traffic_shaper_pipe"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/trafficshaper/pipe/togglePipe/{uuid}/{enabled}")
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled == "1", "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_traffic_shaper_pipe", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_traffic_shaper_queue(uuid: str, enabled: str) -> dict:
    """Enable or disable a traffic shaper queue without deleting it. uuid: from list_traffic_shaper_queues. enabled: '1' to enable, '0' to disable. Applies traffic shaper configuration immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_traffic_shaper_queue"}
    if enabled not in ("0", "1"):
        return {"error": "enabled must be '0' or '1'", "tool": "toggle_traffic_shaper_queue"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/trafficshaper/queue/toggleQueue/{uuid}/{enabled}")
        resp.raise_for_status()
        reconf = await _request("POST", "/trafficshaper/pipe/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled == "1", "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_traffic_shaper_queue", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_routing_table() -> dict:
    """Get the live kernel routing table showing all active routes: destination, gateway, flags, interface, and route type (static, connected, BGP, OSPF)."""
    try:
        resp = await _request("GET", "/routes/routes/")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_routing_table", "detail": type(e).__name__}


@mcp.tool()
async def list_ipsec_pools() -> dict:
    """List IPsec IP address pools used for mobile client (road warrior) VPN assignments. Returns pool name, network range, and utilization."""
    try:
        resp = await _request("GET", "/ipsec/pools/searchPool")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_ipsec_pools", "detail": type(e).__name__}


@mcp.tool()
async def add_ipsec_pool(name: str, addresses: str, description: str = "") -> dict:
    """Add an IPsec IP address pool for mobile client (road warrior) VPN address assignment. name: pool identifier. addresses: CIDR range to assign to clients (e.g. '10.100.0.0/24'). Reconfigures IPsec immediately."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_ipsec_pool"}
    if not addresses or not addresses.strip():
        return {"error": "addresses must not be empty", "tool": "add_ipsec_pool"}
    try:
        payload = {"pool": {"name": name.strip(), "addresses": addresses.strip(), "description": description}}
        resp = await _request("POST", "/ipsec/pools/addPool", json=payload)
        resp.raise_for_status()
        data = resp.json()
        uuid = data.get("uuid", "")
        reconf = await _request("POST", "/ipsec/service/reconfigure")
        return {"result": {"uuid": uuid, "name": name.strip(), "addresses": addresses.strip(), "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_ipsec_pool", "detail": type(e).__name__}


@mcp.tool()
async def delete_ipsec_pool(uuid: str) -> dict:
    """Delete an IPsec IP address pool by UUID. Use list_ipsec_pools to find UUIDs. Reconfigures IPsec immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_ipsec_pool"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/ipsec/pools/delPool/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/ipsec/service/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_ipsec_pool", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_snmp_settings() -> dict:
    """Get OPNsense SNMP agent configuration: community string, contact, location, version (v1/v2c/v3), bind interface, and enabled state. Requires the os-net-snmp plugin."""
    try:
        resp = await _request("GET", "/netsnmp/service/get")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_snmp_settings", "detail": type(e).__name__}


@mcp.tool()
async def update_snmp_settings(
    enabled: str = "",
    community: str = "",
    contact: str = "",
    location: str = "",
    bindip: str = "",
    description: str = "",
) -> dict:
    """Update OPNsense SNMP agent settings (os-net-snmp plugin required). enabled: '1' to enable, '0' to disable. community: SNMP v1/v2c community string. contact: sysContact OID value. location: sysLocation OID value. bindip: IP address to listen on (blank = all). Only non-empty fields are changed. Restarts the SNMP daemon after update."""
    if not any([enabled, community, contact, location, bindip, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_snmp_settings"}
    try:
        get_resp = await _request("GET", "/netsnmp/service/get")
        get_resp.raise_for_status()
        current = get_resp.json().get("netsnmp", {})
        if enabled:
            current["enabled"] = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
        if community:
            current["community"] = community.strip()
        if contact:
            current["contact"] = contact.strip()
        if location:
            current["location"] = location.strip()
        if bindip:
            current["bindip"] = bindip.strip()
        if description:
            current["description"] = description.strip()
        set_resp = await _request("POST", "/netsnmp/service/set", json={"netsnmp": current})
        set_resp.raise_for_status()
        restart_resp = await _request("POST", "/netsnmp/service/restart")
        return {"result": {"updated": True, "restarted": restart_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_snmp_settings", "detail": type(e).__name__}


@mcp.tool()
async def get_ipsec_pool(uuid: str) -> dict:
    """Get a single IPsec IP address pool by UUID. Returns pool name, network range, and configuration details. Use list_ipsec_pools to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_ipsec_pool"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/ipsec/pools/getPool/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ipsec_pool", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_ipsec_pool(uuid: str, name: str = "", addresses: str = "", description: str = "") -> dict:
    """Update an existing IPsec IP address pool by UUID. Only non-empty fields are changed. Use list_ipsec_pools to find UUIDs. Reconfigures IPsec immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_ipsec_pool"}
    if not any([name, addresses, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_ipsec_pool"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/ipsec/pools/getPool/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("pool", {})
        if name:
            current["name"] = name.strip()
        if addresses:
            current["addresses"] = addresses.strip()
        if description:
            current["description"] = description.strip()
        set_resp = await _request("POST", f"/ipsec/pools/setPool/{uuid}", json={"pool": current})
        set_resp.raise_for_status()
        reconf = await _request("POST", "/ipsec/service/reconfigure")
        return {"result": {"uuid": uuid, "updated": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_ipsec_pool", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_gateway_group(
    name: str,
    trigger: str = "memberloss",
    description: str = "",
) -> dict:
    """Add a gateway group for failover or load balancing. name: group identifier (no spaces). trigger: when to consider a gateway down — 'memberloss' (any member lost), 'packetloss' (packet loss detected), 'latency' (high latency), 'latencypacketloss' (either), or 'down' (interface down). description: optional label. After creating, use update_gateway_group to add member gateways and their priority tiers."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "add_gateway_group"}
    valid_triggers = {"memberloss", "packetloss", "latency", "latencypacketloss", "down"}
    if trigger not in valid_triggers:
        return {"error": f"trigger must be one of: {', '.join(sorted(valid_triggers))}", "tool": "add_gateway_group"}
    try:
        payload = {"gatewaygroup": {"name": name.strip(), "trigger": trigger, "descr": description, "item": []}}
        resp = await _request("POST", "/routes/gateway/addGatewayGroup", json=payload)
        resp.raise_for_status()
        data = resp.json()
        uuid = data.get("uuid", "")
        reconf = await _request("POST", "/routes/gateway/reconfigure")
        return {"result": {"uuid": uuid, "name": name.strip(), "trigger": trigger, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_gateway_group", "detail": type(e).__name__}


@mcp.tool()
async def delete_gateway_group(uuid: str) -> dict:
    """Delete a gateway group by UUID. Use list_gateway_groups to find UUIDs. Reconfigures routing immediately. Will fail if the group is referenced by firewall rules."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_gateway_group"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/routes/gateway/delGatewayGroup/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/routes/gateway/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_gateway_group", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_gateway_group(uuid: str) -> dict:
    """Get a single gateway group by UUID, including member gateways, trigger level, and priority tiers. Use list_gateway_groups to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_gateway_group"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/routes/gateway/getGatewayGroup/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_gateway_group", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_gateway_group(
    uuid: str,
    trigger: str = "",
    description: str = "",
) -> dict:
    """Update an existing gateway group's trigger level or description. uuid: from list_gateway_groups. trigger: 'memberloss', 'packetloss', 'latency', 'latencypacketloss', or 'down'. Only non-empty fields are changed. Reconfigures routing immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_gateway_group"}
    if not any([trigger, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_gateway_group"}
    valid_triggers = {"memberloss", "packetloss", "latency", "latencypacketloss", "down"}
    if trigger and trigger not in valid_triggers:
        return {"error": f"trigger must be one of: {', '.join(sorted(valid_triggers))}", "tool": "update_gateway_group"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/routes/gateway/getGatewayGroup/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("gatewaygroup", {})
        if trigger:
            current["trigger"] = trigger
        if description:
            current["descr"] = description.strip()
        set_resp = await _request("POST", f"/routes/gateway/setGatewayGroup/{uuid}", json={"gatewaygroup": current})
        set_resp.raise_for_status()
        reconf = await _request("POST", "/routes/gateway/reconfigure")
        return {"result": {"uuid": uuid, "updated": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_gateway_group", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_captive_portal_settings() -> dict:
    """Get global captive portal settings: authentication method, HTTPS enforcement, allowed IP ranges, and voucher settings."""
    try:
        resp = await _request("GET", "/captiveportal/settings/get")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_captive_portal_settings", "detail": type(e).__name__}


@mcp.tool()
async def update_captive_portal_settings(
    enable_https: str = "",
    authentication: str = "",
    description: str = "",
) -> dict:
    """Update global captive portal settings. enable_https: '1' to enforce HTTPS on portal, '0' to use HTTP. authentication: authentication backend type (e.g. 'none', 'local', 'radius'). Only non-empty fields are changed."""
    if not any([enable_https, authentication, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_captive_portal_settings"}
    try:
        get_resp = await _request("GET", "/captiveportal/settings/get")
        get_resp.raise_for_status()
        current = get_resp.json().get("settings", get_resp.json())
        if enable_https:
            current["httpsForwardPort"] = "1" if enable_https.strip() in {"1", "true", "yes"} else "0"
        if authentication:
            current["authType"] = authentication.strip()
        if description:
            current["description"] = description.strip()
        set_resp = await _request("POST", "/captiveportal/settings/set", json={"settings": current})
        set_resp.raise_for_status()
        return {"result": {"updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_captive_portal_settings", "detail": type(e).__name__}


@mcp.tool()
async def list_firewall_states(
    filter_src: str = "",
    filter_dst: str = "",
    filter_iface: str = "",
    limit: int = 200,
) -> dict:
    """List active firewall state table entries (live connections tracked by pf). filter_src: filter by source IP/subnet. filter_dst: filter by destination IP/subnet. filter_iface: filter by interface name (e.g. 'em0', 'lan'). limit: max entries to return (default 200, max 2000). Useful for diagnosing active connections and NAT state."""
    limit = min(max(1, limit), 2000)
    try:
        params: dict = {"limit": limit}
        if filter_src:
            params["filter[srcaddr]"] = filter_src.strip()
        if filter_dst:
            params["filter[dstaddr]"] = filter_dst.strip()
        if filter_iface:
            params["filter[iface]"] = filter_iface.strip()
        resp = await _request("GET", "/diagnostics/states/search", params=params)
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_firewall_states", "detail": type(e).__name__}


@mcp.tool()
async def flush_firewall_states(
    filter_src: str = "",
    filter_dst: str = "",
) -> dict:
    """Flush (kill) firewall state table entries. If filter_src or filter_dst are provided, only matching states are removed; otherwise ALL states are cleared (use with caution — drops all active connections). filter_src: source IP to match. filter_dst: destination IP to match."""
    try:
        if filter_src or filter_dst:
            payload: dict = {}
            if filter_src:
                payload["srcaddr"] = filter_src.strip()
            if filter_dst:
                payload["dstaddr"] = filter_dst.strip()
            resp = await _request("POST", "/diagnostics/states/killStates", json=payload)
        else:
            resp = await _request("POST", "/diagnostics/states/clearStates")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "flush_firewall_states", "detail": type(e).__name__}


@mcp.tool()
async def list_unbound_forwards() -> dict:
    """List Unbound DNS query forwarding zones — domains whose queries are forwarded to specific upstream resolvers instead of being resolved recursively. Useful for split-DNS setups."""
    try:
        resp = await _request("GET", "/unbound/settings/searchForward")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_unbound_forwards", "detail": type(e).__name__}


@mcp.tool()
async def add_unbound_forward(
    domain: str,
    server: str,
    port: int = 53,
    tls: bool = False,
    tls_hostname: str = "",
    description: str = "",
) -> dict:
    """Add a DNS forwarding zone to Unbound: queries for domain are forwarded to server instead of resolved recursively. domain: DNS zone to forward (e.g. 'corp.local', '.' for all queries). server: IP address of the upstream resolver. port: resolver port (default 53, use 853 for DNS-over-TLS). tls: enable DNS-over-TLS. tls_hostname: TLS SNI hostname (e.g. 'dns.cloudflare.com'). Restarts Unbound after adding."""
    if not domain or not domain.strip():
        return {"error": "domain must not be empty", "tool": "add_unbound_forward"}
    if not server or not server.strip():
        return {"error": "server must not be empty", "tool": "add_unbound_forward"}
    if not (1 <= port <= 65535):
        return {"error": f"port must be 1-65535, got: {port}", "tool": "add_unbound_forward"}
    try:
        import ipaddress
        ipaddress.ip_address(server.strip())
    except ValueError:
        return {"error": f"server must be a valid IP address, got: '{server}'", "tool": "add_unbound_forward"}
    try:
        payload = {
            "forward": {
                "enabled": "1",
                "domain": domain.strip(),
                "server": server.strip(),
                "port": str(port),
                "verify": "1" if tls else "0",
                "tls_hostname": tls_hostname.strip() if tls else "",
                "description": description,
            }
        }
        resp = await _request("POST", "/unbound/settings/addForward", json=payload)
        resp.raise_for_status()
        data = resp.json()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        return {"result": {"uuid": data.get("uuid", ""), "domain": domain.strip(), "server": server.strip(), "port": port, "tls": tls, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_unbound_forward", "detail": type(e).__name__}


@mcp.tool()
async def get_unbound_forward(uuid: str) -> dict:
    """Get details of a single DNS forwarding zone by UUID. Returns domain, server, port, TLS settings, and status. Use list_unbound_forwards to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_unbound_forward"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/unbound/settings/getForward/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_unbound_forward", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def delete_unbound_forward(uuid: str) -> dict:
    """Delete a DNS forwarding zone from Unbound by UUID. Use list_unbound_forwards to find UUIDs. Restarts Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_unbound_forward"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/unbound/settings/delForward/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_unbound_forward", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_unbound_forward(
    uuid: str,
    domain: str = "",
    server: str = "",
    port: int = 0,
    tls: str = "",
    tls_hostname: str = "",
    description: str = "",
) -> dict:
    """Update an existing DNS forwarding zone by UUID. Only non-empty/non-zero fields are changed. domain: DNS zone (e.g. 'corp.local'). server: upstream resolver IP. port: 1-65535 (0 = keep current). tls: '1'/'true' or '0'/'false' to update TLS setting. tls_hostname: TLS SNI hostname. Restarts Unbound after updating."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_unbound_forward"}
    uuid = uuid.strip()
    if server and server.strip():
        try:
            import ipaddress as _ip
            _ip.ip_address(server.strip())
        except ValueError:
            return {"error": f"server must be a valid IP address, got: '{server}'", "tool": "update_unbound_forward"}
    if port and not (1 <= port <= 65535):
        return {"error": f"port must be 1-65535, got: {port}", "tool": "update_unbound_forward"}
    if not any([domain, server, port, tls, tls_hostname, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_unbound_forward"}
    try:
        get_resp = await _request("GET", f"/unbound/settings/getForward/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("forward", {})
        if domain:
            current["domain"] = domain.strip()
        if server:
            current["server"] = server.strip()
        if port:
            current["port"] = str(port)
        if tls:
            current["verify"] = "1" if tls.strip().lower() in {"1", "true", "yes"} else "0"
        if tls_hostname:
            current["tls_hostname"] = tls_hostname.strip()
        if description:
            current["description"] = description
        set_resp = await _request("POST", f"/unbound/settings/setForward/{uuid}", json={"forward": current})
        set_resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        return {"result": {"uuid": uuid, "updated": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_unbound_forward", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_unbound_forward(uuid: str, enabled: str) -> dict:
    """Enable or disable a DNS forwarding zone without deleting it. uuid: from list_unbound_forwards. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Restarts Unbound immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_unbound_forward"}
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_unbound_forward"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/unbound/settings/getForward/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("forward", {})
        current["enabled"] = enabled_val
        set_resp = await _request("POST", f"/unbound/settings/setForward/{uuid}", json={"forward": current})
        set_resp.raise_for_status()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1", "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_unbound_forward", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_virtual_ips() -> dict:
    """List all virtual IP addresses (VIPs) configured in OPNsense: CARP addresses for HA failover, IP aliases, proxy ARP entries. Returns type, interface, subnet, VHID, and enabled state."""
    try:
        resp = await _request("GET", "/interfaces/vips/searchItem")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_virtual_ips", "detail": type(e).__name__}


@mcp.tool()
async def get_virtual_ip(uuid: str) -> dict:
    """Get a single virtual IP (VIP) entry by UUID. Returns type (carp/ipalias/proxyarp), interface, IP, subnet mask, VHID, and password. Use list_virtual_ips to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_virtual_ip"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/interfaces/vips/getItem/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_virtual_ip", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def add_virtual_ip(
    vip_type: str,
    interface: str,
    ip: str,
    subnet: int = 32,
    vhid: int = 1,
    password: str = "",
    description: str = "",
) -> dict:
    """Add a virtual IP (VIP) to an OPNsense interface. vip_type: 'carp' (HA failover with VRRP-like protocol), 'ipalias' (additional IP on interface), 'proxyarp' (respond to ARP for IP range), or 'other' (passthrough). interface: interface name (e.g. 'em0', 'igb1'). ip: virtual IP address. subnet: prefix length (default 32). vhid: CARP VHID 1-255, must be unique per segment (CARP only). password: CARP shared password. Applies interface changes immediately."""
    if not vip_type or vip_type not in {"carp", "ipalias", "proxyarp", "other"}:
        return {"error": "vip_type must be one of: carp, ipalias, proxyarp, other", "tool": "add_virtual_ip"}
    if not interface or not interface.strip():
        return {"error": "interface must not be empty", "tool": "add_virtual_ip"}
    if not ip or not ip.strip():
        return {"error": "ip must not be empty", "tool": "add_virtual_ip"}
    if not 0 <= subnet <= 128:
        return {"error": "subnet must be 0-128", "tool": "add_virtual_ip"}
    if vip_type == "carp" and not (1 <= vhid <= 255):
        return {"error": "vhid must be 1-255 for CARP", "tool": "add_virtual_ip"}
    try:
        payload = {
            "vip": {
                "mode": vip_type,
                "interface": interface.strip(),
                "network": ip.strip(),
                "network_mask": str(subnet),
                "vhid": str(vhid) if vip_type == "carp" else "1",
                "password": password,
                "advbase": "1",
                "advskew": "0",
                "descr": description,
            }
        }
        resp = await _request("POST", "/interfaces/vips/addItem", json=payload)
        resp.raise_for_status()
        data = resp.json()
        uuid = data.get("uuid", "")
        reconf = await _request("POST", "/interfaces/vips/reconfigure")
        return {"result": {"uuid": uuid, "vip_type": vip_type, "interface": interface, "ip": ip, "subnet": subnet, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_virtual_ip", "detail": type(e).__name__}


@mcp.tool()
async def delete_virtual_ip(uuid: str) -> dict:
    """Delete a virtual IP (VIP) by UUID. Use list_virtual_ips to find UUIDs. Applies interface changes immediately. Removing a CARP VIP used by firewall rules may cause issues."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_virtual_ip"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/interfaces/vips/delItem/{uuid}")
        resp.raise_for_status()
        reconf = await _request("POST", "/interfaces/vips/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_virtual_ip", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_cpu_usage() -> dict:
    """Get current CPU utilization per core: user, system, interrupt, and idle percentages. Also returns total CPU count and load averages (1m, 5m, 15m)."""
    try:
        resp = await _request("GET", "/diagnostics/cpu_usage/")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_cpu_usage", "detail": type(e).__name__}


@mcp.tool()
async def get_memory_usage() -> dict:
    """Get current system memory utilization: total, used, free, cached, and swap usage in bytes and percentages."""
    try:
        resp = await _request("GET", "/diagnostics/memory_usage/")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_memory_usage", "detail": type(e).__name__}


@mcp.tool()
async def update_virtual_ip(
    uuid: str,
    ip: str = "",
    subnet: int = -1,
    vhid: int = -1,
    password: str = "",
    description: str = "",
) -> dict:
    """Update an existing virtual IP (VIP) by UUID. Only non-empty/non-negative fields are changed. Use list_virtual_ips to find UUIDs. Applies interface changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_virtual_ip"}
    if not any([ip, subnet >= 0, vhid >= 0, password, description]):
        return {"error": "At least one field to update must be specified", "tool": "update_virtual_ip"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/interfaces/vips/getItem/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("vip", {})
        if ip:
            current["network"] = ip.strip()
        if subnet >= 0:
            current["network_mask"] = str(subnet)
        if vhid >= 0:
            current["vhid"] = str(vhid)
        if password:
            current["password"] = password
        if description:
            current["descr"] = description.strip()
        set_resp = await _request("POST", f"/interfaces/vips/setItem/{uuid}", json={"vip": current})
        set_resp.raise_for_status()
        reconf = await _request("POST", "/interfaces/vips/reconfigure")
        return {"result": {"uuid": uuid, "updated": True, "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_virtual_ip", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_virtual_ip(uuid: str, enabled: str) -> dict:
    """Enable or disable a virtual IP (VIP) without deleting it. uuid: from list_virtual_ips. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies interface changes immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_virtual_ip"}
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_virtual_ip"}
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/interfaces/vips/toggleItem/{uuid}/{enabled_val}")
        resp.raise_for_status()
        reconf = await _request("POST", "/interfaces/vips/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1", "reconfigured": reconf.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_virtual_ip", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_disk_usage() -> dict:
    """Get disk usage statistics for all mounted filesystems: device, mount point, total size, used, available, and utilization percentage."""
    try:
        resp = await _request("GET", "/diagnostics/disk/")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_disk_usage", "detail": type(e).__name__}


@mcp.tool()
async def list_processes(filter_name: str = "") -> dict:
    """List active system processes with PID, CPU %, memory %, state, and command. filter_name: optional substring to filter by process name. Useful for checking if specific daemons are running and their resource usage."""
    try:
        resp = await _request("GET", "/diagnostics/activity/")
        resp.raise_for_status()
        data = resp.json()
        if filter_name and filter_name.strip():
            fn = filter_name.strip().lower()
            procs = data if isinstance(data, list) else data.get("procs", data.get("processes", []))
            data = [p for p in procs if fn in str(p.get("command", p.get("cmd", ""))).lower()]
        return {"result": data}
    except Exception as e:
        return {"error": str(e), "tool": "list_processes", "detail": type(e).__name__}


@mcp.tool()
async def get_gateway_status() -> dict:
    """Get live status of all configured gateways with RTT (ms), packet loss %, and up/down/pending state. Essential for diagnosing WAN failover and multi-WAN load balancing issues."""
    try:
        resp = await _request("GET", "/routes/gateway/status")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_gateway_status", "detail": type(e).__name__}


@mcp.tool()
async def list_openvpn_sessions() -> dict:
    """List all currently connected OpenVPN client sessions across all instances: client IP, virtual IP, bytes in/out, connected since, and username."""
    try:
        resp = await _request("GET", "/openvpn/service/searchSessions")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_openvpn_sessions", "detail": type(e).__name__}


@mcp.tool()
async def get_pf_stats() -> dict:
    """Get packet filter (pf) statistics: state table size and limits, packets/bytes passed and blocked, active rules count, and TCP/UDP/ICMP state counts."""
    try:
        resp = await _request("GET", "/diagnostics/pfstats/")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_pf_stats", "detail": type(e).__name__}


@mcp.tool()
async def flush_alias(name: str) -> dict:
    """Flush the resolved content of a firewall alias — removes all currently loaded IPs/networks from the live pf table for that alias without deleting the alias definition. Useful for forcing immediate reload of URL table aliases, pfBlocker lists, or GeoIP tables. name: alias name (not UUID)."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "flush_alias"}
    name = name.strip()
    try:
        resp = await _request("POST", f"/firewall/alias_util/flush/{name}")
        resp.raise_for_status()
        return {"result": {"alias": name, "flushed": True, "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "flush_alias", "detail": type(e).__name__}


@mcp.tool()
async def get_alias_resolved(name: str) -> dict:
    """Get the currently resolved IP addresses and networks inside a firewall alias. For URL table aliases, shows what IPs were loaded from the remote URL. For host aliases, shows the resolved IPs. name: alias name (not UUID)."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "get_alias_resolved"}
    name = name.strip()
    try:
        resp = await _request("GET", f"/firewall/alias_util/list/{name}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_alias_resolved", "detail": type(e).__name__}


@mcp.tool()
async def get_system_information() -> dict:
    """Get general OPNsense system information: hostname, domain, OS version, CPU model, installed RAM, and uptime. Useful for inventory and documentation."""
    try:
        resp = await _request("GET", "/core/system/status")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_system_information", "detail": type(e).__name__}


@mcp.tool()
async def get_ids_settings() -> dict:
    """Get global IDS/IPS settings: enabled state, mode (IDS=detect-only / IPS=block), monitoring interface, and HOME_NET definition. Use before calling update_ids_settings."""
    try:
        resp = await _request("GET", "/ids/settings/getSettings")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ids_settings", "detail": type(e).__name__}


@mcp.tool()
async def update_ids_settings(enabled: bool = True, mode: str = "ids", homenet: str = "", interface: str = "") -> dict:
    """Update global IDS/IPS settings. mode: 'ids' (detect and alert only) or 'ips' (actively block matching traffic via inline mode). homenet: comma-separated CIDR ranges defining the HOME_NET Suricata variable (e.g. '192.168.0.0/16,10.0.0.0/8'). interface: network interface to monitor (e.g. 'em0', 'igb0'). Changes are applied immediately via reconfigure."""
    if mode and mode not in {"ids", "ips"}:
        return {"error": "mode must be 'ids' or 'ips'", "tool": "update_ids_settings"}
    try:
        get_resp = await _request("GET", "/ids/settings/getSettings")
        get_resp.raise_for_status()
        current = get_resp.json()
        settings = current.get("ids", current)
        settings["ips"] = "1" if mode == "ips" else "0"
        settings["enabled"] = "1" if enabled else "0"
        if homenet:
            settings["homenet"] = homenet
        if interface:
            settings["interfaces"] = interface
        post_resp = await _request("POST", "/ids/settings/setSettings", json={"ids": settings})
        post_resp.raise_for_status()
        apply_resp = await _request("POST", "/ids/service/reconfigure")
        return {"result": {"updated": True, "mode": mode, "enabled": enabled, "applied": apply_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_ids_settings", "detail": type(e).__name__}


@mcp.tool()
async def list_ids_user_rules() -> dict:
    """List all user-defined custom IDS/IPS rules (Suricata rules written manually). These supplement the downloaded rulesets. Returns uuid, enabled state, action, source/dest, protocol, SID, and message for each rule."""
    try:
        resp = await _request("GET", "/ids/settings/searchUserRules")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_ids_user_rules", "detail": type(e).__name__}


@mcp.tool()
async def add_ids_user_rule(
    action: str,
    msg: str,
    source_ip: str = "any",
    dest_ip: str = "any",
    proto: str = "tcp",
    sid: int = 9000001,
    description: str = "",
) -> dict:
    """Add a custom Suricata IDS/IPS rule. action: alert (log only), drop (block in IPS mode), pass (allow and skip remaining rules), or reject. msg: rule description shown in alerts. source_ip/dest_ip: IP, CIDR, or 'any'. proto: tcp, udp, icmp, or any. sid: unique rule ID — use 9000000+ for custom rules to avoid conflicts with official rulesets."""
    valid_actions = {"alert", "drop", "pass", "reject"}
    if action not in valid_actions:
        return {"error": f"action must be one of: {', '.join(sorted(valid_actions))}", "tool": "add_ids_user_rule"}
    if sid < 1:
        return {"error": "sid must be a positive integer", "tool": "add_ids_user_rule"}
    if not msg or not msg.strip():
        return {"error": "msg must not be empty", "tool": "add_ids_user_rule"}
    try:
        payload = {
            "userrule": {
                "enabled": "1",
                "action": action,
                "source": source_ip or "any",
                "destination": dest_ip or "any",
                "proto": proto or "tcp",
                "sid": str(sid),
                "msg": msg.strip(),
                "description": description,
            }
        }
        resp = await _request("POST", "/ids/settings/addUserRule", json=payload)
        resp.raise_for_status()
        data = resp.json()
        uuid = data.get("uuid", "")
        apply_resp = await _request("POST", "/ids/service/reconfigure")
        return {"result": {"uuid": uuid, "action": action, "sid": sid, "msg": msg, "applied": apply_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_ids_user_rule", "detail": type(e).__name__}


@mcp.tool()
async def delete_ids_user_rule(uuid: str) -> dict:
    """Delete a user-defined IDS/IPS custom rule by UUID. Changes are applied immediately — the rule is removed from the active Suricata ruleset. Get UUIDs from list_ids_user_rules."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_ids_user_rule"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/ids/settings/delUserRule/{uuid}")
        resp.raise_for_status()
        apply_resp = await _request("POST", "/ids/service/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "applied": apply_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_ids_user_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_ids_user_rule(uuid: str) -> dict:
    """Get details of a specific user-defined IDS/IPS custom rule by UUID. Returns action, source, destination, protocol, SID, message, and enabled state. Use list_ids_user_rules to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_ids_user_rule"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/ids/settings/getUserRule/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_ids_user_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_ids_user_rule(
    uuid: str,
    action: str = "",
    msg: str = "",
    source_ip: str = "",
    dest_ip: str = "",
    proto: str = "",
    sid: int = 0,
    description: str = "",
) -> dict:
    """Update an existing user-defined IDS/IPS custom rule. Only provided (non-empty) fields are changed; fetch current values with get_ids_user_rule first. Changes are applied immediately via reconfigure."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_ids_user_rule"}
    valid_actions = {"alert", "drop", "pass", "reject"}
    if action and action not in valid_actions:
        return {"error": f"action must be one of: {', '.join(sorted(valid_actions))}", "tool": "update_ids_user_rule"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/ids/settings/getUserRule/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("userrule", {})
        if action:
            current["action"] = action
        if msg:
            current["msg"] = msg.strip()
        if source_ip:
            current["source"] = source_ip
        if dest_ip:
            current["destination"] = dest_ip
        if proto:
            current["proto"] = proto
        if sid > 0:
            current["sid"] = str(sid)
        if description:
            current["description"] = description
        post_resp = await _request("POST", f"/ids/settings/setUserRule/{uuid}", json={"userrule": current})
        post_resp.raise_for_status()
        apply_resp = await _request("POST", "/ids/service/reconfigure")
        return {"result": {"uuid": uuid, "updated": True, "applied": apply_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_ids_user_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def toggle_ids_user_rule(uuid: str, enabled: str) -> dict:
    """Enable or disable a user-defined IDS/IPS custom rule without modifying other settings. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Changes are applied immediately."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "toggle_ids_user_rule"}
    if not enabled or not enabled.strip():
        return {"error": "enabled must not be empty", "tool": "toggle_ids_user_rule"}
    uuid = uuid.strip()
    enabled_val = "1" if enabled.strip().lower() in {"1", "true", "yes"} else "0"
    try:
        resp = await _request("POST", f"/ids/settings/toggleUserRule/{uuid}/{enabled_val}")
        resp.raise_for_status()
        apply_resp = await _request("POST", "/ids/service/reconfigure")
        return {"result": {"uuid": uuid, "enabled": enabled_val == "1", "applied": apply_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_ids_user_rule", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def list_unbound_acls() -> dict:
    """List all Unbound DNS resolver access control rules — which networks are allowed or denied from querying this resolver. Useful for restricting DNS to trusted subnets."""
    try:
        resp = await _request("GET", "/unbound/settings/searchAcl")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_unbound_acls", "detail": type(e).__name__}


@mcp.tool()
async def add_unbound_acl(network: str, action: str, description: str = "") -> dict:
    """Add an Unbound DNS resolver access control rule. network: CIDR (e.g. '192.168.1.0/24'). action: allow, allow_snoop, allow_setrd, allow_setrd_snoop, deny, deny_non_local, refuse, refuse_non_local. Changes are applied immediately."""
    valid_actions = {"allow", "allow_snoop", "allow_setrd", "allow_setrd_snoop", "deny", "deny_non_local", "refuse", "refuse_non_local"}
    if not network or not network.strip():
        return {"error": "network must not be empty", "tool": "add_unbound_acl"}
    if action not in valid_actions:
        return {"error": f"action must be one of: {', '.join(sorted(valid_actions))}", "tool": "add_unbound_acl"}
    try:
        ipaddress.ip_network(network.strip(), strict=False)
    except ValueError as e:
        return {"error": f"Invalid network CIDR: {e}", "tool": "add_unbound_acl"}
    try:
        payload = {"acl": {"enabled": "1", "network": network.strip(), "action": action, "description": description}}
        resp = await _request("POST", "/unbound/settings/addAcl", json=payload)
        resp.raise_for_status()
        data = resp.json()
        uuid = data.get("uuid", "")
        apply_resp = await _request("POST", "/unbound/service/reconfigure")
        return {"result": {"uuid": uuid, "network": network.strip(), "action": action, "applied": apply_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "add_unbound_acl", "detail": type(e).__name__}


@mcp.tool()
async def delete_unbound_acl(uuid: str) -> dict:
    """Delete an Unbound DNS access control rule by UUID. Changes are applied immediately. Get UUIDs from list_unbound_acls."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "delete_unbound_acl"}
    uuid = uuid.strip()
    try:
        resp = await _request("POST", f"/unbound/settings/delAcl/{uuid}")
        resp.raise_for_status()
        apply_resp = await _request("POST", "/unbound/service/reconfigure")
        return {"result": {"uuid": uuid, "deleted": True, "applied": apply_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "delete_unbound_acl", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def get_unbound_acl(uuid: str) -> dict:
    """Get details of a specific Unbound DNS access control rule by UUID. Returns network, action, enabled state, and description. Use list_unbound_acls to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_unbound_acl"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/unbound/settings/getAcl/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_unbound_acl", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def update_unbound_acl(uuid: str, network: str = "", action: str = "", description: str = "") -> dict:
    """Update an existing Unbound DNS access control rule. Only provided (non-empty) fields are changed — fetch current values with get_unbound_acl first. Changes are applied immediately via reconfigure."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "update_unbound_acl"}
    valid_actions = {"allow", "allow_snoop", "allow_setrd", "allow_setrd_snoop", "deny", "deny_non_local", "refuse", "refuse_non_local"}
    if action and action not in valid_actions:
        return {"error": f"action must be one of: {', '.join(sorted(valid_actions))}", "tool": "update_unbound_acl"}
    if network:
        try:
            ipaddress.ip_network(network.strip(), strict=False)
        except ValueError as e:
            return {"error": f"Invalid network CIDR: {e}", "tool": "update_unbound_acl"}
    uuid = uuid.strip()
    try:
        get_resp = await _request("GET", f"/unbound/settings/getAcl/{uuid}")
        get_resp.raise_for_status()
        current = get_resp.json().get("acl", {})
        if network:
            current["network"] = network.strip()
        if action:
            current["action"] = action
        if description:
            current["description"] = description
        post_resp = await _request("POST", f"/unbound/settings/setAcl/{uuid}", json={"acl": current})
        post_resp.raise_for_status()
        apply_resp = await _request("POST", "/unbound/service/reconfigure")
        return {"result": {"uuid": uuid, "updated": True, "applied": apply_resp.status_code == 200}}
    except Exception as e:
        return {"error": str(e), "tool": "update_unbound_acl", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def perform_firmware_upgrade(confirm: bool = False) -> dict:
    """Trigger an OPNsense firmware upgrade to the latest available release. WARNING: This will reboot the firewall and cause a network interruption during upgrade. The upgrade runs in the background — poll get_firmware_status to monitor progress. confirm must be explicitly set to True to execute (safety gate)."""
    if not confirm:
        return {"error": "Set confirm=True to execute the upgrade. WARNING: This reboots the firewall and interrupts network traffic.", "tool": "perform_firmware_upgrade"}
    try:
        resp = await _request("POST", "/core/firmware/upgrade", json={"upgrade_type": "current"})
        resp.raise_for_status()
        return {"result": {"upgrade_started": True, "message": "Firmware upgrade initiated. Firewall will reboot — use get_firmware_status to monitor.", "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "perform_firmware_upgrade", "detail": type(e).__name__}


@mcp.tool()
async def restart_haproxy() -> dict:
    """Restart (reconfigure) the HAProxy load balancer service — applies all pending configuration changes. Call after adding or modifying HAProxy frontends, backends, or servers."""
    try:
        resp = await _request("POST", "/haproxy/service/reconfigure")
        resp.raise_for_status()
        return {"result": {"restarted": True, "response": resp.json()}}
    except Exception as e:
        return {"error": str(e), "tool": "restart_haproxy", "detail": type(e).__name__}


@mcp.tool()
async def list_certificate_authorities() -> dict:
    """List all certificate authorities (CAs) configured in the OPNsense trust store. Returns UUID, name, distinguished name, and expiry for each CA. Use UUIDs with generate_signed_certificate."""
    try:
        resp = await _request("GET", "/trust/ca/search")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "list_certificate_authorities", "detail": type(e).__name__}


@mcp.tool()
async def get_certificate_authority(uuid: str) -> dict:
    """Get full details of a specific certificate authority by UUID. Returns distinguished name, validity period, key type, and whether the private key is stored locally. Use list_certificate_authorities to find UUIDs."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "get_certificate_authority"}
    uuid = uuid.strip()
    try:
        resp = await _request("GET", f"/trust/ca/get/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_certificate_authority", "uuid": uuid, "detail": type(e).__name__}


@mcp.tool()
async def generate_signed_certificate(
    name: str,
    ca_uuid: str,
    common_name: str,
    cert_type: str = "usr_cert",
    key_type: str = "RSA",
    key_bits: int = 2048,
    lifetime_days: int = 825,
) -> dict:
    """Generate a new certificate signed by an existing certificate authority (CA). name: display name for the cert. ca_uuid: UUID of the signing CA (from list_certificate_authorities). common_name: CN field (e.g. 'vpn-client-alice' or 'server.example.com'). cert_type: 'usr_cert' (client) or 'server_cert'. key_type: RSA or EC. key_bits: 2048 or 4096 for RSA. lifetime_days: validity period (default 825, max 825 for Apple compatibility)."""
    if not name or not name.strip():
        return {"error": "name must not be empty", "tool": "generate_signed_certificate"}
    if not ca_uuid or not ca_uuid.strip():
        return {"error": "ca_uuid must not be empty", "tool": "generate_signed_certificate"}
    if not common_name or not common_name.strip():
        return {"error": "common_name must not be empty", "tool": "generate_signed_certificate"}
    valid_cert_types = {"usr_cert", "server_cert"}
    if cert_type not in valid_cert_types:
        return {"error": f"cert_type must be one of: {', '.join(sorted(valid_cert_types))}", "tool": "generate_signed_certificate"}
    valid_key_types = {"RSA", "EC"}
    if key_type not in valid_key_types:
        return {"error": "key_type must be 'RSA' or 'EC'", "tool": "generate_signed_certificate"}
    if key_bits not in {2048, 4096} and key_type == "RSA":
        return {"error": "key_bits must be 2048 or 4096 for RSA", "tool": "generate_signed_certificate"}
    if lifetime_days < 1 or lifetime_days > 3650:
        return {"error": "lifetime_days must be between 1 and 3650", "tool": "generate_signed_certificate"}
    try:
        payload = {
            "cert": {
                "descr": name.strip(),
                "caref": ca_uuid.strip(),
                "type": cert_type,
                "keytype": key_type,
                "keylen": str(key_bits),
                "digest_alg": "sha256",
                "lifetime": str(lifetime_days),
                "dn_commonname": common_name.strip(),
            }
        }
        resp = await _request("POST", "/trust/cert/add", json=payload)
        resp.raise_for_status()
        data = resp.json()
        uuid = data.get("uuid", "")
        return {"result": {"uuid": uuid, "name": name, "ca_uuid": ca_uuid, "common_name": common_name, "cert_type": cert_type, "lifetime_days": lifetime_days}}
    except Exception as e:
        return {"error": str(e), "tool": "generate_signed_certificate", "detail": type(e).__name__}


@mcp.tool()
async def export_certificate_pem(uuid: str) -> dict:
    """Export a certificate (and optionally its private key) as PEM-encoded strings. Useful for downloading generated certificates to configure clients. Returns 'certificate' (PEM) and 'private_key' (PEM, if stored) fields. Handle private key material carefully."""
    if not uuid or not uuid.strip():
        return {"error": "uuid must not be empty", "tool": "export_certificate_pem"}
    uuid = uuid.strip()
    try:
        import base64 as _b64
        resp = await _request("GET", f"/trust/cert/get/{uuid}")
        resp.raise_for_status()
        data = resp.json()
        cert_obj = data.get("cert", data)
        crt_b64 = cert_obj.get("crt", "")
        prv_b64 = cert_obj.get("prv", "")
        result: dict = {"uuid": uuid, "name": cert_obj.get("descr", "")}
        if crt_b64:
            try:
                result["certificate"] = _b64.b64decode(crt_b64).decode("utf-8", errors="replace")
            except Exception:
                result["certificate_b64"] = crt_b64
        if prv_b64:
            try:
                result["private_key"] = _b64.b64decode(prv_b64).decode("utf-8", errors="replace")
            except Exception:
                result["private_key_b64"] = prv_b64
        if not crt_b64:
            return {"error": "Certificate data not found in response", "tool": "export_certificate_pem", "raw": data}
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "export_certificate_pem", "uuid": uuid, "detail": type(e).__name__}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
