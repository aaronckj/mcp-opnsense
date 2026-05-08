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
                "descr": description,
                "pcp": "",
            }},
        )
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "add_vlan", "detail": type(e).__name__}


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
async def get_system_log(log_type: str = "system", rows: int = 50) -> dict:
    """Fetch recent OPNsense log entries via the diagnostics API. log_type: 'system', 'firmware', 'dhcp', 'filter'. rows: 1-500."""
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
        fields["description"] = description
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
        resp = await _request("POST", f"/cron/settings/setJob/{uuid.strip()}", json={"job": fields})
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
                "description": description,
                "minutes": minute,
                "hours": hour,
                "dayofmonth": dom,
                "months": month,
                "weekdays": dow,
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
    try:
        resp = await _request("GET", f"/dhcpv4/settings/getStaticMap/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_static_lease", "detail": type(e).__name__}


@mcp.tool()
async def add_static_lease(mac: str, ip: str, hostname: str = "") -> dict:
    """Add a static DHCPv4 lease mapping a MAC address to a fixed IP. Reconfigures DHCP immediately."""
    if not _MAC_RE.match(mac):
        return {"error": f"Invalid MAC address: '{mac}'", "tool": "add_static_lease"}
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
async def update_static_lease(uuid: str, mac: str = "", ip: str = "", hostname: str = "") -> dict:
    """Update an existing static DHCPv4 lease by UUID. Only non-empty fields are changed. Reconfigures DHCP immediately."""
    fields: dict = {}
    if mac:
        if not _MAC_RE.match(mac):
            return {"error": f"Invalid MAC address: '{mac}'", "tool": "update_static_lease"}
        fields["mac"] = mac
    if ip:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return {"error": f"Invalid IPv4 address: '{ip}'", "tool": "update_static_lease"}
        fields["ipaddr"] = ip
    if hostname:
        fields["hostname"] = hostname
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_static_lease"}
    try:
        resp = await _request("POST", f"/dhcpv4/settings/setStaticMap/{uuid}", json={"staticmap": fields})
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
    try:
        resp = await _request("GET", f"/unbound/host/getHostOverride/{uuid}")
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
    host: dict = {}
    if hostname:
        host["host"] = hostname
    if domain:
        host["domain"] = domain
    if record_type:
        rt = record_type.upper()
        if rt not in {"A", "AAAA"}:
            return {"error": f"Invalid record_type '{record_type}'. Must be 'A' or 'AAAA'", "tool": "update_dns_override"}
        host["rr"] = rt
    if server:
        try:
            ipaddress.IPv4Address(server)
        except ValueError:
            try:
                ipaddress.IPv6Address(server)
            except ValueError:
                return {"error": f"Invalid IP address for server: '{server}'", "tool": "update_dns_override"}
        host["server"] = server
    if not host:
        return {"error": "At least one field to update must be specified", "tool": "update_dns_override"}
    try:
        resp = await _request("POST", f"/unbound/host/setHostOverride/{uuid}", json={"host": host})
        resp.raise_for_status()
        result = resp.json()

        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()

        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "update_dns_override", "detail": type(e).__name__}


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
                "network": network,
                "gateway": gateway,
                "descr": description,
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
    fields: dict = {}
    if network:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            return {"error": f"Invalid network CIDR: '{network}'", "tool": "update_static_route"}
        fields["network"] = network
    if gateway:
        fields["gateway"] = gateway.strip()
    if description:
        fields["descr"] = description
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
    description: str = "",
) -> dict:
    """Add a firewall filter rule and apply immediately. action: pass/block/reject. protocol: any/tcp/udp/icmp/etc. src/dst: network or 'any'."""
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
async def update_firewall_rule(
    uuid: str,
    action: str = "",
    interface: str = "",
    protocol: str = "",
    src: str = "",
    dst: str = "",
    description: str = "",
    enabled: str = "",
) -> dict:
    """Update an existing firewall rule by UUID. Only non-empty fields are changed. enabled: '1'/'true' or '0'/'false'. Applies changes immediately."""
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
    if description:
        rule["description"] = description
    if enabled:
        rule["enabled"] = "1" if enabled.lower() in {"1", "true", "yes"} else "0"
    if not rule:
        return {"error": "At least one field to update must be specified", "tool": "update_firewall_rule"}
    try:
        resp = await _request("POST", f"/firewall/filter/setRule/{uuid}", json={"rule": rule})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_firewall_rule", "detail": type(e).__name__}




@mcp.tool()
async def toggle_firewall_rule(uuid: str, enabled: str) -> dict:
    """Enable or disable a firewall rule by UUID. enabled: '1'/'true'/'yes' to enable, '0'/'false'/'no' to disable. Applies changes immediately without touching other rule fields."""
    enabled_val = "1" if enabled.lower() in {"1", "true", "yes"} else "0"
    try:
        resp = await _request("POST", f"/firewall/filter/setRule/{uuid}", json={"rule": {"enabled": enabled_val}})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "enabled": enabled_val == "1"}}
    except Exception as e:
        return {"error": str(e), "tool": "toggle_firewall_rule", "detail": type(e).__name__}


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
async def get_port_forward(uuid: str) -> dict:
    """Get a specific NAT port forward rule by UUID."""
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
) -> dict:
    """Add a NAT port forward rule and apply immediately. interface: WAN interface name. protocol: tcp/udp/tcp/udp. target: internal IPv4 address."""
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
    """Update an existing NAT port forward rule by UUID. Only non-empty fields are changed. enabled: '1'/'true' or '0'/'false'. Applies immediately."""
    rule: dict = {}
    if interface:
        rule["interface"] = interface
    if protocol:
        rule["protocol"] = protocol
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
        rule["description"] = description
    if enabled:
        rule["enabled"] = "1" if enabled.lower() in {"1", "true", "yes"} else "0"
    if not rule:
        return {"error": "At least one field to update must be specified", "tool": "update_port_forward"}
    try:
        resp = await _request("POST", f"/firewall/nat/setRule/{uuid}", json={"rule": rule})
        resp.raise_for_status()

        apply = await _request("POST", "/firewall/filter/apply")
        apply.raise_for_status()

        return {"result": {"uuid": uuid, "updated": True}}
    except Exception as e:
        return {"error": str(e), "tool": "update_port_forward", "detail": type(e).__name__}


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
    try:
        resp = await _request("GET", f"/firewall/alias/getItem/{uuid}")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_alias", "detail": type(e).__name__}


@mcp.tool()
async def update_alias(uuid: str, alias_type: str = "", content: str = "", description: str = "") -> dict:
    """Update an existing firewall alias by UUID. Only non-empty fields are changed. alias_type: host/network/port/url. content: newline or comma-separated entries. Reconfigures immediately."""
    fields: dict = {}
    if alias_type:
        _valid_alias_types = {"host", "network", "port", "url"}
        if alias_type not in _valid_alias_types:
            return {"error": f"Invalid alias_type '{alias_type}'. Must be one of: {', '.join(sorted(_valid_alias_types))}", "tool": "update_alias"}
        fields["type"] = alias_type
    if content:
        fields["content"] = content
    if description:
        fields["description"] = description
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_alias"}
    try:
        resp = await _request("POST", f"/firewall/alias/setItem/{uuid}", json={"alias": fields})
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
                "name": name,
                "type": alias_type,
                "content": content,
                "description": description,
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
    try:
        resp = await _request("POST", f"/firewall/alias/delItem/{uuid}")
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
    if not server or not server.strip():
        return {"error": "server must not be empty", "tool": "add_unbound_domain"}
    try:
        ipaddress.ip_address(server)
    except ValueError:
        return {"error": f"Invalid IP address for server: '{server}'", "tool": "add_unbound_domain"}
    try:
        resp = await _request(
            "POST",
            "/unbound/domain/addDomainOverride",
            json={"domain": {"domain": domain, "server": server, "description": description, "enabled": "1"}},
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
    fields: dict = {}
    if domain:
        fields["domain"] = domain.strip()
    if server:
        try:
            ipaddress.ip_address(server)
        except ValueError:
            return {"error": f"Invalid IP address for server: '{server}'", "tool": "update_unbound_domain"}
        fields["server"] = server
    if description:
        fields["description"] = description
    if not fields:
        return {"error": "At least one field to update must be specified", "tool": "update_unbound_domain"}
    try:
        resp = await _request("POST", f"/unbound/domain/setDomainOverride/{uuid.strip()}", json={"domain": fields})
        resp.raise_for_status()
        result = resp.json()
        reconf = await _request("POST", "/unbound/service/reconfigure")
        reconf.raise_for_status()
        return {"result": result}
    except Exception as e:
        return {"error": str(e), "tool": "update_unbound_domain", "detail": type(e).__name__}


@mcp.tool()
async def get_firmware_status() -> dict:
    """Check OPNsense firmware update status — current version and available updates."""
    try:
        resp = await _request("GET", "/core/firmware/status")
        resp.raise_for_status()
        return {"result": resp.json()}
    except Exception as e:
        return {"error": str(e), "tool": "get_firmware_status", "detail": type(e).__name__}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
