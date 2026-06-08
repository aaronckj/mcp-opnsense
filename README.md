# mcp-opnsense

MCP server for [OPNsense](https://opnsense.org/) firewall management. Exposes 299 tools covering system status & diagnostics, services, cron, interfaces/VLANs, DHCP, Unbound DNS, firewall rules & aliases, NAT, traffic shaping, OpenVPN, WireGuard, IPsec, HAProxy, IDS/IPS, certificates, users, captive portal, and more — all via the OPNsense REST API.

## Quick Start

**With uvx (recommended):**
```bash
OPNSENSE_HOST=https://192.168.1.1 \
OPNSENSE_API_KEY=yourkey \
OPNSENSE_API_SECRET=yoursecret \
uvx mcp-opnsense
```

**With Docker:**
```bash
docker run -i \
  -e OPNSENSE_HOST=https://192.168.1.1 \
  -e OPNSENSE_API_KEY=yourkey \
  -e OPNSENSE_API_SECRET=yoursecret \
  ghcr.io/aaronckj/mcp-opnsense:latest
```

**Add to Claude Code:**
```bash
claude mcp add opnsense -- uvx mcp-opnsense
```

Or with environment configured inline:
```bash
claude mcp add opnsense -s user \
  -e OPNSENSE_HOST=https://192.168.1.1 \
  -e OPNSENSE_API_KEY=yourkey \
  -e OPNSENSE_API_SECRET=yoursecret \
  -- uvx mcp-opnsense
```

**`mcp.json` snippet** (Claude Desktop, Cursor, or any MCP client):
```json
{
  "mcpServers": {
    "opnsense": {
      "command": "uvx",
      "args": ["mcp-opnsense"],
      "env": {
        "OPNSENSE_HOST": "https://192.168.1.1",
        "OPNSENSE_API_KEY": "yourkey",
        "OPNSENSE_API_SECRET": "yoursecret"
      }
    }
  }
}
```

## Creating API Credentials

In OPNsense: **System → User Manager → Users** → edit a user → **API keys** → Add key. Copy the key and secret (the secret is only shown once).

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPNSENSE_API_KEY` | Yes | — | API key from OPNsense user manager |
| `OPNSENSE_API_SECRET` | Yes | — | API secret from OPNsense user manager |
| `OPNSENSE_HOST` | No | `https://192.168.1.1` | OPNsense host URL |
| `OPNSENSE_TIMEOUT` | No | `30` | HTTP timeout in seconds |
| `OPNSENSE_VERIFY_SSL` | No | `false` | Set to `true` if using a trusted certificate |

## Tools

This server exposes **299 tools**. Most domains follow a consistent CRUD pattern:
`list_*`, `get_*`, `add_*`, `update_*`, `delete_*`, and `toggle_*`. Tools are
grouped by domain below (counts sum to 299):

| Domain | Tools | Examples |
|--------|------:|----------|
| Unbound DNS | 28 | `list_unbound_hosts`, `add_unbound_host`, `delete_unbound_host`, `get_unbound_stats`, `flush_dns_cache` |
| HAProxy | 22 | `list_haproxy_backends`, `add_haproxy_server`, `get_haproxy_stats`, `restart_haproxy` |
| Users & groups | 22 | `list_users`, `add_user`, `delete_user`, `add_group` |
| DHCP & static leases | 20 | `list_dhcp_leases`, `add_static_lease`, `list_dhcpv6_leases`, `add_dhcp_range` |
| IPsec VPN | 19 | `list_ipsec_tunnels`, `add_ipsec_tunnel`, `list_ipsec_sa`, `get_ipsec_status` |
| Firewall (filter rules, aliases, states) | 18 | `list_firewall_rules`, `add_firewall_rule`, `delete_firewall_rule`, `add_alias`, `flush_states` |
| NAT (port forwards, outbound, 1:1) | 18 | `list_port_forwards`, `add_port_forward`, `add_nat_outbound`, `add_nat_binat` |
| Traffic shaper | 18 | `add_traffic_shaper_pipe`, `add_traffic_shaper_queue`, `add_traffic_shaper_rule` |
| System & diagnostics | 17 | `system_status`, `get_cpu_usage`, `get_system_log`, `backup_config`, `reboot_system`, `shutdown_system` |
| Interfaces, VLANs & virtual IPs | 15 | `list_interfaces`, `add_vlan`, `add_virtual_ip`, `get_interface_stats` |
| OpenVPN | 15 | `list_openvpn_instances`, `add_openvpn_instance`, `list_openvpn_sessions`, `disconnect_openvpn_session` |
| WireGuard | 13 | `list_wireguard_servers`, `add_wireguard_peer`, `get_wireguard_status` |
| IDS/IPS (Suricata) | 12 | `get_ids_settings`, `update_ids_settings`, `list_ids_alerts`, `restart_ids` |
| ARP/NDP, routes & gateways | 12 | `get_arp_table`, `get_gateways`, `add_static_route`, `flush_arp_table` |
| Captive portal | 10 | `list_captive_portal_zones`, `add_captive_portal_zone`, `disconnect_captive_portal_client` |
| Certificates & CAs | 9 | `list_certificates`, `generate_self_signed_cert`, `import_certificate`, `export_certificate_pem` |
| Plugins & firmware | 7 | `list_plugins`, `install_plugin`, `remove_plugin`, `perform_firmware_upgrade` |
| Cron jobs | 6 | `list_cron_jobs`, `add_cron_job`, `toggle_cron_job` |
| NTP | 6 | `list_ntp_servers`, `add_ntp_server` |
| Syslog | 6 | `list_syslog_destinations`, `add_syslog_destination` |
| Services | 4 | `list_services`, `restart_service`, `start_service`, `stop_service` |
| SNMP | 2 | `get_snmp_settings`, `update_snmp_settings` |
| Plus | 1 | `apply_changes` (apply pending firewall/NAT changes), `health_check` |

> The `examples` column is illustrative, not exhaustive. Run the server and ask
> your MCP client to list tools for the full inventory.

### ⚠️ Destructive / high-impact tools

Many tools mutate live firewall configuration and apply immediately. Treat the
following as destructive and confirm before invoking — several can drop your
connection or take the firewall offline:

- **Whole-system:** `reboot_system`, `shutdown_system`, `perform_firmware_upgrade`, `install_plugin`, `remove_plugin`
- **Config deletion (37 `delete_*` tools):** e.g. `delete_firewall_rule`, `delete_port_forward`, `delete_user`, `delete_vlan`, `delete_certificate`, `delete_ipsec_tunnel`, `delete_unbound_host`
- **Service / state control:** `restart_service`, `stop_service`, `start_service`, `restart_unbound`, `restart_haproxy`, `hard_restart_haproxy`, `restart_ids`, `stop_ids`, `start_ids`
- **Flush / disconnect:** `flush_states`, `flush_firewall_states`, `flush_arp_table`, `flush_dns_cache`, `flush_alias`, `flush_ids_alerts`, `disconnect_openvpn_session`, `disconnect_captive_portal_client`
- **Apply:** `apply_changes` commits staged firewall/NAT changes

Scope the API credentials to the least privilege your use case needs, and
consider a read-only OPNsense user if you only want status/inspection tools.

## Development

```bash
git clone https://github.com/aaronckj/mcp-opnsense
cd mcp-opnsense
uv sync --extra dev
uv run pytest -v
```
