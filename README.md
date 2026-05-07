# mcp-opnsense

MCP server for [OPNsense](https://opnsense.org/) firewall management. Exposes 16 tools for system status, services, DHCP, DNS overrides, firewall rules, and NAT port forwards via the OPNsense REST API.

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
  -e OPNSENSE_HOST=https://10.0.0.1 \
  -e OPNSENSE_API_KEY=yourkey \
  -e OPNSENSE_API_SECRET=yoursecret \
  ghcr.io/aaronckj/mcp-opnsense:latest
```

**Add to Claude Code:**
```bash
claude mcp add opnsense -s user \
  -e OPNSENSE_HOST=https://10.0.0.1 \
  -e OPNSENSE_API_KEY=yourkey \
  -- uvx mcp-opnsense
```

Then set `OPNSENSE_API_SECRET` in your Claude Code MCP settings.

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

| Tool | Description |
|------|-------------|
| `system_status` | CPU, memory, uptime, firmware version |
| `get_gateways` | WAN gateway status and packet loss |
| `list_interfaces` | All interfaces with IPs and link state |
| `list_services` | All services and running status |
| `restart_service` | Restart a named service |
| `apply_changes` | Apply pending firewall changes |
| `list_dhcp_leases` | Active and static DHCP leases |
| `add_static_lease` | Add a static DHCP mapping |
| `list_dns_overrides` | Unbound host overrides |
| `add_dns_override` | Add a host override (auto-reconfigures) |
| `delete_dns_override` | Remove a host override by UUID (auto-reconfigures) |
| `list_firewall_rules` | All firewall filter rules |
| `add_firewall_rule` | Add a rule (auto-applies) |
| `delete_firewall_rule` | Delete a rule by UUID (auto-applies) |
| `list_port_forwards` | NAT port forward rules |
| `add_port_forward` | Add a port forward (auto-applies) |

## Development

```bash
git clone https://github.com/aaronckj/mcp-opnsense
cd mcp-opnsense
uv sync --extra dev
uv run pytest -v
```
