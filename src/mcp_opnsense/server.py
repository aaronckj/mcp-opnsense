"""mcp-opnsense: OPNsense firewall management MCP server."""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("opnsense")

_DEFAULT_HOST = "https://192.168.1.1"
_DEFAULT_TIMEOUT = 30.0


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
