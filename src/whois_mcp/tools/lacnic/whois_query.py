"""LACNIC WHOIS query tool."""

import asyncio
import logging

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from whois_mcp.cache import TTLCache
from whois_mcp.config import (
    CACHE_MAX_ITEMS,
    CACHE_TTL_SECONDS,
    LACNIC_WHOIS_PORT,
    LACNIC_WHOIS_SERVER,
    WHOIS_CONNECT_TIMEOUT_SECONDS,
    WHOIS_READ_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)

TOOL_NAME = "lacnic_whois_query"
TOOL_DESCRIPTION = """Query the LACNIC WHOIS database for network resource information.

This tool performs raw WHOIS protocol queries against LACNIC's WHOIS server.
It can be used to look up information about IP addresses, ASNs, domain objects,
person/role contacts, and other registry objects in the LACNIC service region 
(Latin America and the Caribbean).

Examples:
- IP addresses: "200.160.0.0"
- IPv6 addresses: "2801:10::"
- AS numbers: "AS27699" or "27699"
- Domain objects: "0.160.200.in-addr.arpa"
- Person/role handles: "LACNIC-HOSTMASTER"
"""

# Cache for WHOIS query results
cache: TTLCache[str, str] = TTLCache(max_items=CACHE_MAX_ITEMS, ttl_seconds=CACHE_TTL_SECONDS)


async def _whois_query(query: str) -> str:
    """Execute a WHOIS query against LACNIC."""
    # TODO: Implement WHOIS query logic
    raise NotImplementedError("LACNIC WHOIS query not yet implemented")


def register(mcp: FastMCP) -> None:
    """Register the LACNIC WHOIS query tool with the MCP server."""

    @mcp.tool(name=TOOL_NAME, description=TOOL_DESCRIPTION)
    async def lacnic_whois_query(
        query: str = Field(description="The query string to send to LACNIC WHOIS server"),
    ) -> str:
        """Query the LACNIC WHOIS database."""
        # TODO: Implement tool logic
        raise NotImplementedError("LACNIC WHOIS query not yet implemented")

