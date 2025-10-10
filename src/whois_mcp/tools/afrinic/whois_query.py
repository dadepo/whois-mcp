"""AfriNIC WHOIS query tool."""

import asyncio
import logging

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from whois_mcp.cache import TTLCache
from whois_mcp.config import (
    AFRINIC_WHOIS_PORT,
    AFRINIC_WHOIS_SERVER,
    CACHE_MAX_ITEMS,
    CACHE_TTL_SECONDS,
    WHOIS_CONNECT_TIMEOUT_SECONDS,
    WHOIS_READ_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)

TOOL_NAME = "afrinic_whois_query"
TOOL_DESCRIPTION = """Query the AfriNIC WHOIS database for network resource information.

This tool performs raw WHOIS protocol queries against AfriNIC's WHOIS server.
It can be used to look up information about IP addresses, ASNs, domain objects,
person/role contacts, and other registry objects in the AfriNIC service region (Africa).

Examples:
- IP addresses: "196.216.2.0"
- IPv6 addresses: "2001:43f8::"
- AS numbers: "AS37611" or "37611"
- Domain objects: "2.216.196.in-addr.arpa"
- Person/role handles: "AA1-AFRINIC"
"""

# Cache for WHOIS query results
cache: TTLCache[str, str] = TTLCache(max_items=CACHE_MAX_ITEMS, ttl_seconds=CACHE_TTL_SECONDS)


async def _whois_query(query: str) -> str:
    """Execute a WHOIS query against AfriNIC."""
    # TODO: Implement WHOIS query logic
    raise NotImplementedError("AfriNIC WHOIS query not yet implemented")


def register(mcp: FastMCP) -> None:
    """Register the AfriNIC WHOIS query tool with the MCP server."""

    @mcp.tool(name=TOOL_NAME, description=TOOL_DESCRIPTION)
    async def afrinic_whois_query(
        query: str = Field(description="The query string to send to AfriNIC WHOIS server"),
    ) -> str:
        """Query the AfriNIC WHOIS database."""
        # TODO: Implement tool logic
        raise NotImplementedError("AfriNIC WHOIS query not yet implemented")

