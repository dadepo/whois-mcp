"""LACNIC contact card tool."""

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from whois_mcp.cache import TTLCache
from whois_mcp.config import CACHE_MAX_ITEMS, CACHE_TTL_SECONDS

logger = logging.getLogger(__name__)

TOOL_NAME = "lacnic_contact_card"
TOOL_DESCRIPTION = """Retrieve contact information for LACNIC network resources.

This tool fetches structured contact information for IP addresses and AS numbers
from LACNIC's RDAP service. The contact information includes administrative and
technical contacts, email addresses, phone numbers, and organizational details.

The tool accepts either:
- IP addresses (IPv4 or IPv6): e.g., "200.160.0.0", "2801:10::"
- AS numbers: e.g., "AS27699", "27699"

Returns structured contact data including names, roles, emails, and phone numbers
in an easy-to-read format.
"""

# Cache for contact card results
cache: TTLCache[str, dict[str, Any]] = TTLCache(
    max_items=CACHE_MAX_ITEMS, ttl_seconds=CACHE_TTL_SECONDS
)


async def _contact_card_request(resource: str) -> dict[str, Any]:
    """Fetch contact information from LACNIC RDAP."""
    # TODO: Implement RDAP contact card logic
    raise NotImplementedError("LACNIC contact card not yet implemented")


def register(mcp: FastMCP) -> None:
    """Register the LACNIC contact card tool with the MCP server."""

    @mcp.tool(name=TOOL_NAME, description=TOOL_DESCRIPTION)
    async def lacnic_contact_card(
        resource: str = Field(
            description="IP address (IPv4/IPv6) or AS number (with or without 'AS' prefix) to look up"
        ),
    ) -> str:
        """Retrieve contact information for a LACNIC network resource."""
        # TODO: Implement tool logic
        raise NotImplementedError("LACNIC contact card not yet implemented")

