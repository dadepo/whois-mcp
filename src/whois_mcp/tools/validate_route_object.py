import ipaddress
import logging
from typing import Annotated, Any

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from whois_mcp.cache import TTLCache
from whois_mcp.config import HTTP_TIMEOUT_SECONDS, RIPE_REST, USER_AGENT

__all__ = ["register"]

# Configure logging
logger = logging.getLogger(__name__)

# Initialize cache with 5-minute TTL for route validation results
_route_cache: TTLCache[str, Any] = TTLCache(max_items=1000, ttl_seconds=300.0)

# Tool metadata constants
TOOL_NAME = "validate_route_object"
TOOL_DESCRIPTION = (
    "PREFERRED TOOL for validating route object registration. Use this when you need to "
    "CHECK, VERIFY, or VALIDATE if a route object exists for a prefix-ASN pair. "
    "Keywords: 'route validation', 'check route', 'verify route', 'route exists', "
    "'BGP security', 'route filtering', 'IRR coverage', 'RPKI validation'. "
    "Automatically handles IPv4/IPv6 detection and returns simple exists/not-found status. "
    "Much faster and more accurate than parsing raw WHOIS data for route validation."
)

PREFIX_DESCRIPTION = (
    "IP prefix to CHECK/VALIDATE for route object registration. Use CIDR notation like "
    "'192.0.2.0/24' for IPv4 or '2001:db8::/32' for IPv6. Use this when you need to "
    "VERIFY if a prefix has a registered route object in the IRR database."
)

ORIGIN_ASN_DESCRIPTION = (
    "Origin ASN number to VALIDATE/CHECK for route coverage (without 'AS' prefix). "
    "For example, use 64496 to VERIFY if AS64496 has a route object registered for the "
    "specified prefix. This VALIDATES proper BGP route registration and IRR coverage."
)


async def _search_route(prefix: str) -> tuple[dict[str, Any], str]:
    """Search for route objects matching the given prefix."""
    route_type = "route6" if ":" in prefix else "route"
    url = f"{RIPE_REST}/search.json?query-string={prefix}&type-filter={route_type}"

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT_SECONDS, headers={"User-Agent": USER_AGENT}
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json(), route_type


async def _validate_route_object_request(
    prefix: Annotated[str, Field(description=PREFIX_DESCRIPTION)],
    origin_asn: Annotated[int, Field(description=ORIGIN_ASN_DESCRIPTION)],
) -> dict[str, Any]:
    """
    Validate IRR route/route6 coverage for a specific prefix-ASN combination.

    This tool is optimized for validation workflows where you need to verify if a specific
    route object exists for a known prefix-ASN pair. Much more efficient than whois_query
    when you just need to check coverage status rather than examine full route object details.

    Use Cases:
    - BGP route filtering validation ("Is 192.0.2.0/24 AS64496 properly registered?")
    - RPKI validation workflows
    - Network security audits
    - Automated route policy verification

    Returns: {"ok": true, "data": {"state": "exists|not-found", "matches": [...], "prefix": "...", "origin_asn": N}}
    """
    # Create cache key from prefix and ASN
    cache_key = f"route:{prefix}|{origin_asn}"

    # Check cache first
    cached_result = _route_cache.get(cache_key)
    if cached_result is not None:
        logger.info(f"Route validation for '{prefix}' AS{origin_asn} served from cache")
        return cached_result

    try:
        # Validate prefix format
        ipaddress.ip_network(prefix, strict=False)
    except Exception as e:
        logger.error(f"Invalid prefix format '{prefix}': {str(e)}")
        return {"ok": False, "error": "invalid_prefix", "detail": str(e)}

    try:
        # Search for route objects
        search_data, route_type = await _search_route(prefix)

        matches: list[dict[str, str]] = []
        objects = search_data.get("objects", {}).get("object", [])

        for obj in objects:
            attrs = obj.get("attributes", {}).get("attribute", [])

            # Extract route and origin from attributes
            route = next(
                (a["value"] for a in attrs if a.get("name") in ("route", "route6")),
                None,
            )
            origin = next((a["value"] for a in attrs if a.get("name") == "origin"), "")

            if not route:
                continue

            # Parse origin ASN
            try:
                origin_num = int(origin.upper().replace("AS", ""))
            except Exception:
                continue

            # Check if this route matches our target ASN
            if origin_num == origin_asn:
                matches.append(
                    {
                        "route": route,
                        "origin": origin,
                        "source": route_type,
                    }
                )

        result = {
            "ok": True,
            "data": {
                "state": "exists" if matches else "not-found",
                "matches": matches,
                "prefix": prefix,
                "origin_asn": origin_asn,
            },
        }

        # Cache the result
        _route_cache.set(cache_key, result)

        logger.info(
            f"Route validation for '{prefix}' AS{origin_asn} completed: "
            f"{len(matches)} matches found"
        )
        return result

    except httpx.HTTPError as e:
        logger.error(f"HTTP error during route search for '{prefix}': {str(e)}")
        return {"ok": False, "error": "http_error", "detail": str(e)}
    except Exception as e:
        logger.error(f"Route validation for '{prefix}' AS{origin_asn} failed: {str(e)}")
        return {"ok": False, "error": "validation_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    """Register the validate_route_object tool with the MCP server."""
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_validate_route_object_request)
