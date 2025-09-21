import ipaddress
import logging
from typing import Annotated, Any

import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession
from pydantic import Field

from whois_mcp.cache import TTLCache
from whois_mcp.config import (
    ARIN_REST_BASE,
    HTTP_TIMEOUT_SECONDS,
    SUPPORT_ARIN,
    USER_AGENT,
)

__all__ = ["register"]

# Configure logging
logger = logging.getLogger(__name__)

# Initialize cache with 5-minute TTL for route validation results
_route_cache: TTLCache[str, Any] = TTLCache(max_items=1000, ttl_seconds=300.0)

# Tool metadata constants
TOOL_NAME = "arin_validate_route_object"
TOOL_DESCRIPTION = (
    "PREFERRED TOOL for validating route object registration in the ARIN database. "
    "This tool is specifically for the ARIN RIR (North America region - United States, Canada, parts of Caribbean). "
    "Use this when you need to CHECK, VERIFY, or VALIDATE if a route object exists for a prefix-ASN pair in ARIN. "
    "Keywords: 'route validation', 'check route', 'verify route', 'route exists', "
    "'BGP security', 'route filtering', 'IRR coverage', 'RPKI validation'. "
    "Automatically handles IPv4/IPv6 detection and returns simple exists/not-found status. "
    "Much faster and more accurate than parsing raw WHOIS data for route validation in ARIN database."
)

PREFIX_DESCRIPTION = (
    "IP prefix to CHECK/VALIDATE for route object registration in ARIN database. Use CIDR notation like "
    "'192.0.2.0/24' for IPv4 or '2001:db8::/32' for IPv6. Use this when you need to "
    "VERIFY if a prefix has a registered route object in the ARIN IRR database."
)

ORIGIN_ASN_DESCRIPTION = (
    "Origin ASN number to VALIDATE/CHECK for route coverage (without 'AS' prefix). "
    "For example, use 64496 to VERIFY if AS64496 has a route object registered for the "
    "specified prefix. This VALIDATES proper BGP route registration and IRR coverage."
)


async def _search_route(prefix: str) -> dict[str, Any]:
    """Search for route objects matching the given prefix using ARIN's REST API."""
    # ARIN uses different endpoints for route objects
    # Try searching in the IRR database
    route_type = "route6" if ":" in prefix else "route"

    # ARIN's IRR search endpoint format
    url = f"{ARIN_REST_BASE}/irr/{route_type}/{prefix}"

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        follow_redirects=True,
    ) as client:
        response = await client.get(url)

        # ARIN may return 404 for non-existent routes, which is expected
        if response.status_code == 404:
            return {"routes": []}

        response.raise_for_status()
        return response.json()


async def _validate_route_object_request(
    prefix: Annotated[str, Field(description=PREFIX_DESCRIPTION)],
    origin_asn: Annotated[int, Field(description=ORIGIN_ASN_DESCRIPTION)],
    ctx: Context[ServerSession, None],
) -> dict[str, Any]:
    """
    Validate IRR route/route6 coverage for a specific prefix-ASN combination in ARIN database.

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

    # Check if ARIN support is enabled
    if not SUPPORT_ARIN:
        error_msg = "Route validation is currently disabled (SUPPORT_ARIN=false)"
        logger.warning(error_msg)
        await ctx.error(error_msg)
        return {
            "ok": False,
            "error": "service_disabled",
            "detail": "ARIN route validation support is disabled. Set SUPPORT_ARIN=true to enable.",
        }

    # Log the incoming request
    await ctx.info(
        f"Starting ARIN route validation for prefix '{prefix}' origin AS{origin_asn}"
    )

    # Create cache key from prefix and ASN
    cache_key = f"arin:route:{prefix}|{origin_asn}"

    # Check cache first
    cached_result = _route_cache.get(cache_key)
    if cached_result is not None:
        logger.info(
            f"ARIN route validation for '{prefix}' AS{origin_asn} served from cache"
        )
        await ctx.info(
            f"ARIN route validation for '{prefix}' AS{origin_asn} served from cache"
        )
        return cached_result

    try:
        # Validate prefix format
        ipaddress.ip_network(prefix, strict=False)
    except Exception as e:
        error_msg = f"Invalid prefix format '{prefix}': {str(e)}"
        logger.error(error_msg)
        await ctx.error(f"ARIN route validation failed: {error_msg}")
        return {"ok": False, "error": "invalid_prefix", "detail": str(e)}

    try:
        # Search for route objects
        search_data = await _search_route(prefix)

        matches: list[dict[str, str]] = []
        routes: list[dict[str, Any]] = search_data.get("routes", [])

        # Handle different possible ARIN response formats
        if isinstance(routes, dict):
            routes = [routes]

        for route_obj in routes:
            # ARIN may have different field names - adapt as needed
            route = route_obj.get("route", route_obj.get("prefix", ""))
            origin = route_obj.get("origin", route_obj.get("originAS", ""))

            if not route or not origin:
                continue

            # Parse origin ASN
            try:
                origin_str = str(origin).upper().replace("AS", "")
                origin_num = int(origin_str)
            except (ValueError, TypeError):
                continue

            # Check if this route matches our target ASN
            if origin_num == origin_asn:
                matches.append(
                    {
                        "route": route,
                        "origin": f"AS{origin_num}",
                        "source": "arin_irr",
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
            f"ARIN route validation for '{prefix}' AS{origin_asn} completed: "
            f"{len(matches)} matches found"
        )

        # Log successful completion via MCP context
        state = result["data"]["state"]
        match_count = len(matches)
        await ctx.info(
            f"ARIN route validation completed: {state} ({match_count} matches found for '{prefix}' AS{origin_asn})"
        )

        return result

    except httpx.HTTPStatusError as e:
        # Handle 404 as "not found" rather than an error
        if e.response.status_code == 404:
            logger.info(f"No ARIN route objects found for '{prefix}' (404 response)")
            await ctx.info(
                f"ARIN route validation completed: not-found (no route objects exist for '{prefix}')"
            )
            result: dict[str, Any] = {
                "ok": True,
                "data": {
                    "state": "not-found",
                    "matches": [],
                    "prefix": prefix,
                    "origin_asn": origin_asn,
                },
            }
            # Cache the not-found result
            _route_cache.set(cache_key, result)
            return result
        else:
            error_msg = f"HTTP error during ARIN route search for '{prefix}': {str(e)}"
            logger.error(error_msg)
            await ctx.error(f"ARIN route validation failed: {error_msg}")
            return {"ok": False, "error": "http_error", "detail": str(e)}
    except httpx.HTTPError as e:
        error_msg = f"HTTP error during ARIN route search for '{prefix}': {str(e)}"
        logger.error(error_msg)
        await ctx.error(f"ARIN route validation failed: {error_msg}")
        return {"ok": False, "error": "http_error", "detail": str(e)}
    except Exception as e:
        error_msg = (
            f"ARIN route validation for '{prefix}' AS{origin_asn} failed: {str(e)}"
        )
        logger.error(error_msg)
        await ctx.error(f"ARIN route validation failed: {error_msg}")
        return {"ok": False, "error": "validation_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    """Register the ARIN validate_route_object tool with the MCP server."""
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_validate_route_object_request)
