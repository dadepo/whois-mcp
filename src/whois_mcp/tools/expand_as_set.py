import logging
from typing import Annotated, Any

import aiohttp
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from whois_mcp.cache import TTLCache
from whois_mcp.config import HTTP_TIMEOUT_SECONDS, RIPE_REST, USER_AGENT

__all__ = ["register"]

# Configure logging
logger = logging.getLogger(__name__)

# Initialize cache with 5-minute TTL for AS-SET results
_as_set_cache: TTLCache[str, Any] = TTLCache(max_items=1000, ttl_seconds=300.0)

# Tool metadata constants
TOOL_NAME = "expand_as_set"
TOOL_DESCRIPTION = (
    "Efficiently expand AS-SET objects into concrete ASNs with configurable depth. "
    "Use this instead of whois_query when you need ASNs from an AS-SET. "
    "CRITICAL: For 'top-level', 'direct', or 'immediate' members, use max_depth=1. "
    "For complete expansion, use max_depth=10+. Large AS-SETs like 'AS-RETN' have hundreds "
    "of nested AS-SETs - choose depth carefully to balance completeness vs speed. "
    "Automatically handles recursive expansion, deduplication, and cycle detection. "
    "Perfect for network analysis, route filtering, and policy generation."
)

SETNAME_DESCRIPTION = (
    "AS-SET name to recursively expand into concrete ASN numbers. "
    "Examples: 'AS-CLOUDFLARE', 'AS-GOOGLE', 'AS-RETN'. "
    "The tool will automatically resolve all nested AS-SETs and return a complete "
    "list of individual ASNs contained within the hierarchy."
)

MAX_DEPTH_DESCRIPTION = (
    "Maximum recursion depth for AS-SET expansion (1-20 levels, default: 10). "
    "IMPORTANT: Use depth=1 for 'top-level' or 'direct' members only. "
    "Use depth=2-3 for shallow analysis, depth=10 for complete expansion. "
    "Higher values provide more complete results but take much longer to process. "
    "For questions about 'immediate' or 'direct' members, always use depth=1."
)


async def _get_json(url: str) -> dict[str, Any]:
    """Fetch JSON data from the specified URL."""
    try:
        async with aiohttp.ClientSession(
            headers={"User-Agent": USER_AGENT},
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS),
        ) as session:
            async with session.get(url) as response:
                response.raise_for_status()
                logger.debug(f"Successfully fetched JSON from {url}")
                return await response.json()
    except aiohttp.ClientResponseError as e:
        if e.status == 404:
            # Return empty structure for 404s (AS-SET not found)
            logger.debug(f"AS-SET not found (404): {url}")
            return {"objects": {"object": []}}
        else:
            logger.error(f"HTTP error fetching JSON from {url}: {str(e)}")
            raise
    except aiohttp.ClientError as e:
        logger.error(f"Failed to fetch JSON from {url}: {str(e)}")
        raise


def _attrs(obj: dict[str, Any], name: str) -> list[str]:
    """Extract attribute values by name from an object."""
    return [
        attr.get("value", "").strip()
        for attr in obj.get("attributes", {}).get("attribute", [])
        if attr.get("name") == name and attr.get("value", "").strip()
    ]


async def _expand_as_set_recursive(
    setname: str,
    seen: set[str],
    out_asns: set[int],
    depth: int = 0,
    max_depth: int = 10,
) -> None:
    """Recursively expand an AS-SET into concrete ASNs (cycle-safe, depth-limited)."""
    if depth >= max_depth:
        logger.warning(
            f"Maximum recursion depth ({max_depth}) reached for AS-SET: {setname}"
        )
        return

    if setname in seen:
        logger.debug(f"Cycle detected for AS-SET: {setname}")
        return
    seen.add(setname)

    cache_key = f"as_set:{setname}"
    cached_result = _as_set_cache.get(cache_key)
    if cached_result:
        logger.debug(f"Cache hit for AS-SET: {setname}")
        out_asns.update(cached_result)
        return

    try:
        url = f"{RIPE_REST}/ripe/as-set/{setname}.json"
        data = await _get_json(url)
        objects = data.get("objects", {}).get("object", [])
        if not objects:
            logger.warning(f"No objects found for AS-SET: {setname}")
            return

        obj = objects[0]
        asns: set[int] = set()
        for member in _attrs(obj, "members"):
            if member.upper().startswith("AS") and member[2:].isdigit():
                asns.add(int(member[2:]))
            elif member.upper().startswith("AS-"):
                try:
                    await _expand_as_set_recursive(
                        member, seen, asns, depth + 1, max_depth
                    )
                except Exception as e:
                    logger.warning(f"Failed to expand nested AS-SET {member}: {str(e)}")
                    # Continue with other members even if one fails

        _as_set_cache.set(cache_key, asns)
        out_asns.update(asns)
        logger.info(f"Successfully expanded AS-SET {setname} with {len(asns)} ASNs")
    except Exception as e:
        logger.error(f"Failed to expand AS-SET {setname}: {str(e)}")
        raise


async def _expand_as_set_request(
    setname: Annotated[str, Field(description=SETNAME_DESCRIPTION)],
    max_depth: Annotated[
        int,
        Field(description=MAX_DEPTH_DESCRIPTION, ge=1, le=20),
    ] = 10,
) -> dict[str, Any]:
    """
    Expand an AS-SET into all concrete ASNs and return the result in a structured format.

    This tool recursively resolves AS-SET hierarchies with configurable depth limits,
    automatically handling cycles and deduplication. Much more efficient than multiple
    whois_query calls when you need complete AS-SET membership information.

    Args:
        setname: The AS-SET name to expand (e.g., 'AS-RETN')
        max_depth: Maximum recursion depth (1-20, default: 10). Use lower values (3-5)
                  for quick analysis, higher values (15-20) for comprehensive expansion.
                  Most AS-SETs are fully resolved within 10 levels.

    Returns: {"ok": true, "data": {"as_set": "...", "asns": [1234, 5678, ...], "count": N}}

    Performance Notes:
    - Depth 1: FAST - Only direct/immediate members (use for "top-level" questions)
    - Depth 2-3: Quick overview with one level of nesting
    - Depth 6-10: Balanced, handles most real-world AS-SETs completely
    - Depth 11-20: Comprehensive, may be very slow for large AS-SETs like AS-RETN
    """
    # Check cache first
    cache_key = f"as_set:{setname}"
    cached_result = _as_set_cache.get(cache_key)
    if cached_result is not None:
        logger.info(f"AS-SET expansion for '{setname}' served from cache")
        return {
            "ok": True,
            "data": {
                "as_set": setname,
                "asns": sorted(cached_result),
                "count": len(cached_result),
            },
        }

    try:
        seen: set[str] = set()
        asns: set[int] = set()
        await _expand_as_set_recursive(setname, seen, asns, 0, max_depth)

        # Check if the AS-SET was found (if seen contains only the original setname, it wasn't found)
        if len(asns) == 0 and len(seen) <= 1:
            logger.info(f"AS-SET '{setname}' not found or contains no ASNs")
            result: dict[str, Any] = {
                "ok": True,
                "data": {
                    "as_set": setname,
                    "asns": [],
                    "count": 0,
                    "status": "not-found",
                },
            }
        else:
            result = {
                "ok": True,
                "data": {
                    "as_set": setname,
                    "asns": sorted(asns),
                    "count": len(asns),
                    "status": "expanded",
                },
            }

        logger.info(f"AS-SET expansion for '{setname}' completed with {len(asns)} ASNs")
        return result

    except Exception as e:
        logger.error(f"AS-SET expansion for '{setname}' failed: {str(e)}")
        return {"ok": False, "error": "expansion_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    """Register the expand_as_set tool with the MCP server."""
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_expand_as_set_request)
