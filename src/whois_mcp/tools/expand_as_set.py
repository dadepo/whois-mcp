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
    setname: str, seen: set[str], out_asns: set[int]
) -> None:
    """Recursively expand an AS-SET into concrete ASNs (cycle-safe)."""
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
                await _expand_as_set_recursive(member, seen, asns)

        _as_set_cache.set(cache_key, asns)
        out_asns.update(asns)
        logger.info(f"Successfully expanded AS-SET {setname} with {len(asns)} ASNs")
    except Exception as e:
        logger.error(f"Failed to expand AS-SET {setname}: {str(e)}")
        raise


async def _expand_as_set_request(
    setname: Annotated[
        str,
        Field(
            description="AS-SET name to expand (e.g., 'AS-CLOUDFLARE', 'AS-GOOGLE', 'AS-RETN')"
        ),
    ],
) -> dict[str, Any]:
    """
    Expand an AS-SET into all concrete ASNs and return the result in a structured format.

    This tool recursively resolves AS-SET hierarchies that may be hundreds of levels deep,
    automatically handling cycles and deduplication. Much more efficient than multiple
    whois_query calls when you need complete AS-SET membership information.

    Returns: {"ok": true, "data": {"as_set": "...", "asns": [1234, 5678, ...], "count": N}}
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
        await _expand_as_set_recursive(setname, seen, asns)

        result = {
            "ok": True,
            "data": {"as_set": setname, "asns": sorted(asns), "count": len(asns)},
        }

        logger.info(f"AS-SET expansion for '{setname}' completed with {len(asns)} ASNs")
        return result

    except Exception as e:
        logger.error(f"AS-SET expansion for '{setname}' failed: {str(e)}")
        return {"ok": False, "error": "expansion_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    """Register the expand_as_set tool with the MCP server."""
    mcp.tool(
        name="expand_as_set",
        description=(
            "Efficiently expand AS-SET objects into complete lists of concrete ASNs. "
            "Use this instead of whois_query when you need ALL ASNs from an AS-SET, "
            "as it automatically handles recursive expansion, deduplication, and cycle detection. "
            "A single AS-SET like 'AS-RETN' may contain hundreds of nested AS-SETs and ASNs - "
            "this tool flattens the entire hierarchy in one call, returning a sorted list "
            "with count metadata. Perfect for network analysis, route filtering, and policy generation."
        ),
    )(_expand_as_set_request)
