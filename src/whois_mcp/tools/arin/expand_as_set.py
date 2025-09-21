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

# Initialize cache with 5-minute TTL for AS-SET results
_as_set_cache: TTLCache[str, Any] = TTLCache(max_items=1000, ttl_seconds=300.0)

# Tool metadata constants
TOOL_NAME = "arin_expand_as_set"
TOOL_DESCRIPTION = (
    "Efficiently expand AS-SET objects from the ARIN IRR database into concrete ASNs with configurable depth. "
    "This tool is specifically for the ARIN RIR (North America region - United States, Canada, parts of Caribbean). "
    "Use this instead of whois_query when you need ASNs from an ARIN AS-SET. "
    "CRITICAL: For 'top-level', 'direct', or 'immediate' members, use max_depth=1. "
    "For complete expansion, use max_depth=10+. Large AS-SETs may have nested structures - "
    "choose depth carefully to balance completeness vs speed. "
    "Automatically handles recursive expansion, deduplication, and cycle detection. "
    "Perfect for network analysis, route filtering, and policy generation for ARIN-managed AS-SETs."
)

SETNAME_DESCRIPTION = (
    "AS-SET name to recursively expand into concrete ASN numbers from ARIN IRR database. "
    "Examples: 'AS-COMCAST', 'AS-VERIZON', 'AS-ATT'. "
    "The tool will automatically resolve all nested AS-SETs and return a complete "
    "list of individual ASNs contained within the hierarchy from ARIN IRR records."
)

MAX_DEPTH_DESCRIPTION = (
    "Maximum recursion depth for AS-SET expansion (1-20 levels, default: 10). "
    "IMPORTANT: Use depth=1 for 'top-level' or 'direct' members only. "
    "Use depth=2-3 for shallow analysis, depth=10 for complete expansion. "
    "Higher values provide more complete results but take much longer to process. "
    "For questions about 'immediate' or 'direct' members, always use depth=1."
)


async def _get_as_set_data(setname: str) -> dict[str, Any]:
    """Fetch AS-SET data from ARIN's IRR database."""
    # ARIN IRR AS-SET endpoint
    url = f"{ARIN_REST_BASE}/irr/as-set/{setname}"

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        follow_redirects=True,
    ) as client:
        try:
            response = await client.get(url)

            # ARIN may return 404 for non-existent AS-SETs
            if response.status_code == 404:
                logger.debug(f"AS-SET not found (404): {setname}")
                return {"members": []}

            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"AS-SET not found (404): {setname}")
                return {"members": []}
            else:
                logger.error(f"HTTP error fetching AS-SET {setname}: {str(e)}")
                raise
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch AS-SET {setname}: {str(e)}")
            raise


def _extract_members(data: dict[str, Any]) -> list[str]:
    """Extract member list from ARIN AS-SET response."""
    # ARIN's response format may vary, handle different possible structures
    members: list[str] = []

    # Try different possible field names for members
    for field in ["members", "member", "as-set", "asSet"]:
        if field in data:
            member_data: str | list[str] = data[field]
            if isinstance(member_data, list):
                for item in member_data:
                    if item:
                        members.append(str(item).strip())
            else:
                members.extend(
                    [
                        m.strip()
                        for m in member_data.replace(",", " ").split()
                        if m.strip()
                    ]
                )
            break

    return members


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
            f"Maximum recursion depth ({max_depth}) reached for ARIN AS-SET: {setname}"
        )
        return

    if setname in seen:
        logger.debug(f"Cycle detected for ARIN AS-SET: {setname}")
        return
    seen.add(setname)

    cache_key = f"arin:as_set:{setname}"
    cached_result = _as_set_cache.get(cache_key)
    if cached_result:
        logger.debug(f"Cache hit for ARIN AS-SET: {setname}")
        out_asns.update(cached_result)
        return

    try:
        data = await _get_as_set_data(setname)
        members = _extract_members(data)

        if not members:
            logger.warning(f"No members found for ARIN AS-SET: {setname}")
            return

        asns: set[int] = set()
        for member in members:
            member = member.strip().upper()
            if member.startswith("AS") and member[2:].isdigit():
                # Direct ASN member
                asns.add(int(member[2:]))
            elif member.startswith("AS-"):
                # Nested AS-SET - recurse
                try:
                    await _expand_as_set_recursive(
                        member, seen, asns, depth + 1, max_depth
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to expand nested ARIN AS-SET {member}: {str(e)}"
                    )
                    # Continue with other members even if one fails

        _as_set_cache.set(cache_key, asns)
        out_asns.update(asns)
        logger.info(
            f"Successfully expanded ARIN AS-SET {setname} with {len(asns)} ASNs"
        )
    except Exception as e:
        logger.error(f"Failed to expand ARIN AS-SET {setname}: {str(e)}")
        raise


async def _expand_as_set_request(
    setname: Annotated[str, Field(description=SETNAME_DESCRIPTION)],
    max_depth: Annotated[
        int,
        Field(description=MAX_DEPTH_DESCRIPTION, ge=1, le=20),
    ] = 10,
    *,
    ctx: Context[ServerSession, None],
) -> dict[str, Any]:
    """
    Expand an ARIN AS-SET into all concrete ASNs and return the result in a structured format.

    This tool recursively resolves AS-SET hierarchies with configurable depth limits,
    automatically handling cycles and deduplication. Much more efficient than multiple
    whois_query calls when you need complete AS-SET membership information from ARIN IRR.

    Args:
        setname: The AS-SET name to expand (e.g., 'AS-COMCAST')
        max_depth: Maximum recursion depth (1-20, default: 10). Use lower values (3-5)
                  for quick analysis, higher values (15-20) for comprehensive expansion.
                  Most AS-SETs are fully resolved within 10 levels.

    Returns: {"ok": true, "data": {"as_set": "...", "asns": [1234, 5678, ...], "count": N}}

    Performance Notes:
    - Depth 1: FAST - Only direct/immediate members (use for "top-level" questions)
    - Depth 2-3: Quick overview with one level of nesting
    - Depth 6-10: Balanced, handles most real-world AS-SETs completely
    - Depth 11-20: Comprehensive, may be very slow for large AS-SETs
    """

    # Check if ARIN support is enabled
    if not SUPPORT_ARIN:
        error_msg = "AS-SET expansion is currently disabled (SUPPORT_ARIN=false)"
        logger.warning(error_msg)
        await ctx.error(error_msg)
        return {
            "ok": False,
            "error": "service_disabled",
            "detail": "ARIN AS-SET expansion support is disabled. Set SUPPORT_ARIN=true to enable.",
        }

    # Log the incoming request
    await ctx.info(
        f"Starting ARIN AS-SET expansion for '{setname}' with max_depth={max_depth}"
    )

    # Check cache first for the complete result
    cache_key = f"arin:as_set:{setname}:depth_{max_depth}"
    cached_result = _as_set_cache.get(cache_key)
    if cached_result is not None:
        logger.info(f"ARIN AS-SET expansion for '{setname}' served from cache")
        await ctx.info(
            f"ARIN AS-SET expansion for '{setname}' served from cache ({len(cached_result)} ASNs)"
        )
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

        # Check if the AS-SET was found
        if len(asns) == 0 and len(seen) <= 1:
            logger.info(f"ARIN AS-SET '{setname}' not found or contains no ASNs")
            await ctx.info(
                f"ARIN AS-SET expansion completed: not-found ('{setname}' does not exist or contains no ASNs)"
            )
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
            await ctx.info(
                f"ARIN AS-SET expansion completed: expanded (found {len(asns)} ASNs from '{setname}' at depth {max_depth})"
            )
            result = {
                "ok": True,
                "data": {
                    "as_set": setname,
                    "asns": sorted(asns),
                    "count": len(asns),
                    "status": "expanded",
                },
            }

        # Cache the complete result
        _as_set_cache.set(cache_key, asns)

        logger.info(
            f"ARIN AS-SET expansion for '{setname}' completed with {len(asns)} ASNs"
        )
        return result

    except Exception as e:
        error_msg = f"ARIN AS-SET expansion for '{setname}' failed: {str(e)}"
        logger.error(error_msg)
        await ctx.error(f"ARIN AS-SET expansion failed: {error_msg}")
        return {"ok": False, "error": "expansion_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    """Register the ARIN expand_as_set tool with the MCP server."""
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_expand_as_set_request)
