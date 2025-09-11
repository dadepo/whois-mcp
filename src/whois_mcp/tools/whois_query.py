import asyncio
import contextlib
import logging
import time
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.session import ServerSession
from pydantic import Field

from whois_mcp.cache import TTLCache
from whois_mcp.config import (
    WHOIS_CONNECT_TIMEOUT_SECONDS,
    WHOIS_PORT,
    WHOIS_READ_TIMEOUT_SECONDS,
    WHOIS_SERVER,
)

__all__ = ["register"]

# Configure logging
logger = logging.getLogger(__name__)

# Initialize cache with 5-minute TTL for WHOIS results
_whois_cache: TTLCache[str, Any] = TTLCache(max_items=1000, ttl_seconds=300.0)

# Tool metadata constants
TOOL_NAME = "whois_query"
TOOL_DESCRIPTION = (
    "Perform raw WHOIS queries to get complete object information in RPSL format. "
    "Use ONLY when you need full object details, contact information, or administrative data. "
    "DO NOT use for route validation - use validate_route_object for checking if route objects exist. "
    "DO NOT use for AS-SET expansion - use expand_as_set for getting ASN lists. "
    "This returns raw database records with all attributes for detailed analysis."
)

QUERY_DESCRIPTION = (
    "The domain name, IP address, ASN, or other identifier to query via WHOIS. "
    "Examples: 'example.com', '192.0.2.1', 'AS64496', 'RIPE-NCC-HM-MNT'. "
    "Returns complete object details from the WHOIS database."
)

FLAGS_DESCRIPTION = (
    "Optional WHOIS flags to modify the query behavior. Common flags: "
    "['-B'] for brief output (less verbose), ['-r'] for raw output (no filtering), "
    "['-T', 'person'] to limit object types. Use empty list [] or null for default query."
)


async def _whois_request(
    query: Annotated[str, Field(description=QUERY_DESCRIPTION)],
    ctx: Context[ServerSession, None],
    flags: Annotated[
        list[str] | None,
        Field(default=None, description=FLAGS_DESCRIPTION),
    ] = None,
) -> dict[str, Any]:
    """Execute a WHOIS request and return the result in a structured format."""
    # Create cache key from query and flags
    cache_key = f"{query}|{','.join(flags or [])}"
    
    # Log the incoming request
    await ctx.info(f"Starting WHOIS query for '{query}'" + (f" with flags {flags}" if flags else ""))

    # Check cache first
    cached_result = _whois_cache.get(cache_key)
    if cached_result is not None:
        logger.info(f"WHOIS query for '{query}' served from cache")
        await ctx.info(f"WHOIS query for '{query}' served from cache")
        return cached_result

    line = (" ".join(flags or []) + " " + query).strip() + "\r\n"
    start = time.perf_counter()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(WHOIS_SERVER, WHOIS_PORT),
            WHOIS_CONNECT_TIMEOUT_SECONDS,
        )

        writer.write(line.encode("utf-8"))
        await writer.drain()

        chunks: list[bytes] = []
        while True:
            chunk = await asyncio.wait_for(
                reader.read(65536), WHOIS_READ_TIMEOUT_SECONDS
            )
            if not chunk:
                break
            chunks.append(chunk)

        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

        rpsl = b"".join(chunks).decode("utf-8", errors="replace")
        latency_ms = int((time.perf_counter() - start) * 1000)

        logger.info(f"WHOIS query for '{query}' completed in {latency_ms}ms")
        
        # Log successful completion via MCP context
        await ctx.info(f"WHOIS query for '{query}' completed successfully in {latency_ms}ms (server: {WHOIS_SERVER})")

        result = {
            "ok": True,
            "data": {"rpsl": rpsl, "server": WHOIS_SERVER, "latency_ms": latency_ms},
        }

        # Cache the successful result
        _whois_cache.set(cache_key, result)

        return result

    except TimeoutError:
        error_msg = f"WHOIS query for '{query}' timed out"
        logger.error(error_msg)
        await ctx.error(f"{error_msg} (server: {WHOIS_SERVER})")
        return {
            "ok": False,
            "error": "timeout_error",
            "detail": "Connection or read timeout",
        }
    except (ConnectionError, OSError) as e:
        error_msg = f"Network error for WHOIS query '{query}': {str(e)}"
        logger.error(error_msg)
        await ctx.error(f"{error_msg} (server: {WHOIS_SERVER})")
        return {
            "ok": False,
            "error": "network_error",
            "detail": f"Network connection failed: {str(e)}",
        }
    except Exception as e:
        error_msg = f"WHOIS query for '{query}' failed: {str(e)}"
        logger.error(error_msg)
        await ctx.error(f"{error_msg} (server: {WHOIS_SERVER})")
        return {"ok": False, "error": "whois_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_whois_request)
