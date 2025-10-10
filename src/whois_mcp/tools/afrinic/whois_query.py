"""AfriNIC WHOIS query tool."""

import asyncio
import contextlib
import logging
import time
from typing import Annotated, Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession
from pydantic import Field

from whois_mcp.cache import TTLCache
from whois_mcp.config import (
    AFRINIC_WHOIS_PORT,
    AFRINIC_WHOIS_SERVER,
    SUPPORT_AFRINIC,
    WHOIS_CONNECT_TIMEOUT_SECONDS,
    WHOIS_READ_TIMEOUT_SECONDS,
)

__all__ = ["register"]

# Configure logging
logger = logging.getLogger(__name__)

# Initialize cache with 5-minute TTL for WHOIS results
_whois_cache: TTLCache[str, Any] = TTLCache(max_items=1000, ttl_seconds=300.0)


def _get_whois_config() -> tuple[str, int]:
    """Get the appropriate WHOIS server and port based on RIR support configuration."""
    if SUPPORT_AFRINIC:
        return AFRINIC_WHOIS_SERVER, AFRINIC_WHOIS_PORT
    else:
        raise RuntimeError(
            "No RIR support enabled. Set SUPPORT_AFRINIC=true to enable AfriNIC queries."
        )


# Tool metadata constants
TOOL_NAME = "afrinic_whois_query"
TOOL_DESCRIPTION = (
    "Perform raw WHOIS queries against the AfriNIC database to get complete object information in RPSL format. "
    "This tool is specifically for the AfriNIC RIR (African region). "
    "Use ONLY when you need full object details or administrative data from AfriNIC. "
    "DO NOT use for contact information - use afrinic_contact_card for abuse, NOC, admin, or tech contacts. "
    "This returns raw AfriNIC database records with all attributes for detailed analysis."
)

QUERY_DESCRIPTION = (
    "The domain name, IP address, ASN, or other identifier to query via AfriNIC WHOIS. "
    "Examples: 'example.com', '196.216.2.0', 'AS37611', '2001:43f8::', 'AA1-AFRINIC'. "
    "Returns complete object details from the AfriNIC database."
)

FLAGS_DESCRIPTION = (
    "Optional WHOIS flags to modify the query behavior. Common AfriNIC flags: "
    "['-r'] for raw output (no filtering), ['-B'] for brief output, ['-T', 'person'] to limit object types. "
    "Use empty list [] or null for default query."
)


async def _whois_request(
    query: Annotated[str, Field(description=QUERY_DESCRIPTION)],
    flags: Annotated[
        list[str] | None,
        Field(default=None, description=FLAGS_DESCRIPTION),
    ] = None,
    *,
    ctx: Context[ServerSession, None],
) -> dict[str, Any]:
    """Execute a WHOIS request and return the result in a structured format."""

    # Check if AfriNIC support is enabled
    if not SUPPORT_AFRINIC:
        error_msg = "WHOIS queries are currently disabled (SUPPORT_AFRINIC=false)"
        logger.warning(error_msg)
        await ctx.error(error_msg)
        return {
            "ok": False,
            "error": "service_disabled",
            "detail": "AfriNIC WHOIS support is disabled. Set SUPPORT_AFRINIC=true to enable.",
        }

    # Create cache key from query and flags
    cache_key = f"afrinic:{query}|{','.join(flags or [])}"

    # Log the incoming request
    await ctx.info(
        f"AfriNIC WHOIS query requested: '{query}'"
        + (f" with flags: {flags}" if flags else "")
    )

    # Check cache first
    cached_result = _whois_cache.get(cache_key)
    if cached_result is not None:
        logger.info(f"AfriNIC WHOIS query for '{query}' served from cache")
        await ctx.info(f"AfriNIC WHOIS query for '{query}' served from cache")
        return cached_result

    line = (" ".join(flags or []) + " " + query).strip() + "\r\n"
    start = time.perf_counter()

    # Get appropriate WHOIS server configuration
    whois_server, whois_port = _get_whois_config()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(whois_server, whois_port),
            WHOIS_CONNECT_TIMEOUT_SECONDS,
        )

        writer.write(line.encode("utf-8"))
        await writer.drain()

        chunks: list[bytes] = []
        while True:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(8192), WHOIS_READ_TIMEOUT_SECONDS
                )
                if not chunk:
                    break
                chunks.append(chunk)
            except TimeoutError:
                break

        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()

        rpsl = b"".join(chunks).decode("utf-8", errors="replace")
        latency_ms = int((time.perf_counter() - start) * 1000)

        logger.info(f"AfriNIC WHOIS query for '{query}' completed in {latency_ms}ms")

        # Log successful completion via MCP context
        await ctx.info(
            f"AfriNIC WHOIS query for '{query}' completed successfully in {latency_ms}ms (server: {whois_server})"
        )

        result = {
            "ok": True,
            "data": {"rpsl": rpsl, "server": whois_server, "latency_ms": latency_ms},
        }

        # Cache the successful result
        _whois_cache.set(cache_key, result)

        return result

    except TimeoutError:
        error_msg = f"AfriNIC WHOIS query for '{query}' timed out"
        logger.error(error_msg)
        await ctx.error(f"{error_msg} (server: {whois_server})")
        return {
            "ok": False,
            "error": "timeout_error",
            "detail": "Connection or read timeout",
        }
    except (ConnectionError, OSError) as e:
        error_msg = f"Network error for AfriNIC WHOIS query '{query}': {str(e)}"
        logger.error(error_msg)
        await ctx.error(f"{error_msg} (server: {whois_server})")
        return {
            "ok": False,
            "error": "network_error",
            "detail": f"Network connection failed: {str(e)}",
        }
    except Exception as e:
        error_msg = f"Unexpected error for AfriNIC WHOIS query '{query}': {str(e)}"
        logger.error(error_msg)
        await ctx.error(f"{error_msg} (server: {whois_server})")
        return {
            "ok": False,
            "error": "internal_error",
            "detail": f"Internal server error: {str(e)}",
        }


def register(mcp: FastMCP) -> None:
    """Register the AfriNIC WHOIS query tool with the MCP server."""
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_whois_request)

