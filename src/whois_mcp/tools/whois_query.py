import asyncio
import contextlib
import logging
import time
from typing import Annotated, Dict, List, Optional, Union

from mcp.server.fastmcp import FastMCP
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
_whois_cache = TTLCache(max_items=1000, ttl_seconds=300.0)


async def _whois_request(
    query: Annotated[
        str,
        Field(
            description="The domain name, IP address, or other identifier to query via WHOIS"
        ),
    ],
    flags: Annotated[
        Optional[List[str]],
        Field(
            default=None,
            description="Optional WHOIS flags to modify the query (e.g., ['-B'] for brief output, ['-r'] for raw output)",
        ),
    ] = None,
) -> Dict[str, Union[bool, str, Dict[str, Union[str, int]]]]:
    """Execute a WHOIS request and return the result in a structured format."""
    # Create cache key from query and flags
    cache_key = f"{query}|{','.join(flags or [])}"

    # Check cache first
    cached_result = _whois_cache.get(cache_key)
    if cached_result is not None:
        logger.info(f"WHOIS query for '{query}' served from cache")
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

        chunks: List[bytes] = []
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

        result = {
            "ok": True,
            "data": {"rpsl": rpsl, "server": WHOIS_SERVER, "latency_ms": latency_ms},
        }

        # Cache the successful result
        _whois_cache.set(cache_key, result)

        return result

    except asyncio.TimeoutError:
        logger.error(f"WHOIS query for '{query}' timed out")
        return {
            "ok": False,
            "error": "timeout_error",
            "detail": "Connection or read timeout",
        }
    except Exception as e:
        logger.error(f"WHOIS query for '{query}' failed: {str(e)}")
        return {"ok": False, "error": "whois_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    mcp.tool(
        name="whois_query",
        description="Perform a raw WHOIS query (port 43) and return RPSL text.",
    )(_whois_request)
