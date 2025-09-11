"""Contact card tool for retrieving contact information from RIPE database."""

from __future__ import annotations

import logging
from typing import Annotated, Any

import httpx
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.session import ServerSession
from pydantic import Field

from ..cache import TTLCache
from ..config import HTTP_TIMEOUT_SECONDS, RIPE_REST, USER_AGENT

__all__ = ["register"]

logger = logging.getLogger(__name__)

# Initialize cache with 10-minute TTL for contact results
_contact_cache: TTLCache[str, Any] = TTLCache(max_items=500, ttl_seconds=600.0)

# Tool metadata constants
TOOL_NAME = "contact_card"
TOOL_DESCRIPTION = (
    "Retrieve contact information (abuse, NOC, admin) for IP addresses, ASNs, or organizations. "
    "Automatically resolves organization details and extracts abuse mailboxes, NOC contacts, "
    "phone numbers, and administrative information from RIPE database. Perfect for incident response, "
    "network troubleshooting, and compliance reporting. Returns structured contact data with "
    "clear categorization of contact types and purposes."
)

IP_DESCRIPTION = "IP address to look up contact information for (IPv4 or IPv6)"
ASN_DESCRIPTION = "ASN number to look up contact information for (without 'AS' prefix)"
ORG_DESCRIPTION = "Organization handle/key to look up contact information for directly"


async def _get_json(url: str) -> dict[str, Any]:
    """Fetch JSON data from the specified URL."""
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.debug(f"Resource not found (404): {url}")
            return {"objects": {"object": []}}
        else:
            logger.error(f"HTTP error fetching JSON from {url}: {str(e)}")
            raise
    except httpx.HTTPError as e:
        logger.error(f"HTTP error fetching JSON from {url}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error fetching JSON from {url}: {str(e)}")
        raise


def _attrs(obj: dict[str, Any], name: str) -> list[str]:
    """Extract attribute values by name from an object."""
    return [
        attr.get("value", "").strip()
        for attr in obj.get("attributes", {}).get("attribute", [])
        if attr.get("name") == name and attr.get("value", "").strip()
    ]


async def _contact_card_request(
    ip: Annotated[str | None, Field(description=IP_DESCRIPTION)] = None,
    asn: Annotated[int | None, Field(description=ASN_DESCRIPTION)] = None,
    org: Annotated[str | None, Field(description=ORG_DESCRIPTION)] = None,
    *,
    ctx: Context[ServerSession, None],
) -> dict[str, Any]:
    """
    Retrieve comprehensive contact information for IP addresses, ASNs, or organizations.

    This tool automatically resolves organization details and extracts contact information
    including abuse mailboxes, NOC contacts, phone numbers, and administrative details.
    Perfect for incident response, network troubleshooting, and compliance reporting.

    Args:
        ip: IP address (IPv4 or IPv6) to look up contact information for
        asn: ASN number (without 'AS' prefix) to look up contact information for
        org: Organization handle/key to look up contact information for directly

    Returns: {"ok": true, "data": {"org": "...", "abuse": {...}, "contacts": [...], ...}}

    Note: Provide exactly one of ip, asn, or org parameters.
    """
    # Validate input parameters
    provided_params = sum(1 for param in [ip, asn, org] if param is not None)
    if provided_params != 1:
        await ctx.error("Contact card request failed: Provide exactly one of ip, asn, or org")
        return {
            "ok": False,
            "error": "bad_request",
            "detail": "Provide exactly one of: ip, asn, or org",
        }

    # Create cache key
    if ip:
        cache_key = f"contact_ip:{ip}"
        query_type = "ip"
        query_value = ip
    elif asn is not None:
        cache_key = f"contact_asn:{asn}"
        query_type = "asn"
        query_value = str(asn)
    else:
        cache_key = f"contact_org:{org}"
        query_type = "org"
        query_value = org

    # Log the incoming request
    await ctx.info(f"Starting contact card lookup for {query_type}='{query_value}'")

    # Check cache first
    cached_result = _contact_cache.get(cache_key)
    if cached_result is not None:
        logger.info(f"Contact card for {query_type}='{query_value}' served from cache")
        await ctx.info(f"Contact card for {query_type}='{query_value}' served from cache")
        return cached_result

    try:
        # Resolve organization key first
        org_key = org
        if not org_key:
            if ip:
                logger.info(f"Looking up organization for IP: {ip}")
                data = await _get_json(
                    f"{RIPE_REST}/search.json?query-string={ip}&type-filter=inetnum&type-filter=inet6num"
                )
            elif asn is not None:
                logger.info(f"Looking up organization for ASN: {asn}")
                data = await _get_json(f"{RIPE_REST}/ripe/aut-num/AS{asn}.json")
            else:
                # This should never happen due to input validation, but ensures data is bound
                return {
                    "ok": False,
                    "error": "bad_request",
                    "detail": "Internal error: no valid query parameter",
                }

            objs = data.get("objects", {}).get("object", [])
            if not objs:
                result = {
                    "ok": False,
                    "error": "not_found",
                    "detail": f"No records found for {query_type}='{query_value}'",
                }
                _contact_cache.set(cache_key, result)
                return result

            # Find organization reference
            for obj in objs:
                org_refs = _attrs(obj, "org") or _attrs(obj, "organisation")
                if org_refs:
                    org_key = org_refs[0]
                    break

            if not org_key:
                result = {
                    "ok": False,
                    "error": "no_organisation",
                    "detail": f"No organization found for {query_type}='{query_value}'",
                }
                _contact_cache.set(cache_key, result)
                return result

        # Fetch organization details
        logger.info(f"Fetching organization details for: {org_key}")
        org_data = await _get_json(f"{RIPE_REST}/ripe/organisation/{org_key}.json")
        org_objs = org_data.get("objects", {}).get("object", [])

        if not org_objs:
            result = {
                "ok": False,
                "error": "org_not_found",
                "detail": f"Organization '{org_key}' not found",
            }
            _contact_cache.set(cache_key, result)
            return result

        org_obj = org_objs[0]

        # Extract basic organization info
        org_name = (_attrs(org_obj, "org-name") or [None])[0]
        country = (_attrs(org_obj, "country") or [None])[0]
        remarks = _attrs(org_obj, "remarks")

        # Get abuse contact
        abuse_c = (_attrs(org_obj, "abuse-c") or [None])[0]
        abuse_info = None

        if abuse_c:
            logger.info(f"Fetching abuse contact details for: {abuse_c}")
            try:
                abuse_data = await _get_json(f"{RIPE_REST}/ripe/role/{abuse_c}.json")
                abuse_objs = abuse_data.get("objects", {}).get("object", [])
                if abuse_objs:
                    abuse_obj = abuse_objs[0]
                    abuse_info = {
                        "handle": abuse_c,
                        "role": (_attrs(abuse_obj, "role") or [None])[0],
                        "emails": _attrs(abuse_obj, "e-mail"),
                        "phones": _attrs(abuse_obj, "phone"),
                        "remarks": _attrs(abuse_obj, "remarks"),
                    }
            except Exception as e:
                logger.warning(f"Failed to fetch abuse contact {abuse_c}: {str(e)}")

        # Get admin and tech contacts
        admin_contacts: list[dict[str, Any]] = []
        tech_contacts: list[dict[str, Any]] = []

        for contact_type, contact_list in [
            ("admin-c", admin_contacts),
            ("tech-c", tech_contacts),
        ]:
            contact_handles = _attrs(org_obj, contact_type)
            for handle in contact_handles:
                try:
                    logger.debug(
                        f"Fetching {contact_type} contact details for: {handle}"
                    )
                    contact_data = await _get_json(
                        f"{RIPE_REST}/ripe/person/{handle}.json"
                    )
                    contact_objs = contact_data.get("objects", {}).get("object", [])
                    if contact_objs:
                        contact_obj = contact_objs[0]
                        contact_info = {
                            "handle": handle,
                            "person": (_attrs(contact_obj, "person") or [None])[0],
                            "emails": _attrs(contact_obj, "e-mail"),
                            "phones": _attrs(contact_obj, "phone"),
                            "remarks": _attrs(contact_obj, "remarks"),
                        }
                        contact_list.append(contact_info)
                except Exception as e:
                    logger.warning(
                        f"Failed to fetch {contact_type} contact {handle}: {str(e)}"
                    )

        # Build result
        result: dict[str, Any] = {
            "ok": True,
            "data": {
                "query": {
                    "type": query_type,
                    "value": query_value,
                },
                "organization": {
                    "key": org_key,
                    "name": org_name,
                    "country": country,
                    "remarks": remarks,
                },
                "abuse": abuse_info,
                "admin_contacts": admin_contacts,
                "tech_contacts": tech_contacts,
            },
        }

        # Cache the result
        _contact_cache.set(cache_key, result)
        
        # Log successful completion via MCP context
        org_name = result["data"]["organization"]["name"]
        abuse_available = "available" if result["data"]["abuse"] else "not available"
        admin_count = len(result["data"]["admin_contacts"])
        tech_count = len(result["data"]["tech_contacts"])
        await ctx.info(
            f"Contact card completed: found '{org_name}' (abuse: {abuse_available}, "
            f"admin: {admin_count}, tech: {tech_count} contacts)"
        )
        
        logger.info(
            f"Contact card lookup for {query_type}='{query_value}' completed successfully"
        )
        return result

    except Exception as e:
        error_msg = f"Contact card lookup for {query_type}='{query_value}' failed: {str(e)}"
        logger.error(error_msg)
        await ctx.error(f"Contact card lookup failed: {error_msg}")
        return {"ok": False, "error": "lookup_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    """Register the contact_card tool with the MCP server."""
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_contact_card_request)
