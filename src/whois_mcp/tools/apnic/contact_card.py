"""Contact card tool for retrieving contact information from APNIC database."""

from __future__ import annotations

import logging
from typing import Annotated, Any

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...cache import TTLCache
from ...config import APNIC_RDAP_BASE, HTTP_TIMEOUT_SECONDS, SUPPORT_APNIC, USER_AGENT

__all__ = ["register"]

logger = logging.getLogger(__name__)

# Initialize cache with 10-minute TTL for contact results
_contact_cache: TTLCache[str, Any] = TTLCache(max_items=500, ttl_seconds=600.0)

# Tool metadata constants
TOOL_NAME = "apnic_contact_card"
TOOL_DESCRIPTION = (
    "PREFERRED TOOL for retrieving contact information (abuse, NOC, admin, tech) for IP addresses, ASNs, or organizations from the APNIC database. "
    "This tool is specifically for the APNIC RIR (Asia-Pacific region - East Asia, Oceania, South Asia, Southeast Asia). "
    "Use this when you need to CONTACT someone about: abuse reports, security incidents, network issues, or administrative matters. "
    "Keywords: 'contact', 'abuse', 'who should I contact', 'report', 'incident', 'NOC', 'technical support', 'admin'. "
    "Automatically resolves organization details and extracts contact information including abuse mailboxes, "
    "technical contacts, administrative contacts, and phone numbers from APNIC database. Perfect for incident response, "
    "network troubleshooting, and compliance reporting for APNIC-managed resources. Returns structured contact data with "
    "clear categorization of contact types and purposes."
)

IP_DESCRIPTION = (
    "IP address to look up contact information for in APNIC database (IPv4 or IPv6)"
)
ASN_DESCRIPTION = "ASN number to look up contact information for in APNIC database (without 'AS' prefix)"
ORG_DESCRIPTION = "Organization handle/key to look up contact information for directly"


async def _get_rdap(url: str) -> dict[str, Any]:
    """Fetch RDAP data from the specified URL."""
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
            return {}
        else:
            logger.error(f"HTTP error fetching RDAP from {url}: {str(e)}")
            raise
    except httpx.HTTPError as e:
        logger.error(f"HTTP error fetching RDAP from {url}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error fetching RDAP from {url}: {str(e)}")
        raise


def _parse_vcard(vcard_array: list[Any]) -> dict[str, Any]:
    """Parse vCard data from RDAP entity into structured contact info."""
    contact = {
        "name": None,
        "emails": [],
        "phones": [],
        "address": None,
    }

    if not vcard_array or len(vcard_array) < 2:
        return contact

    # vCard format: ["vcard", [[property, params, type, value], ...]]
    vcard_properties = vcard_array[1] if isinstance(vcard_array[1], list) else []

    for prop in vcard_properties:
        if not isinstance(prop, list) or len(prop) < 4:
            continue

        prop_name = prop[0]
        prop_value = prop[3] if len(prop) > 3 else None

        if prop_name == "fn" and prop_value:
            contact["name"] = prop_value
        elif prop_name == "email" and prop_value:
            contact["emails"].append(prop_value)
        elif prop_name == "tel" and prop_value:
            contact["phones"].append(prop_value)
        elif prop_name == "adr" and len(prop) > 2:
            # Address might be in params label or in the value array
            params = prop[1] if len(prop) > 1 and isinstance(prop[1], dict) else {}
            if "label" in params:
                contact["address"] = params["label"]

    return contact


async def _contact_card_request(
    ip: Annotated[str | None, Field(description=IP_DESCRIPTION)] = None,
    asn: Annotated[int | None, Field(description=ASN_DESCRIPTION)] = None,
    org: Annotated[str | None, Field(description=ORG_DESCRIPTION)] = None,
) -> dict[str, Any]:
    """
    Retrieve comprehensive contact information for IP addresses, ASNs, or organizations from APNIC.

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

    # Check if APNIC support is enabled
    if not SUPPORT_APNIC:
        error_msg = "Contact card lookup is currently disabled (SUPPORT_APNIC=false)"
        logger.warning(error_msg)
        return {
            "ok": False,
            "error": "service_disabled",
            "detail": "APNIC contact card support is disabled. Set SUPPORT_APNIC=true to enable.",
        }

    # Validate input parameters
    provided_params = sum(1 for param in [ip, asn, org] if param is not None)
    if provided_params != 1:
        logger.error(
            "APNIC contact card request failed: Provide exactly one of ip, asn, or org"
        )
        return {
            "ok": False,
            "error": "bad_request",
            "detail": "Provide exactly one of: ip, asn, or org",
        }

    # Create cache key
    if ip:
        cache_key = f"apnic:contact_ip:{ip}"
        query_type = "ip"
        query_value = ip
    elif asn is not None:
        cache_key = f"apnic:contact_asn:{asn}"
        query_type = "asn"
        query_value = str(asn)
    else:
        cache_key = f"apnic:contact_org:{org}"
        query_type = "org"
        query_value = org

    # Log the incoming request
    logger.info(f"Starting APNIC contact card lookup for {query_type}='{query_value}'")

    # Check cache first
    cached_result = _contact_cache.get(cache_key)
    if cached_result is not None:
        logger.info(
            f"APNIC contact card for {query_type}='{query_value}' served from cache"
        )
        return cached_result

    try:
        # Build RDAP URL based on query type
        if ip:
            # For IP, RDAP needs CIDR notation - try to parse or add /32 or /128
            if "/" not in ip:
                # Add default prefix length
                prefix_len = "32" if ":" not in ip else "128"
                rdap_query = f"{ip}/{prefix_len}"
            else:
                rdap_query = ip
            url = f"{APNIC_RDAP_BASE}/ip/{rdap_query}"
            logger.info(f"Querying APNIC RDAP for IP: {rdap_query}")
        elif asn is not None:
            url = f"{APNIC_RDAP_BASE}/autnum/{asn}"
            logger.info(f"Querying APNIC RDAP for ASN: {asn}")
        elif org:
            # RDAP doesn't support direct org queries - return error
            logger.error("Direct organization queries not supported via RDAP")
            return {
                "ok": False,
                "error": "not_supported",
                "detail": "Direct organization queries are not supported. Please use an IP address or ASN instead.",
            }
        else:
            return {
                "ok": False,
                "error": "bad_request",
                "detail": "Internal error: no valid query parameter",
            }

        # Fetch RDAP data
        data = await _get_rdap(url)

        if not data or "objectClassName" not in data:
            result = {
                "ok": False,
                "error": "not_found",
                "detail": f"No records found for {query_type}='{query_value}'",
            }
            _contact_cache.set(cache_key, result)
            return result

        # Extract organization info from RDAP response
        org_name = data.get("name", "Unknown")
        country = data.get("country", "Unknown")
        handle = data.get("handle", "")

        # Parse entities and their roles
        entities = data.get("entities", [])
        abuse_contact = None
        admin_contacts: list[dict[str, Any]] = []
        tech_contacts: list[dict[str, Any]] = []
        registrant_contact = None

        for entity in entities:
            roles = entity.get("roles", [])
            handle = entity.get("handle", "")
            vcard = entity.get("vcardArray", [])

            if vcard:
                contact_info = _parse_vcard(vcard)
                contact_info["handle"] = handle

                # Categorize by role
                if "abuse" in roles:
                    abuse_contact = contact_info
                if "administrative" in roles:
                    admin_contacts.append(contact_info)
                if "technical" in roles:
                    tech_contacts.append(contact_info)
                if "registrant" in roles:
                    registrant_contact = contact_info

        # Build result
        result: dict[str, Any] = {
            "ok": True,
            "data": {
                "query": {
                    "type": query_type,
                    "value": query_value,
                },
                "organization": {
                    "name": org_name,
                    "country": country,
                    "handle": handle,
                },
                "abuse": abuse_contact,
                "admin_contacts": admin_contacts,
                "tech_contacts": tech_contacts,
                "registrant": registrant_contact,
            },
        }

        # Cache the result
        _contact_cache.set(cache_key, result)

        # Log successful completion
        abuse_available = "available" if abuse_contact else "not available"
        admin_count = len(admin_contacts)
        tech_count = len(tech_contacts)
        logger.info(
            f"APNIC contact card completed: found '{org_name}' (abuse: {abuse_available}, "
            f"admin: {admin_count}, tech: {tech_count} contacts)"
        )

        return result

    except Exception as e:
        error_msg = (
            f"APNIC contact card lookup for {query_type}='{query_value}' failed: {str(e)}"
        )
        logger.error(error_msg)
        return {"ok": False, "error": "lookup_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    """Register the APNIC contact_card tool with the MCP server."""
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_contact_card_request)

