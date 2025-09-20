"""Contact card tool for retrieving contact information from ARIN database."""

from __future__ import annotations

import logging
from typing import Annotated, Any

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...cache import TTLCache
from ...config import ARIN_REST_BASE, HTTP_TIMEOUT_SECONDS, SUPPORT_ARIN, USER_AGENT

__all__ = ["register"]

logger = logging.getLogger(__name__)

# Initialize cache with 10-minute TTL for contact results
_contact_cache: TTLCache[str, Any] = TTLCache(max_items=500, ttl_seconds=600.0)

# Tool metadata constants
TOOL_NAME = "arin_contact_card"
TOOL_DESCRIPTION = (
    "PREFERRED TOOL for retrieving contact information (abuse, NOC, admin, tech) for IP addresses, ASNs, or organizations from the ARIN database. "
    "This tool is specifically for the ARIN RIR (North America region - United States, Canada, parts of Caribbean). "
    "Use this when you need to CONTACT someone about: abuse reports, security incidents, network issues, or administrative matters. "
    "Keywords: 'contact', 'abuse', 'who should I contact', 'report', 'incident', 'NOC', 'technical support', 'admin'. "
    "Automatically resolves organization details and extracts POC (Point of Contact) information including abuse mailboxes, "
    "technical contacts, administrative contacts, and phone numbers from ARIN database. Perfect for incident response, "
    "network troubleshooting, and compliance reporting for ARIN-managed resources. Returns structured contact data with "
    "clear categorization of contact types and purposes."
)

IP_DESCRIPTION = (
    "IP address to look up contact information for in ARIN database (IPv4 or IPv6)"
)
ASN_DESCRIPTION = "ASN number to look up contact information for in ARIN database (without 'AS' prefix)"
ORG_DESCRIPTION = "Organization handle/key to look up contact information for directly"


async def _get_json(url: str) -> dict[str, Any]:
    """Fetch JSON data from the specified URL."""
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
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
            logger.error(f"HTTP error fetching JSON from {url}: {str(e)}")
            raise
    except httpx.HTTPError as e:
        logger.error(f"HTTP error fetching JSON from {url}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error fetching JSON from {url}: {str(e)}")
        raise


async def _get_poc_details(poc_handle: str) -> dict[str, Any] | None:
    """Fetch POC (Point of Contact) details from ARIN."""
    try:
        url = f"{ARIN_REST_BASE}/poc/{poc_handle}"
        poc_data = await _get_json(url)

        if not poc_data:
            return None

        # Extract POC information from ARIN's response format
        poc = poc_data.get("poc", {})

        # Extract emails
        emails = []
        email_data = poc.get("emails", {})
        if isinstance(email_data.get("email"), list):
            emails = [
                email.get("$", "") for email in email_data["email"] if email.get("$")
            ]
        elif isinstance(email_data.get("email"), dict):
            email_val = email_data["email"].get("$", "")
            if email_val:
                emails = [email_val]

        # Extract phones
        phones = []
        phone_data = poc.get("phones", {})
        if isinstance(phone_data.get("phone"), list):
            phones = [
                phone.get("$", "") for phone in phone_data["phone"] if phone.get("$")
            ]
        elif isinstance(phone_data.get("phone"), dict):
            phone_val = phone_data["phone"].get("$", "")
            if phone_val:
                phones = [phone_val]

        return {
            "handle": poc_handle,
            "name": poc.get("companyName", {}).get("$", "")
            or poc.get("contactName", {}).get("$", ""),
            "emails": emails,
            "phones": phones,
            "type": poc.get("contactType", {}).get("$", ""),
        }
    except Exception as e:
        logger.warning(f"Failed to fetch POC details for {poc_handle}: {str(e)}")
        return None


async def _contact_card_request(
    ip: Annotated[str | None, Field(description=IP_DESCRIPTION)] = None,
    asn: Annotated[int | None, Field(description=ASN_DESCRIPTION)] = None,
    org: Annotated[str | None, Field(description=ORG_DESCRIPTION)] = None,
) -> dict[str, Any]:
    """
    Retrieve comprehensive contact information for IP addresses, ASNs, or organizations from ARIN.

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

    # Check if ARIN support is enabled
    if not SUPPORT_ARIN:
        error_msg = "Contact card lookup is currently disabled (SUPPORT_ARIN=false)"
        logger.warning(error_msg)
        return {
            "ok": False,
            "error": "service_disabled",
            "detail": "ARIN contact card support is disabled. Set SUPPORT_ARIN=true to enable.",
        }

    # Validate input parameters
    provided_params = sum(1 for param in [ip, asn, org] if param is not None)
    if provided_params != 1:
        logger.error(
            "ARIN contact card request failed: Provide exactly one of ip, asn, or org"
        )
        return {
            "ok": False,
            "error": "bad_request",
            "detail": "Provide exactly one of: ip, asn, or org",
        }

    # Create cache key
    if ip:
        cache_key = f"arin:contact_ip:{ip}"
        query_type = "ip"
        query_value = ip
    elif asn is not None:
        cache_key = f"arin:contact_asn:{asn}"
        query_type = "asn"
        query_value = str(asn)
    else:
        cache_key = f"arin:contact_org:{org}"
        query_type = "org"
        query_value = org

    # Log the incoming request
    logger.info(f"Starting ARIN contact card lookup for {query_type}='{query_value}'")

    # Check cache first
    cached_result = _contact_cache.get(cache_key)
    if cached_result is not None:
        logger.info(
            f"ARIN contact card for {query_type}='{query_value}' served from cache"
        )
        # Already logged above
        return cached_result

    try:
        # Fetch data from ARIN based on query type
        if ip:
            logger.info(f"Looking up ARIN data for IP: {ip}")
            url = f"{ARIN_REST_BASE}/ip/{ip}"
        elif asn is not None:
            logger.info(f"Looking up ARIN data for ASN: {asn}")
            url = f"{ARIN_REST_BASE}/asn/AS{asn}"
        else:  # org
            logger.info(f"Looking up ARIN data for organization: {org}")
            url = f"{ARIN_REST_BASE}/org/{org}"

        data = await _get_json(url)

        if not data:
            result = {
                "ok": False,
                "error": "not_found",
                "detail": f"No records found for {query_type}='{query_value}'",
            }
            _contact_cache.set(cache_key, result)
            return result

        # Extract organization information
        org_info = {}
        org_handle = None

        if "net" in data:
            # IP lookup response
            net_data = data["net"]
            org_ref = net_data.get("orgRef", {})
            org_handle = org_ref.get("@handle", "")
            org_info = {
                "key": org_handle,
                "name": org_ref.get("@name", ""),
                "country": "US",  # ARIN is primarily US-based
            }
        elif "asn" in data:
            # ASN lookup response
            asn_data = data["asn"]
            org_ref = asn_data.get("orgRef", {})
            org_handle = org_ref.get("@handle", "")
            org_info = {
                "key": org_handle,
                "name": org_ref.get("@name", ""),
                "country": "US",
            }
        elif "org" in data:
            # Organization lookup response
            org_data = data["org"]
            org_handle = org_data.get("handle", {}).get("$", "")
            org_info = {
                "key": org_handle,
                "name": org_data.get("name", {}).get("$", ""),
                "country": "US",
            }

        # Get POC links
        poc_links = []
        if "net" in data:
            poc_links_data = data["net"].get("pocLinks", {})
        elif "asn" in data:
            poc_links_data = data["asn"].get("pocLinks", {})
        elif "org" in data:
            poc_links_data = data["org"].get("pocLinks", {})
        else:
            poc_links_data = {}

        if poc_links_data and "pocLinkRef" in poc_links_data:
            poc_refs = poc_links_data["pocLinkRef"]
            if not isinstance(poc_refs, list):
                poc_refs = [poc_refs]

            for poc_ref in poc_refs:
                poc_handle = poc_ref.get("@handle", "")
                poc_function = poc_ref.get("@function", "")
                if poc_handle:
                    poc_links.append(
                        {
                            "handle": poc_handle,
                            "function": poc_function,
                        }
                    )

        # Fetch detailed POC information
        abuse_contact = None
        admin_contacts = []
        tech_contacts = []
        noc_contacts = []

        for poc_link in poc_links:
            poc_details = await _get_poc_details(poc_link["handle"])
            if poc_details:
                function = poc_link["function"].lower()
                if "abuse" in function:
                    abuse_contact = poc_details
                elif "admin" in function or "administrative" in function:
                    admin_contacts.append(poc_details)
                elif "tech" in function or "technical" in function:
                    tech_contacts.append(poc_details)
                elif "noc" in function:
                    noc_contacts.append(poc_details)

        # Build result
        result: dict[str, Any] = {
            "ok": True,
            "data": {
                "query": {
                    "type": query_type,
                    "value": query_value,
                },
                "organization": org_info,
                "abuse": abuse_contact,
                "admin_contacts": admin_contacts,
                "tech_contacts": tech_contacts,
                "noc_contacts": noc_contacts,
            },
        }

        # Cache the result
        _contact_cache.set(cache_key, result)

        # Log successful completion via MCP context
        org_name = result["data"]["organization"]["name"]
        abuse_available = "available" if result["data"]["abuse"] else "not available"
        admin_count = len(result["data"]["admin_contacts"])
        tech_count = len(result["data"]["tech_contacts"])
        noc_count = len(result["data"]["noc_contacts"])
        logger.info(
            f"ARIN contact card completed: found '{org_name}' (abuse: {abuse_available}, "
            f"admin: {admin_count}, tech: {tech_count}, noc: {noc_count} contacts)"
        )

        logger.info(
            f"ARIN contact card lookup for {query_type}='{query_value}' completed successfully"
        )
        return result

    except Exception as e:
        error_msg = f"ARIN contact card lookup for {query_type}='{query_value}' failed: {str(e)}"
        logger.error(error_msg)
        # Error already logged above
        return {"ok": False, "error": "lookup_error", "detail": str(e)}


def register(mcp: FastMCP) -> None:
    """Register the ARIN contact_card tool with the MCP server."""
    mcp.tool(
        name=TOOL_NAME,
        description=TOOL_DESCRIPTION,
    )(_contact_card_request)
