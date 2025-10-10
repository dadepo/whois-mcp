import logging
from collections.abc import Callable
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

env_path = Path(".env")
if env_path.exists():
    logger.info(f"Loading environment variables from {env_path}")
    load_dotenv(dotenv_path=env_path)
else:
    logger.warning("No .env file found, proceeding with system environment variables")


def register_tools(mcp: FastMCP) -> None:
    """Register all tools with the MCP server."""
    from whois_mcp.config import (
        SUPPORT_AFRINIC,
        SUPPORT_APNIC,
        SUPPORT_ARIN,
        SUPPORT_RIPE,
    )

    tool_registrations: list[Callable[[FastMCP], None]] = []

    # Register RIPE tools if enabled
    if SUPPORT_RIPE:
        logger.info("RIPE NCC support enabled - registering RIPE tools")
        from whois_mcp.tools.ripe.contact_card import register as reg_contact_card
        from whois_mcp.tools.ripe.expand_as_set import register as reg_expand_as_set
        from whois_mcp.tools.ripe.validate_route_object import (
            register as reg_validate_route,
        )
        from whois_mcp.tools.ripe.whois_query import register as reg_whois

        tool_registrations.extend(
            [
                reg_whois,
                reg_expand_as_set,
                reg_validate_route,
                reg_contact_card,
            ]
        )
    else:
        logger.info("RIPE NCC support disabled - skipping RIPE tools")

    # Register ARIN tools if enabled
    if SUPPORT_ARIN:
        logger.info("ARIN support enabled - registering ARIN tools")
        from whois_mcp.tools.arin.contact_card import register as reg_arin_contact_card
        from whois_mcp.tools.arin.expand_as_set import (
            register as reg_arin_expand_as_set,
        )
        from whois_mcp.tools.arin.validate_route_object import (
            register as reg_arin_validate_route,
        )
        from whois_mcp.tools.arin.whois_query import register as reg_arin_whois

        tool_registrations.extend(
            [
                reg_arin_whois,
                reg_arin_validate_route,
                reg_arin_expand_as_set,
                reg_arin_contact_card,
            ]
        )
    else:
        logger.info("ARIN support disabled - skipping ARIN tools")

    # Register APNIC tools if enabled
    if SUPPORT_APNIC:
        logger.info("APNIC support enabled - registering APNIC tools")
        from whois_mcp.tools.apnic.contact_card import (
            register as reg_apnic_contact_card,
        )
        from whois_mcp.tools.apnic.whois_query import register as reg_apnic_whois

        tool_registrations.extend(
            [
                reg_apnic_whois,
                reg_apnic_contact_card,
            ]
        )
        logger.info(
            "Note: APNIC expand_as_set and validate_route_object tools are not yet implemented"
        )
    else:
        logger.info("APNIC support disabled - skipping APNIC tools")

    # Register AfriNIC tools if enabled
    if SUPPORT_AFRINIC:
        logger.info("AfriNIC support enabled - registering AfriNIC tools")
        from whois_mcp.tools.afrinic.contact_card import (
            register as reg_afrinic_contact_card,
        )
        from whois_mcp.tools.afrinic.whois_query import register as reg_afrinic_whois

        tool_registrations.extend(
            [
                reg_afrinic_whois,
                reg_afrinic_contact_card,
            ]
        )
        logger.info(
            "Note: AfriNIC expand_as_set and validate_route_object tools are not yet implemented"
        )
    else:
        logger.info("AfriNIC support disabled - skipping AfriNIC tools")

    if not tool_registrations:
        logger.warning("No tools registered - all RIR support is disabled")
        return

    # Register each tool
    for tool in tool_registrations:
        try:
            logger.debug(f"Registering tool: {tool.__name__}")
            tool(mcp)
            logger.info(f"Successfully registered tool: {tool.__name__}")
        except Exception as e:
            logger.error(f"Failed to register tool {tool.__name__}: {str(e)}")
            raise


# Create and configure the MCP server
app = FastMCP("whois-mcp")
register_tools(app)
