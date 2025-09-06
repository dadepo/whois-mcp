import logging
from pathlib import Path
from typing import Callable, List
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
    # Import tool registration functions
    from whois_mcp.tools.whois_query import register as reg_whois

    # List of registration functions
    tool_registrations: List[Callable[[FastMCP], None]] = [
        reg_whois,
    ]

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
