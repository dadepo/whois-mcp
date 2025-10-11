from mcp.server.fastmcp import FastMCP

from whois_mcp.config import HTTP_HOST, HTTP_PORT
from whois_mcp.register import register_tools


def main() -> None:
    """Main entry point for the MCP server using HTTP transport."""
    # Create the MCP server with host and port configuration
    app = FastMCP("whois-mcp", host=HTTP_HOST, port=HTTP_PORT)

    # Register all tools
    register_tools(app)

    # Run with streamable-http transport (for HTTP server mode)
    print(f"Starting whois-mcp server on http://{HTTP_HOST}:{HTTP_PORT}")
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
