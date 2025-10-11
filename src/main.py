from mcp.server.fastmcp import FastMCP

from whois_mcp.register import register_tools


def main() -> None:
    """Main entry point for the MCP server using stdio transport."""
    # Create the MCP server
    app = FastMCP("whois-mcp")

    # Register all tools
    register_tools(app)

    # Run with stdio transport (default for MCP clients like Claude Desktop)
    app.run()


if __name__ == "__main__":
    main()
