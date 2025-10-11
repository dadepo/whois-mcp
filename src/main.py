from mcp.server.fastmcp import FastMCP

from whois_mcp.register import register_tools

def main() -> None:
    """Main entry point for the MCP server."""
    
    # Create the MCP server
    app = FastMCP("whois-mcp")
    # Configure the MCP server
    register_tools(app)
    
    app.run()


if __name__ == "__main__":
    main()
