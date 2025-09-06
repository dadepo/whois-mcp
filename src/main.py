from whois_mcp.server import app


def main() -> None:
    """Main entry point for the MCP server."""
    app.run()


if __name__ == "__main__":
    main()
