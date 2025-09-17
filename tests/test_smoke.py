"""Smoke tests for whois-mcp tools - basic infrastructure testing only."""

from mcp.server.fastmcp import FastMCP

from whois_mcp.server import register_tools


class TestSmokeTests:
    """Basic smoke tests to ensure tool registration and basic infrastructure works."""

    def test_server_creation(self):
        """Test that the MCP server can be created."""
        app = FastMCP("test-whois-mcp")
        assert app is not None
        assert app.name == "test-whois-mcp"

    def test_tool_registration(self):
        """Test that all tools can be registered without errors."""
        app = FastMCP("test-whois-mcp")

        # This should not raise any exceptions
        register_tools(app)

        # Verify that tools were registered by checking the app has tools
        # Note: FastMCP doesn't expose a direct way to list tools, but registration should not fail
        assert app is not None

    def test_tool_imports(self):
        """Test that all tool modules can be imported without errors."""
        # These imports should not raise any exceptions
        from whois_mcp.tools.ripe import (
            contact_card,
            expand_as_set,
            validate_route_object,
            whois_query,
        )

        # Verify each module has a register function
        assert hasattr(contact_card, "register")
        assert hasattr(expand_as_set, "register")
        assert hasattr(validate_route_object, "register")
        assert hasattr(whois_query, "register")

        # Verify register functions are callable
        assert callable(contact_card.register)
        assert callable(expand_as_set.register)
        assert callable(validate_route_object.register)
        assert callable(whois_query.register)

    def test_cache_imports(self):
        """Test that cache module can be imported and used."""
        from whois_mcp.cache import TTLCache

        # Should be able to create a cache instance
        cache = TTLCache(max_items=10, ttl_seconds=60.0)
        assert cache is not None

        # Basic cache operations should work
        cache.set("test_key", "test_value")
        assert cache.get("test_key") == "test_value"
        assert cache.get("nonexistent_key") is None

    def test_config_imports(self):
        """Test that config module can be imported."""
        from whois_mcp import config

        # Should have required configuration constants
        assert hasattr(config, "RIPE_REST_BASE")
        assert hasattr(config, "HTTP_TIMEOUT_SECONDS")
        assert hasattr(config, "USER_AGENT")

        # Values should be reasonable
        assert isinstance(config.RIPE_REST_BASE, str)
        assert config.RIPE_REST_BASE.startswith("http")
        assert isinstance(config.HTTP_TIMEOUT_SECONDS, int | float)
        assert config.HTTP_TIMEOUT_SECONDS > 0
        assert isinstance(config.USER_AGENT, str)
        assert len(config.USER_AGENT) > 0

    def test_tool_constants(self):
        """Test that tools have proper constant definitions."""
        from whois_mcp.tools.ripe.contact_card import TOOL_DESCRIPTION as CONTACT_DESCRIPTION
        from whois_mcp.tools.ripe.contact_card import TOOL_NAME as CONTACT_TOOL_NAME
        from whois_mcp.tools.ripe.expand_as_set import TOOL_DESCRIPTION as EXPAND_DESCRIPTION
        from whois_mcp.tools.ripe.expand_as_set import TOOL_NAME as EXPAND_TOOL_NAME
        from whois_mcp.tools.ripe.validate_route_object import (
            TOOL_DESCRIPTION as VALIDATE_DESCRIPTION,
        )
        from whois_mcp.tools.ripe.validate_route_object import (
            TOOL_NAME as VALIDATE_TOOL_NAME,
        )
        from whois_mcp.tools.ripe.whois_query import TOOL_DESCRIPTION as WHOIS_DESCRIPTION
        from whois_mcp.tools.ripe.whois_query import TOOL_NAME as WHOIS_TOOL_NAME

        # All tool names should be strings
        assert isinstance(CONTACT_TOOL_NAME, str)
        assert isinstance(EXPAND_TOOL_NAME, str)
        assert isinstance(VALIDATE_TOOL_NAME, str)
        assert isinstance(WHOIS_TOOL_NAME, str)

        # All descriptions should be non-empty strings
        assert isinstance(CONTACT_DESCRIPTION, str)
        assert isinstance(EXPAND_DESCRIPTION, str)
        assert isinstance(VALIDATE_DESCRIPTION, str)
        assert isinstance(WHOIS_DESCRIPTION, str)

        assert len(CONTACT_DESCRIPTION) > 0
        assert len(EXPAND_DESCRIPTION) > 0
        assert len(VALIDATE_DESCRIPTION) > 0
        assert len(WHOIS_DESCRIPTION) > 0

        # Tool names should be unique
        tool_names = {
            CONTACT_TOOL_NAME,
            EXPAND_TOOL_NAME,
            VALIDATE_TOOL_NAME,
            WHOIS_TOOL_NAME,
        }
        assert len(tool_names) == 4  # All names should be unique

    def test_individual_tool_registration(self):
        """Test that each tool can be registered individually."""
        from whois_mcp.tools.ripe.contact_card import register as reg_contact
        from whois_mcp.tools.ripe.expand_as_set import register as reg_expand
        from whois_mcp.tools.ripe.validate_route_object import register as reg_validate
        from whois_mcp.tools.ripe.whois_query import register as reg_whois

        # Each tool should be able to register with a fresh MCP instance
        for register_func in [reg_contact, reg_expand, reg_validate, reg_whois]:
            app = FastMCP("test-individual")
            # Should not raise any exceptions
            register_func(app)
            assert app is not None
