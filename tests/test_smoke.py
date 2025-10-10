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

    def test_tool_imports_ripe(self):
        """Test that all RIPE tool modules can be imported without errors."""
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

    def test_tool_imports_arin(self):
        """Test that all ARIN tool modules can be imported without errors."""
        # These imports should not raise any exceptions
        from whois_mcp.tools.arin import (
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

    def test_tool_imports_apnic(self):
        """Test that all APNIC tool modules can be imported without errors."""
        # These imports should not raise any exceptions
        # Note: Only whois_query and contact_card are implemented for APNIC
        from whois_mcp.tools.apnic import (
            contact_card,
            whois_query,
        )

        # Verify each module has a register function
        assert hasattr(contact_card, "register")
        assert hasattr(whois_query, "register")

        # Verify register functions are callable
        assert callable(contact_card.register)
        assert callable(whois_query.register)

    def test_tool_imports_afrinic(self):
        """Test that all AfriNIC tool modules can be imported without errors."""
        # These imports should not raise any exceptions
        # Note: Only whois_query and contact_card are implemented for AfriNIC
        from whois_mcp.tools.afrinic import (
            contact_card,
            whois_query,
        )

        # Verify each module has a register function
        assert hasattr(contact_card, "register")
        assert hasattr(whois_query, "register")

        # Verify register functions are callable
        assert callable(contact_card.register)
        assert callable(whois_query.register)

    def test_tool_imports_lacnic(self):
        """Test that all LACNIC tool modules can be imported without errors."""
        # These imports should not raise any exceptions
        # Note: Only whois_query and contact_card are implemented for LACNIC
        from whois_mcp.tools.lacnic import (
            contact_card,
            whois_query,
        )

        # Verify each module has a register function
        assert hasattr(contact_card, "register")
        assert hasattr(whois_query, "register")

        # Verify register functions are callable
        assert callable(contact_card.register)
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

        # Should have required configuration constants for all RIRs
        assert hasattr(config, "RIPE_REST_BASE")
        assert hasattr(config, "ARIN_REST_BASE")
        assert hasattr(config, "APNIC_REST_BASE")
        assert hasattr(config, "AFRINIC_RDAP_BASE")
        assert hasattr(config, "LACNIC_RDAP_BASE")
        assert hasattr(config, "HTTP_TIMEOUT_SECONDS")
        assert hasattr(config, "USER_AGENT")

        # Values should be reasonable
        assert isinstance(config.RIPE_REST_BASE, str)
        assert config.RIPE_REST_BASE.startswith("http")
        assert isinstance(config.ARIN_REST_BASE, str)
        assert config.ARIN_REST_BASE.startswith("http")
        assert isinstance(config.APNIC_REST_BASE, str)
        assert config.APNIC_REST_BASE.startswith("http")
        assert isinstance(config.AFRINIC_RDAP_BASE, str)
        assert config.AFRINIC_RDAP_BASE.startswith("http")
        assert isinstance(config.LACNIC_RDAP_BASE, str)
        assert config.LACNIC_RDAP_BASE.startswith("http")
        assert isinstance(config.HTTP_TIMEOUT_SECONDS, int | float)
        assert config.HTTP_TIMEOUT_SECONDS > 0
        assert isinstance(config.USER_AGENT, str)
        assert len(config.USER_AGENT) > 0

        # Should have RIR support flags
        assert hasattr(config, "SUPPORT_RIPE")
        assert hasattr(config, "SUPPORT_ARIN")
        assert hasattr(config, "SUPPORT_APNIC")
        assert hasattr(config, "SUPPORT_AFRINIC")
        assert hasattr(config, "SUPPORT_LACNIC")
        assert isinstance(config.SUPPORT_RIPE, bool)
        assert isinstance(config.SUPPORT_ARIN, bool)
        assert isinstance(config.SUPPORT_APNIC, bool)
        assert isinstance(config.SUPPORT_AFRINIC, bool)
        assert isinstance(config.SUPPORT_LACNIC, bool)

    def test_tool_constants(self):
        """Test that tools have proper constant definitions."""
        from whois_mcp.tools.afrinic.contact_card import (
            TOOL_DESCRIPTION as AFRINIC_CONTACT_DESCRIPTION,
        )
        from whois_mcp.tools.afrinic.contact_card import (
            TOOL_NAME as AFRINIC_CONTACT_TOOL_NAME,
        )
        from whois_mcp.tools.afrinic.whois_query import (
            TOOL_DESCRIPTION as AFRINIC_WHOIS_DESCRIPTION,
        )
        from whois_mcp.tools.afrinic.whois_query import (
            TOOL_NAME as AFRINIC_WHOIS_TOOL_NAME,
        )
        from whois_mcp.tools.apnic.contact_card import (
            TOOL_DESCRIPTION as APNIC_CONTACT_DESCRIPTION,
        )
        from whois_mcp.tools.apnic.contact_card import (
            TOOL_NAME as APNIC_CONTACT_TOOL_NAME,
        )
        from whois_mcp.tools.apnic.whois_query import (
            TOOL_DESCRIPTION as APNIC_WHOIS_DESCRIPTION,
        )
        from whois_mcp.tools.apnic.whois_query import (
            TOOL_NAME as APNIC_WHOIS_TOOL_NAME,
        )
        from whois_mcp.tools.lacnic.contact_card import (
            TOOL_DESCRIPTION as LACNIC_CONTACT_DESCRIPTION,
        )
        from whois_mcp.tools.lacnic.contact_card import (
            TOOL_NAME as LACNIC_CONTACT_TOOL_NAME,
        )
        from whois_mcp.tools.lacnic.whois_query import (
            TOOL_DESCRIPTION as LACNIC_WHOIS_DESCRIPTION,
        )
        from whois_mcp.tools.lacnic.whois_query import (
            TOOL_NAME as LACNIC_WHOIS_TOOL_NAME,
        )
        from whois_mcp.tools.ripe.contact_card import (
            TOOL_DESCRIPTION as RIPE_CONTACT_DESCRIPTION,
        )
        from whois_mcp.tools.ripe.contact_card import (
            TOOL_NAME as RIPE_CONTACT_TOOL_NAME,
        )
        from whois_mcp.tools.ripe.whois_query import (
            TOOL_DESCRIPTION as RIPE_WHOIS_DESCRIPTION,
        )
        from whois_mcp.tools.ripe.whois_query import TOOL_NAME as RIPE_WHOIS_TOOL_NAME

        # All tool names should be strings
        assert isinstance(RIPE_CONTACT_TOOL_NAME, str)
        assert isinstance(RIPE_WHOIS_TOOL_NAME, str)
        assert isinstance(APNIC_CONTACT_TOOL_NAME, str)
        assert isinstance(APNIC_WHOIS_TOOL_NAME, str)
        assert isinstance(AFRINIC_CONTACT_TOOL_NAME, str)
        assert isinstance(AFRINIC_WHOIS_TOOL_NAME, str)
        assert isinstance(LACNIC_CONTACT_TOOL_NAME, str)
        assert isinstance(LACNIC_WHOIS_TOOL_NAME, str)

        # All descriptions should be non-empty strings
        assert isinstance(RIPE_CONTACT_DESCRIPTION, str)
        assert isinstance(RIPE_WHOIS_DESCRIPTION, str)
        assert isinstance(APNIC_CONTACT_DESCRIPTION, str)
        assert isinstance(APNIC_WHOIS_DESCRIPTION, str)
        assert isinstance(AFRINIC_CONTACT_DESCRIPTION, str)
        assert isinstance(AFRINIC_WHOIS_DESCRIPTION, str)
        assert isinstance(LACNIC_CONTACT_DESCRIPTION, str)
        assert isinstance(LACNIC_WHOIS_DESCRIPTION, str)

        assert len(RIPE_CONTACT_DESCRIPTION) > 0
        assert len(RIPE_WHOIS_DESCRIPTION) > 0
        assert len(APNIC_CONTACT_DESCRIPTION) > 0
        assert len(APNIC_WHOIS_DESCRIPTION) > 0
        assert len(AFRINIC_CONTACT_DESCRIPTION) > 0
        assert len(AFRINIC_WHOIS_DESCRIPTION) > 0
        assert len(LACNIC_CONTACT_DESCRIPTION) > 0
        assert len(LACNIC_WHOIS_DESCRIPTION) > 0

        # Tool names should be unique across RIRs
        tool_names = {
            RIPE_CONTACT_TOOL_NAME,
            RIPE_WHOIS_TOOL_NAME,
            APNIC_CONTACT_TOOL_NAME,
            APNIC_WHOIS_TOOL_NAME,
            AFRINIC_CONTACT_TOOL_NAME,
            AFRINIC_WHOIS_TOOL_NAME,
            LACNIC_CONTACT_TOOL_NAME,
            LACNIC_WHOIS_TOOL_NAME,
        }
        assert len(tool_names) == 8  # All names should be unique

    def test_individual_tool_registration_ripe(self):
        """Test that each RIPE tool can be registered individually."""
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

    def test_individual_tool_registration_arin(self):
        """Test that each ARIN tool can be registered individually."""
        from whois_mcp.tools.arin.contact_card import register as reg_contact
        from whois_mcp.tools.arin.expand_as_set import register as reg_expand
        from whois_mcp.tools.arin.validate_route_object import register as reg_validate
        from whois_mcp.tools.arin.whois_query import register as reg_whois

        # Each tool should be able to register with a fresh MCP instance
        for register_func in [reg_contact, reg_expand, reg_validate, reg_whois]:
            app = FastMCP("test-individual")
            # Should not raise any exceptions
            register_func(app)
            assert app is not None

    def test_individual_tool_registration_apnic(self):
        """Test that each APNIC tool can be registered individually."""
        # Note: Only whois_query and contact_card are implemented for APNIC
        from whois_mcp.tools.apnic.contact_card import register as reg_contact
        from whois_mcp.tools.apnic.whois_query import register as reg_whois

        # Each tool should be able to register with a fresh MCP instance
        for register_func in [reg_contact, reg_whois]:
            app = FastMCP("test-individual")
            # Should not raise any exceptions
            register_func(app)
            assert app is not None

    def test_individual_tool_registration_afrinic(self):
        """Test that each AfriNIC tool can be registered individually."""
        # Note: Only whois_query and contact_card are implemented for AfriNIC
        from whois_mcp.tools.afrinic.contact_card import register as reg_contact
        from whois_mcp.tools.afrinic.whois_query import register as reg_whois

        # Each tool should be able to register with a fresh MCP instance
        for register_func in [reg_contact, reg_whois]:
            app = FastMCP("test-individual")
            # Should not raise any exceptions
            register_func(app)
            assert app is not None

    def test_individual_tool_registration_lacnic(self):
        """Test that each LACNIC tool can be registered individually."""
        # Note: Only whois_query and contact_card are implemented for LACNIC
        from whois_mcp.tools.lacnic.contact_card import register as reg_contact
        from whois_mcp.tools.lacnic.whois_query import register as reg_whois

        # Each tool should be able to register with a fresh MCP instance
        for register_func in [reg_contact, reg_whois]:
            app = FastMCP("test-individual")
            # Should not raise any exceptions
            register_func(app)
            assert app is not None
