# whois-mcp

A **Model Context Protocol (MCP) server** that provides LLMs with network information lookup tools through WHOIS and RIPE Database queries.

## Features

### Available Tools
- **`whois_query`** - Query WHOIS servers for domains, IPs, and ASNs
- **`expand_as_set`** - Recursively expand AS-SETs into concrete ASN lists
- **`validate_route_object`** - Check IRR route/route6 object existence
- **`contact_card`** - Fetch abuse, admin, and technical contacts

### Regional Internet Registry (RIR) Support

This MCP server supports multiple Regional Internet Registries (RIRs):

- ✅ **RIPE NCC** (Europe/Middle East/Central Asia) - Full support
- ✅ **ARIN** (North America) - Full support
- 🔄 **APNIC** (Asia-Pacific) - Planned  
- 🔄 **LACNIC** (Latin America) - Planned
- 🔄 **AFRINIC** (Africa) - Planned

## Usage

### With Claude Desktop (or any other MCP Client)

Add to your Claude Desktop configuration:
```json
{
  "mcpServers": {
    "whois-mcp": {
      "command": "/path/to/bin/uvx",
      "args": ["--from", "git+https://github.com/dadepo/whois-mcp.git", "whois-mcp"]
    }
  }
}
```

## Tool Usage Examples

### Query Network Information
```
"What organization owns 8.8.8.8?"
→ Uses whois_query to retrieve registration details
```

### Expand AS-SETs
```
"What ASNs are in AS-HURRICANE?"
→ Uses expand_as_set to list member ASNs
```

### Validate Route Objects
```
"Is there a route object for 192.0.2.0/24 originated by AS64496?"
→ Uses validate_route_object to check IRR databases
```

### Get Contact Information
```
"Who should I contact about abuse from AS15169?"
→ Uses contact_card to retrieve contact details
```

## Configuration

Environment variables (optional):
```bash
# Enable/disable RIR support
SUPPORT_RIPE=true    # RIPE NCC (default: true)
SUPPORT_ARIN=false   # ARIN (default: false)

# General Configuration
HTTP_TIMEOUT_SECONDS=10
WHOIS_CONNECT_TIMEOUT_SECONDS=5
WHOIS_READ_TIMEOUT_SECONDS=5
CACHE_TTL_SECONDS=60
CACHE_MAX_ITEMS=512

# Custom User-Agent string
USER_AGENT="whois-mcp/1.0"
```

### RIR Support Control

- **`SUPPORT_RIPE=true`** (default): Enables RIPE NCC queries using hardcoded endpoints (`whois.ripe.net`, `https://rest.db.ripe.net`)
- **`SUPPORT_ARIN=true`**: Enables ARIN queries using hardcoded endpoints (`whois.arin.net`, `https://whois.arin.net/rest`)
- Set to `false` to disable specific RIRs

All RIR endpoints are hardcoded for reliability. You can enable multiple RIRs simultaneously - tools will be prefixed with the RIR name (e.g., `ripe_whois_query`, `arin_whois_query`).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.