# whois-mcp

A **Model Context Protocol (MCP) server** that provides LLMs with network information lookup tools through WHOIS and RIPE Database queries.

## Features

### Available Tools
- **`whois_query`** - Query WHOIS servers for domains, IPs, and ASNs
- **`expand_as_set`** - Recursively expand AS-SETs into concrete ASN lists
- **`validate_route_object`** - Check IRR route/route6 object existence
- **`contact_card`** - Fetch abuse, admin, and technical contacts

### Regional Internet Registry (RIR) Support

Currently, this MCP server is primarily optimized for **RIPE NCC** (Europe/Middle East/Central Asia) resources and databases. Support for other Regional Internet Registries is planned.

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
# Custom RIPE REST API endpoint
RIPE_REST="https://rest.db.ripe.net"

# HTTP timeout in seconds
HTTP_TIMEOUT_SECONDS=30

# Custom User-Agent string
USER_AGENT="whois-mcp/1.0"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.