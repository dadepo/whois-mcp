# whois-mcp

A **Model Context Protocol (MCP) server** that provides LLMs with network information lookup tools through WHOIS and RIPE Database queries.

## Features

### Available Tools
- **`whois_query`** - Query WHOIS servers for domains, IPs, and ASNs
- **`expand_as_set`** - Recursively expand AS-SETs into concrete ASN lists
- **`validate_route_object`** - Check IRR route/route6 object existence
- **`contact_card`** - Fetch abuse, admin, and technical contacts

### Regional Internet Registry (RIR) Support

This MCP server supports all five Regional Internet Registries (RIRs) with varying tool availability:

| Tool | RIPE NCC | ARIN | APNIC | AfriNIC | LACNIC |
|------|:--------:|:----:|:-----:|:-------:|:------:|
| **WHOIS Query** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AS-SET Expansion** | ✅ | ✅ | ➖ | ➖ | ➖ |
| **Route Validation** | ✅ | ✅ | ➖ | ➖ | ➖ |
| **Contact Card** | ✅ | ✅ | ✅ | ✅ | ✅ |

**Legend:**
- ✅ Fully supported via REST/RDAP APIs
- ➖ Not available (no public API; use `{rir}_whois_query` and parse output instead)

**RIR Coverage:**
- **RIPE NCC** : Europe, Middle East, Central Asia
- **ARIN** : North America
- **APNIC** : Asia-Pacific
- **AfriNIC** : Africa
- **LACNIC** : Latin America & Caribbean

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
"What ASNs are in AS-HETZNER?"
→ Uses expand_as_set to list member ASNs
```

### Validate Route Objects
```
"Is there a route object for 185.1.1.0/24 originated by AS61417?"
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
# Enable/disable RIR support (all default to true)
SUPPORT_RIPE=true      # RIPE NCC (Europe/Middle East/Central Asia)
SUPPORT_ARIN=true      # ARIN (North America)
SUPPORT_APNIC=true     # APNIC (Asia-Pacific)
SUPPORT_AFRINIC=true   # AfriNIC (Africa)
SUPPORT_LACNIC=true    # LACNIC (Latin America & Caribbean)

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

Each RIR can be individually enabled or disabled using environment variables. All RIR endpoints are hardcoded for reliability:

- **RIPE NCC**: `whois.ripe.net`, `https://rest.db.ripe.net`
- **ARIN**: `whois.arin.net`, `https://whois.arin.net/rest`
- **APNIC**: `whois.apnic.net`, `https://rdap.apnic.net`
- **AfriNIC**: `whois.afrinic.net`, `https://rdap.afrinic.net/rdap`
- **LACNIC**: `whois.lacnic.net`, `https://rdap.lacnic.net/rdap`

Set any `SUPPORT_{RIR}=false` to disable specific RIRs. Tools are prefixed with the RIR name (e.g., `ripe_whois_query`, `arin_whois_query`, `apnic_contact_card`).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.