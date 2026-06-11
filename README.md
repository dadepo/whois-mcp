# inet-registry-mcp

MCP server for Internet registry and registry-adjacent data used by network operators.

Today it starts with RIR data: ownership and contact lookups, abuse discovery, IRR route objects, AS-SET expansion, authenticated registry lookups, maintained-object inventory, and basic registry data quality checks.

This project currently runs from a local checkout. It has not been published to npm yet.

## Scope

The project is organized around Internet registry systems and registry-adjacent data sources:

- numbering: RIR/RDAP data, IP and ASN allocation data, authenticated inventory, abuse and contact lookup
- routing: IRR route/route6/aut-num/as-set, RPKI ROA validation, BGP origin visibility, bogon and martian checks
- naming: DNS delegation, DNSSEC validation, reverse DNS, IANA root and TLD data
- interconnection: PeeringDB ASN, org, IX, facility, policy, and contact lookup
- metadata: geofeeds, abuse contacts, and source-of-truth consistency audits

Not all of that exists yet. The current implementation starts with the RIR and IRR pieces.

## Current Coverage

| Tool category | RIPE NCC | ARIN | APNIC | AfriNIC | LACNIC |
| --- | :---: | :---: | :---: | :---: | :---: |
| Public registry query | Yes | Yes | Yes | Yes | Yes |
| Contact card | Yes | Yes | Yes | Yes | Yes |
| Route object validation | Yes | Yes | No | No | No |
| AS-SET expansion | Yes | Yes | No | No | No |
| Authenticated object lookup | Yes | Yes | Not implemented | Not implemented | Not implemented |
| Authenticated resource inventory | Yes | Partial | Not implemented | Not implemented | Not implemented |
| Registry data quality audit | Yes | Yes | Not implemented | Not implemented | Not implemented |

`Not implemented` means this server does not yet expose a tested read-only authenticated path for that RIR. It does not mean the RIR has no authenticated services.

Current workflows:

- look up ownership and registration data for IPs and ASNs
- find abuse, admin, and technical contacts
- validate RIPE and ARIN route objects
- expand RIPE and ARIN AS-SETs
- list authenticated RIPE maintained objects
- fetch authenticated RIPE and ARIN registry objects
- audit authenticated RIPE and ARIN registry objects for basic data quality issues

## Install From Source

```bash
git clone https://github.com/dadepo/inet-registry-mcp.git
cd inet-registry-mcp
npm ci
```

Optional local config:

```bash
cp env.example .env
```

All public RIR tools are enabled by default. Edit `.env` only when you want to disable a registry, change timeouts, change HTTP bind settings, or configure authenticated read-only lookups.

## Running Locally

There is no default transport. Pick one explicitly.

For stdio, which is what most local MCP clients use:

```bash
npm --silent run dev:stdio
```

For HTTP:

```bash
npm run dev:http
```

The HTTP endpoint is:

```text
http://127.0.0.1:8000/mcp
```

To bind somewhere else:

```bash
HTTP_HOST=0.0.0.0 HTTP_PORT=9000 npm run dev:http
```

`npm run dev` intentionally exits with guidance. Use `dev:stdio` or `dev:http`.

## Claude Code

From this repo directory:

```bash
claude mcp add --transport stdio inet-registry-mcp -- npm --silent run dev:stdio
```

Or point Claude Code at the local bin script:

```bash
claude mcp add --transport stdio inet-registry-mcp -- /absolute/path/to/inet-registry-mcp/bin/inet-registry-mcp.js
```

For HTTP mode, start the HTTP server first:

```bash
claude mcp add --transport http inet-registry-mcp-http http://127.0.0.1:8000/mcp
```

## Claude Desktop

After `npm ci`, add a stdio server that points at your local checkout:

```json
{
  "mcpServers": {
    "inet-registry-mcp": {
      "command": "/absolute/path/to/inet-registry-mcp/bin/inet-registry-mcp.js"
    }
  }
}
```

Claude Desktop config locations:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

For HTTP mode:

```json
{
  "mcpServers": {
    "inet-registry-mcp-http": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

## Example Prompts

```text
Who owns 8.8.8.8?
```

```text
Who should I contact about abuse from 1.1.1.1?
```

```text
Is there a RIPE route object for 193.0.0.0/21 originated by AS3333?
```

```text
Expand AS-RIPENCC to direct members only.
```

```text
Show me all objects maintained by DADEPO-TEST-MNT.
```

```text
Run a registry data quality audit for RIPE maintainer DADEPO-TEST-MNT.
```

## Configuration

Environment variables:

```bash
# Auth profile. production is the default. Use test to point supported
# authenticated calls at RIR test environments.
INET_REGISTRY_MCP_PROFILE=production

# Enable or disable RIR support. All default to true.
SUPPORT_RIPE=true
SUPPORT_ARIN=true
SUPPORT_APNIC=true
SUPPORT_AFRINIC=true
SUPPORT_LACNIC=true

# Timeouts and cache settings.
HTTP_TIMEOUT_SECONDS=10
PORT43_CONNECT_TIMEOUT_SECONDS=5
PORT43_READ_TIMEOUT_SECONDS=5
CACHE_TTL_SECONDS=60
CACHE_MAX_ITEMS=512

# Custom User-Agent string.
USER_AGENT=inet-registry-mcp/1.0

# HTTP transport settings.
HTTP_HOST=127.0.0.1
HTTP_PORT=8000
```

## Authenticated Read-Only Tools

Authenticated support uses one global profile:

```bash
INET_REGISTRY_MCP_PROFILE=production
# or
INET_REGISTRY_MCP_PROFILE=test
```

There are no `*_AUTH_ENABLED` flags. A capability is available when its credential is present.

Authenticated lookup tools return the object values received from the RIR. Local MCP credentials such as API keys are still redacted if they appear in responses or URLs.

```bash
# RIPE Database REST API authenticated object lookup, maintained-object inventory, and audit.
# Accepts either the full Basic header value or the base64 part; "Basic "
# is added automatically when omitted.
RIPE_API_KEY=

# ARIN Reg-RWS authenticated object lookup, audit, and configured inventory.
ARIN_API_KEY=

# ARIN inventory is read from explicit handles because Reg-RWS does not expose
# one generic account inventory endpoint through this tool yet.
ARIN_INVENTORY_ORG_HANDLES=
ARIN_INVENTORY_NET_HANDLES=
ARIN_INVENTORY_POC_HANDLES=
ARIN_INVENTORY_CUSTOMER_HANDLES=
ARIN_INVENTORY_DELEGATION_NAMES=
ARIN_INVENTORY_TICKET_NUMBERS=
```

Current authenticated scope:

- RIPE: object lookup, maintained-object inventory by inverse `mnt-by` lookup, and data quality audit.
- ARIN: object lookup and data quality audit; inventory works for handles listed in `ARIN_INVENTORY_*`.
- APNIC, AfriNIC, LACNIC: auth status reports configuration, but authenticated inventory/object/audit calls return `not_supported` until provider-specific read paths are implemented.

Supported endpoint overrides for local testing:

```bash
RIPE_DATABASE_REST_BASE=
ARIN_REG_REST_BASE=
APNIC_REGISTRY_BASE=
LACNIC_REGISTRATION_BASE=
```

With `INET_REGISTRY_MCP_PROFILE=test`, supported authenticated calls use the RIPE TEST DB and ARIN OT&E endpoints by default.

## Endpoints

Default public endpoints:

- RIPE NCC: `whois.ripe.net`, `https://rest.db.ripe.net`, `https://rdap.db.ripe.net`
- ARIN: `whois.arin.net`, `https://whois.arin.net/rest`, `https://rdap.arin.net/registry`
- APNIC: `whois.apnic.net`, `https://registry-api.apnic.net/v1`, `https://rdap.apnic.net`
- AfriNIC: `whois.afrinic.net`, `https://rdap.afrinic.net/rdap`
- LACNIC: `whois.lacnic.net`, `https://rdap.lacnic.net/rdap`

## Development

Run tests:

```bash
npm test
```

Run type checking:

```bash
npm run typecheck
```

Compile TypeScript:

```bash
npm run build
```

## License

MIT. See [LICENSE](LICENSE).
