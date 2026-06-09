# whois-mcp

A Model Context Protocol (MCP) server that gives MCP clients WHOIS, RDAP, IRR route-object, AS-SET, and abuse-contact lookup tools for the five Regional Internet Registries.

This project currently runs from a local checkout. It has not been published to npm yet.

## Features

### RIR Coverage

| Tool category | RIPE NCC | ARIN | APNIC | AfriNIC | LACNIC |
| --- | :---: | :---: | :---: | :---: | :---: |
| Raw WHOIS query | Yes | Yes | Yes | Yes | Yes |
| Contact card | Yes | Yes | Yes | Yes | Yes |
| Route object validation | Yes | Yes | No | No | No |
| AS-SET expansion | Yes | Yes | No | No | No |

Tools are registered with RIR prefixes, for example:

- `arin_whois_query`
- `ripe_validate_route_object`
- `ripe_expand_as_set`
- `apnic_contact_card`
- `afrinic_contact_card`
- `lacnic_contact_card`

### Registry Regions

- RIPE NCC: Europe, Middle East, Central Asia
- ARIN: North America
- APNIC: Asia-Pacific
- AfriNIC: Africa
- LACNIC: Latin America and Caribbean

## Local Setup

Install dependencies from the local checkout:

```bash
git clone https://github.com/dadepo/whois-mcp.git
cd whois-mcp
npm ci
```

Optional local configuration:

```bash
cp env.example .env
```

All RIRs are enabled by default. Edit `.env` only when you want to disable a registry or change timeouts/HTTP bind settings.

## Running Locally

This MCP server supports two transports:

- stdio: for clients that launch the process and communicate over stdin/stdout
- HTTP: for clients that connect to an HTTP endpoint

There is no default transport. Choose one explicitly.

### Stdio Transport

For development:

```bash
npm --silent run dev:stdio
```

For MCP client configuration, prefer the local bin script after `npm ci`:

```bash
/absolute/path/to/whois-mcp/bin/whois-mcp.js
```

The bin script runs the TypeScript source through the local `tsx` dependency.

### HTTP Transport

Start the HTTP MCP server:

```bash
npm run dev:http
```

The HTTP endpoint is:

```text
http://127.0.0.1:8000/mcp
```

Override the bind address or port when needed:

```bash
HTTP_HOST=0.0.0.0 HTTP_PORT=9000 npm run dev:http
```

## Claude Code Setup

From this repository directory, add the stdio server:

```bash
claude mcp add --transport stdio whois-mcp -- npm --silent run dev:stdio
```

Alternatively, use the absolute local bin path:

```bash
claude mcp add --transport stdio whois-mcp -- /absolute/path/to/whois-mcp/bin/whois-mcp.js
```

For HTTP mode, start the HTTP server first and then add:

```bash
claude mcp add --transport http whois-mcp-http http://127.0.0.1:8000/mcp
```

## Claude Desktop Setup

After `npm ci`, add a stdio server that points at your local checkout:

```json
{
  "mcpServers": {
    "whois-mcp": {
      "command": "/absolute/path/to/whois-mcp/bin/whois-mcp.js"
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
    "whois-mcp-http": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

## Tool Usage Examples

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

## Configuration

Environment variables:

```bash
# Enable or disable RIR support. All default to true.
SUPPORT_RIPE=true
SUPPORT_ARIN=true
SUPPORT_APNIC=true
SUPPORT_AFRINIC=true
SUPPORT_LACNIC=true

# Timeouts and cache settings.
HTTP_TIMEOUT_SECONDS=10
WHOIS_CONNECT_TIMEOUT_SECONDS=5
WHOIS_READ_TIMEOUT_SECONDS=5
CACHE_TTL_SECONDS=60
CACHE_MAX_ITEMS=512

# Custom User-Agent string.
USER_AGENT=whois-mcp/1.0

# HTTP transport settings.
HTTP_HOST=127.0.0.1
HTTP_PORT=8000
```

RIR endpoints are configured in source:

- RIPE NCC: `whois.ripe.net`, `https://rest.db.ripe.net`, `https://rdap.db.ripe.net`
- ARIN: `whois.arin.net`, `https://whois.arin.net/rest`, `https://rdap.arin.net/registry`
- APNIC: `whois.apnic.net`, `https://rdap.apnic.net`
- AfriNIC: `whois.afrinic.net`, `https://rdap.afrinic.net/rdap`
- LACNIC: `whois.lacnic.net`, `https://rdap.lacnic.net/rdap`

## Development

Run the TypeScript test suite:

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

`npm run dev` intentionally exits with guidance. Use `npm run dev:stdio` or `npm run dev:http` so the transport is explicit.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
