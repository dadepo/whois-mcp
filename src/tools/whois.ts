import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import { TTLCache } from "../cache.js";
import type { RirConfig, RirId } from "../config.js";
import { RIRS } from "../config.js";
import type { ToolDependencies } from "../deps.js";
import { WhoisTimeoutError } from "../lib/whois-client.js";
import { toMcpResult, type ToolResult } from "../types.js";

interface WhoisArgs {
  query: string;
  flags?: string[] | null | undefined;
}

interface WhoisData {
  rpsl: string;
  server: string;
  latency_ms: number;
}

const whoisCache = new TTLCache<string, ToolResult<WhoisData>>({
  maxItems: 1000,
  ttlSeconds: 300
});

const whoisDescriptions: Record<RirId, { tool: string; query: string; flags: string }> = {
  ripe: {
    tool:
      "Perform raw WHOIS queries against the RIPE NCC database to get complete object information in RPSL format. This tool is specifically for the RIPE RIR (Europe/Middle East/Central Asia region). Use ONLY when you need full object details or administrative data from RIPE. DO NOT use for contact information - use ripe_contact_card for abuse, NOC, admin, or tech contacts. DO NOT use for route validation - use ripe_validate_route_object for checking if route objects exist. DO NOT use for AS-SET expansion - use ripe_expand_as_set for getting ASN lists. This returns raw RIPE database records with all attributes for detailed analysis.",
    query:
      "The domain name, IP address, ASN, or other identifier to query via RIPE WHOIS. Examples: 'example.com', '192.0.2.1', 'AS64496', 'RIPE-NCC-HM-MNT'. Returns complete object details from the RIPE NCC database.",
    flags:
      "Optional WHOIS flags to modify the query behavior. Common flags: ['-B'] for brief output (less verbose), ['-r'] for raw output (no filtering), ['-T', 'person'] to limit object types. Use empty list [] or null for default query."
  },
  arin: {
    tool:
      "Perform raw WHOIS queries against the ARIN database to get complete object information in RPSL format. This tool is specifically for the ARIN RIR (North America region - United States, Canada, parts of Caribbean). Use ONLY when you need full object details or administrative data from ARIN. DO NOT use for contact information - use arin_contact_card for abuse, NOC, admin, or tech contacts. DO NOT use for route validation - use arin_validate_route_object for checking if route objects exist. DO NOT use for AS-SET expansion - use arin_expand_as_set for getting ASN lists. This returns raw ARIN database records with all attributes for detailed analysis.",
    query:
      "The domain name, IP address, ASN, or other identifier to query via ARIN WHOIS. Examples: 'example.com', '8.8.8.8', 'AS15169', 'GOOGLE'. Returns complete object details from the ARIN database.",
    flags:
      "Optional WHOIS flags to modify the query behavior. Common ARIN flags: ['+'] for full details, ['-'] for brief output. ARIN uses different flags than RIPE. Use empty list [] or null for default query."
  },
  apnic: {
    tool:
      "Perform raw WHOIS queries against the APNIC database to get complete object information in RPSL format. This tool is specifically for the APNIC RIR (Asia-Pacific region - East Asia, Oceania, South Asia, Southeast Asia). Use ONLY when you need full object details or administrative data from APNIC. DO NOT use for contact information - use apnic_contact_card for abuse, NOC, admin, or tech contacts. DO NOT use for route validation - use apnic_validate_route_object for checking if route objects exist. DO NOT use for AS-SET expansion - use apnic_expand_as_set for getting ASN lists. This returns raw APNIC database records with all attributes for detailed analysis.",
    query:
      "The domain name, IP address, ASN, or other identifier to query via APNIC WHOIS. Examples: 'example.com', '1.1.1.1', 'AS4608', 'APNIC-HM'. Returns complete object details from the APNIC database.",
    flags:
      "Optional WHOIS flags to modify the query behavior. Common APNIC flags: ['-r'] for raw output (no filtering), ['-B'] for brief output, ['-T', 'person'] to limit object types. Use empty list [] or null for default query."
  },
  afrinic: {
    tool:
      "Perform raw WHOIS queries against the AfriNIC database to get complete object information in RPSL format. This tool is specifically for the AfriNIC RIR (African region). Use ONLY when you need full object details or administrative data from AfriNIC. DO NOT use for contact information - use afrinic_contact_card for abuse, NOC, admin, or tech contacts. This returns raw AfriNIC database records with all attributes for detailed analysis.",
    query:
      "The domain name, IP address, ASN, or other identifier to query via AfriNIC WHOIS. Examples: 'example.com', '196.216.2.0', 'AS37611', '2001:43f8::', 'AA1-AFRINIC'. Returns complete object details from the AfriNIC database.",
    flags:
      "Optional WHOIS flags to modify the query behavior. Common AfriNIC flags: ['-r'] for raw output (no filtering), ['-B'] for brief output, ['-T', 'person'] to limit object types. Use empty list [] or null for default query."
  },
  lacnic: {
    tool:
      "Perform raw WHOIS queries against the LACNIC database to get complete object information in RPSL format. This tool is specifically for the LACNIC RIR (Latin America and Caribbean region). Use ONLY when you need full object details or administrative data from LACNIC. DO NOT use for contact information - use lacnic_contact_card for abuse, NOC, admin, or tech contacts. This returns raw LACNIC database records with all attributes for detailed analysis.",
    query:
      "The domain name, IP address, ASN, or other identifier to query via LACNIC WHOIS. Examples: 'example.com', '200.160.0.0', 'AS27699', '2801:10::', 'LACNIC-HOSTMASTER'. Returns complete object details from the LACNIC database.",
    flags:
      "Optional WHOIS flags to modify the query behavior. Common LACNIC flags: ['-r'] for raw output (no filtering), ['-B'] for brief output, ['-T', 'person'] to limit object types. Use empty list [] or null for default query."
  }
};

function cacheKey(rir: RirConfig, query: string, flags: string[]): string {
  const prefix = rir.id === "ripe" ? "" : `${rir.id}:`;
  return `${prefix}${query}|${flags.join(",")}`;
}

export async function handleWhoisQuery(
  rir: RirConfig,
  args: WhoisArgs,
  deps: ToolDependencies
): Promise<ToolResult<WhoisData>> {
  if (!rir.enabled) {
    return {
      ok: false,
      error: "service_disabled",
      detail: `${rir.label} WHOIS support is disabled. Set ${rir.supportEnv}=true to enable.`
    };
  }

  const flags = args.flags ?? [];
  const key = cacheKey(rir, args.query, flags);
  const cached = whoisCache.get(key);
  if (cached !== undefined) {
    return cached;
  }

  const line = `${[...flags, args.query].join(" ").trim()}\r\n`;
  const started = performance.now();

  try {
    const rpsl = await deps.whoisClient.query(rir.whois, line, {
      chunkSize: rir.id === "ripe" ? 65536 : 8192,
      readTimeoutReturnsPartial: rir.id !== "ripe"
    });
    const result: ToolResult<WhoisData> = {
      ok: true,
      data: {
        rpsl,
        server: rir.whois.server,
        latency_ms: Math.trunc(performance.now() - started)
      }
    };
    whoisCache.set(key, result);
    return result;
  } catch (error) {
    if (error instanceof WhoisTimeoutError) {
      return {
        ok: false,
        error: "timeout_error",
        detail: "Connection or read timeout"
      };
    }

    if (error instanceof Error) {
      return {
        ok: false,
        error: rir.id === "ripe" ? "network_error" : "network_error",
        detail: `Network connection failed: ${error.message}`
      };
    }

    return {
      ok: false,
      error: rir.id === "ripe" ? "whois_error" : "internal_error",
      detail: String(error)
    };
  }
}

export function registerWhoisTool(server: McpServer, rir: RirConfig, deps: ToolDependencies): void {
  const descriptions = whoisDescriptions[rir.id];
  server.registerTool(
    `${rir.id}_whois_query`,
    {
      description: descriptions.tool,
      inputSchema: {
        query: z.string().describe(descriptions.query),
        flags: z.array(z.string()).nullable().optional().describe(descriptions.flags)
      }
    },
    async (args) => toMcpResult(await handleWhoisQuery(rir, args, deps))
  );
}

export function registerAllWhoisTools(server: McpServer, deps: ToolDependencies): void {
  for (const rir of Object.values(RIRS)) {
    if (rir.enabled) {
      registerWhoisTool(server, rir, deps);
    }
  }
}
