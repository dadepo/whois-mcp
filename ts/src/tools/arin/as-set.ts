import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import { ARIN_REST_BASE, RIRS } from "../../config.js";
import { TTLCache } from "../../cache.js";
import type { ToolDependencies } from "../../deps.js";
import { HttpStatusError } from "../../lib/http.js";
import { asRecord } from "../../lib/object.js";
import { toMcpResult, type ToolResult } from "../../types.js";

interface AsSetData {
  as_set: string;
  asns: number[];
  count: number;
  status?: "not-found" | "empty" | "expanded";
}

const cache = new TTLCache<string, Set<number>>({
  maxItems: 1000,
  ttlSeconds: 300
});

async function getAsSetData(setname: string, deps: ToolDependencies): Promise<Record<string, unknown>> {
  try {
    return asRecord(await deps.httpClient.getJson(`${ARIN_REST_BASE}/irr/as-set/${setname}`, { headers: { Accept: "application/json" } }));
  } catch (error) {
    if (error instanceof HttpStatusError && error.status === 404) {
      return { members: [] };
    }
    throw error;
  }
}

function extractMembers(data: Record<string, unknown>): string[] {
  const members: string[] = [];
  for (const field of ["members", "member", "as-set", "asSet"]) {
    if (!(field in data)) {
      continue;
    }

    const value = data[field];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item) {
          members.push(String(item).trim());
        }
      }
    } else if (typeof value === "string") {
      members.push(...value.replaceAll(",", " ").split(/\s+/).filter(Boolean));
    } else if (value) {
      members.push(String(value).trim());
    }
    break;
  }

  return members;
}

async function expandRecursive(
  setname: string,
  seen: Set<string>,
  outAsns: Set<number>,
  foundSets: Set<string>,
  deps: ToolDependencies,
  depth = 0,
  maxDepth = 10
): Promise<void> {
  if (depth >= maxDepth || seen.has(setname)) {
    return;
  }
  seen.add(setname);

  const cacheKey = `arin:as_set:${setname}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined && cached.size > 0) {
    for (const asn of cached) {
      outAsns.add(asn);
    }
    foundSets.add(setname);
    return;
  }

  const data = await getAsSetData(setname, deps);
  foundSets.add(setname);
  const members = extractMembers(data);
  if (members.length === 0) {
    return;
  }

  const asns = new Set<number>();
  for (const memberRaw of members) {
    const member = memberRaw.trim().toUpperCase();
    if (member.startsWith("AS") && /^\d+$/.test(member.slice(2))) {
      asns.add(Number.parseInt(member.slice(2), 10));
    } else if (member.startsWith("AS-")) {
      try {
        await expandRecursive(member, seen, asns, foundSets, deps, depth + 1, maxDepth);
      } catch {
        // Match Python behavior: continue when one nested AS-SET fails.
      }
    }
  }

  cache.set(`arin:as_set:${setname}`, asns);
  for (const asn of asns) {
    outAsns.add(asn);
  }
}

export async function handleArinAsSet(
  args: { setname: string; max_depth?: number },
  deps: ToolDependencies
): Promise<ToolResult<AsSetData>> {
  const rir = RIRS.arin;
  if (!rir.enabled) {
    return {
      ok: false,
      error: "service_disabled",
      detail: "ARIN AS-SET expansion support is disabled. Set SUPPORT_ARIN=true to enable."
    };
  }

  const maxDepth = args.max_depth ?? 10;
  const cacheKey = `arin:as_set:${args.setname}:depth_${maxDepth}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) {
    return {
      ok: true,
      data: {
        as_set: args.setname,
        asns: [...cached].sort((a, b) => a - b),
        count: cached.size
      }
    };
  }

  try {
    const seen = new Set<string>();
    const asns = new Set<number>();
    const foundSets = new Set<string>();
    await expandRecursive(args.setname, seen, asns, foundSets, deps, 0, maxDepth);

    let data: AsSetData;
    if (!foundSets.has(args.setname)) {
      data = { as_set: args.setname, asns: [], count: 0, status: "not-found" };
    } else if (asns.size === 0) {
      data = { as_set: args.setname, asns: [], count: 0, status: "empty" };
    } else {
      data = {
        as_set: args.setname,
        asns: [...asns].sort((a, b) => a - b),
        count: asns.size,
        status: "expanded"
      };
    }

    cache.set(cacheKey, asns);
    return { ok: true, data };
  } catch (error) {
    return {
      ok: false,
      error: "expansion_error",
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

export function registerArinAsSetTool(server: McpServer, deps: ToolDependencies): void {
  server.registerTool(
    "arin_expand_as_set",
    {
      description: "Efficiently expand AS-SET objects from the ARIN IRR database into concrete ASNs with configurable depth.",
      inputSchema: {
        setname: z.string().describe("AS-SET name to recursively expand into concrete ASN numbers from ARIN IRR database."),
        max_depth: z.number().int().min(1).max(20).default(10).describe("Maximum recursion depth for AS-SET expansion (1-20 levels, default: 10).")
      }
    },
    async (args) => toMcpResult(await handleArinAsSet(args, deps))
  );
}
