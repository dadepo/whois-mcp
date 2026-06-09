import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import { TTLCache } from "../../cache.js";
import { RIPE_REST_BASE } from "../../config.js";
import type { ToolDependencies } from "../../deps.js";
import { ripeAttrs, ripeObjects } from "../../lib/ripe-object.js";
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

async function getJson(deps: ToolDependencies, url: string): Promise<unknown> {
  return deps.httpClient.getJson(url, { notFoundValue: { objects: { object: [] } } });
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

  const cacheKey = `as_set:${setname}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined && cached.size > 0) {
    for (const asn of cached) {
      outAsns.add(asn);
    }
    foundSets.add(setname);
    return;
  }

  const objects = ripeObjects(await getJson(deps, `${RIPE_REST_BASE}/ripe/as-set/${setname}.json`));
  if (objects.length === 0) {
    return;
  }

  foundSets.add(setname);
  const asns = new Set<number>();
  for (const memberRaw of ripeAttrs(objects[0], "members")) {
    const member = memberRaw.toUpperCase();
    if (member.startsWith("AS") && /^\d+$/.test(member.slice(2))) {
      asns.add(Number.parseInt(member.slice(2), 10));
    } else if (member.startsWith("AS-")) {
      try {
        await expandRecursive(memberRaw, seen, asns, foundSets, deps, depth + 1, maxDepth);
      } catch {
        // Match Python behavior: continue when one nested AS-SET fails.
      }
    }
  }

  cache.set(cacheKey, asns);
  for (const asn of asns) {
    outAsns.add(asn);
  }
}

export async function handleRipeAsSet(
  args: { setname: string; max_depth?: number },
  deps: ToolDependencies
): Promise<ToolResult<AsSetData>> {
  const maxDepth = args.max_depth ?? 10;
  const cacheKey = `as_set:${args.setname}`;
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

    if (!foundSets.has(args.setname)) {
      return {
        ok: true,
        data: {
          as_set: args.setname,
          asns: [],
          count: 0,
          status: "not-found"
        }
      };
    }

    if (asns.size === 0) {
      return {
        ok: true,
        data: {
          as_set: args.setname,
          asns: [],
          count: 0,
          status: "empty"
        }
      };
    }

    return {
      ok: true,
      data: {
        as_set: args.setname,
        asns: [...asns].sort((a, b) => a - b),
        count: asns.size,
        status: "expanded"
      }
    };
  } catch (error) {
    return {
      ok: false,
      error: "expansion_error",
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

export function registerRipeAsSetTool(server: McpServer, deps: ToolDependencies): void {
  server.registerTool(
    "ripe_expand_as_set",
    {
      description: "Efficiently expand AS-SET objects from the RIPE NCC database into concrete ASNs with configurable depth.",
      inputSchema: {
        setname: z.string().describe("AS-SET name to recursively expand into concrete ASN numbers from RIPE database."),
        max_depth: z.number().int().min(1).max(20).default(10).describe("Maximum recursion depth for AS-SET expansion (1-20 levels, default: 10).")
      }
    },
    async (args) => toMcpResult(await handleRipeAsSet(args, deps))
  );
}
