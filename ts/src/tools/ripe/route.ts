import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import { TTLCache } from "../../cache.js";
import { RIPE_REST_BASE } from "../../config.js";
import type { ToolDependencies } from "../../deps.js";
import { HttpStatusError } from "../../lib/http.js";
import { validateIpPrefix } from "../../lib/prefix.js";
import { ripeObjects } from "../../lib/ripe-object.js";
import { asArray, asRecord, stringValue } from "../../lib/object.js";
import { toMcpResult, type ToolResult } from "../../types.js";

interface RouteArgs {
  prefix: string;
  origin_asn: number;
}

interface RouteData {
  state: "exists" | "not-found";
  matches: Array<{ route: string; origin: string; source: string }>;
  prefix: string;
  origin_asn: number;
}

const cache = new TTLCache<string, ToolResult<RouteData>>({
  maxItems: 1000,
  ttlSeconds: 300
});

async function searchRoute(prefix: string, deps: ToolDependencies): Promise<{ data: unknown; routeType: string }> {
  const routeType = prefix.includes(":") ? "route6" : "route";
  const url = `${RIPE_REST_BASE}/search.json?query-string=${prefix}&type-filter=${routeType}`;
  return { data: await deps.httpClient.getJson(url), routeType };
}

export async function handleRipeRoute(args: RouteArgs, deps: ToolDependencies): Promise<ToolResult<RouteData>> {
  const cacheKey = `route:${args.prefix}|${args.origin_asn}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }

  try {
    validateIpPrefix(args.prefix);
  } catch (error) {
    return {
      ok: false,
      error: "invalid_prefix",
      detail: error instanceof Error ? error.message : String(error)
    };
  }

  try {
    const { data, routeType } = await searchRoute(args.prefix, deps);
    const matches: Array<{ route: string; origin: string; source: string }> = [];

    for (const obj of ripeObjects(data)) {
      const attrs = asArray(asRecord(asRecord(obj).attributes).attribute).map(asRecord);
      const route = stringValue(attrs.find((attr) => attr.name === "route" || attr.name === "route6")?.value);
      const origin = stringValue(attrs.find((attr) => attr.name === "origin")?.value);
      if (!route) {
        continue;
      }

      const originNum = Number.parseInt(origin.toUpperCase().replace("AS", ""), 10);
      if (!Number.isNaN(originNum) && originNum === args.origin_asn) {
        matches.push({
          route,
          origin,
          source: routeType
        });
      }
    }

    const result: ToolResult<RouteData> = {
      ok: true,
      data: {
        state: matches.length > 0 ? "exists" : "not-found",
        matches,
        prefix: args.prefix,
        origin_asn: args.origin_asn
      }
    };
    cache.set(cacheKey, result);
    return result;
  } catch (error) {
    if (error instanceof HttpStatusError && error.status === 404) {
      const result: ToolResult<RouteData> = {
        ok: true,
        data: {
          state: "not-found",
          matches: [],
          prefix: args.prefix,
          origin_asn: args.origin_asn
        }
      };
      cache.set(cacheKey, result);
      return result;
    }

    return {
      ok: false,
      error: error instanceof HttpStatusError ? "http_error" : "validation_error",
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

export function registerRipeRouteTool(server: McpServer, deps: ToolDependencies): void {
  server.registerTool(
    "ripe_validate_route_object",
    {
      description:
        "PREFERRED TOOL for validating route object registration in the RIPE NCC database.",
      inputSchema: {
        prefix: z.string().describe("IP prefix to CHECK/VALIDATE for route object registration in RIPE database."),
        origin_asn: z.number().int().describe("Origin ASN number to VALIDATE/CHECK for route coverage (without 'AS' prefix).")
      }
    },
    async (args) => toMcpResult(await handleRipeRoute(args, deps))
  );
}
