import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import { ARIN_REST_BASE, RIRS } from "../../config.js";
import { TTLCache } from "../../cache.js";
import type { ToolDependencies } from "../../deps.js";
import { HttpStatusError } from "../../lib/http.js";
import { asArray, asRecord, stringValue } from "../../lib/object.js";
import { validateIpPrefix } from "../../lib/prefix.js";
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

async function searchRoute(prefix: string, deps: ToolDependencies): Promise<unknown> {
  const routeType = prefix.includes(":") ? "route6" : "route";
  const url = `${ARIN_REST_BASE}/irr/${routeType}/${prefix}`;
  try {
    return await deps.httpClient.getJson(url, { headers: { Accept: "application/json" } });
  } catch (error) {
    if (error instanceof HttpStatusError && error.status === 404) {
      return { routes: [] };
    }
    throw error;
  }
}

export async function handleArinRoute(args: RouteArgs, deps: ToolDependencies): Promise<ToolResult<RouteData>> {
  const rir = RIRS.arin;
  if (!rir.enabled) {
    return {
      ok: false,
      error: "service_disabled",
      detail: "ARIN route validation support is disabled. Set SUPPORT_ARIN=true to enable."
    };
  }

  const cacheKey = `arin:route:${args.prefix}|${args.origin_asn}`;
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
    const data = asRecord(await searchRoute(args.prefix, deps));
    const rawRoutes = data.routes;
    const routes = Array.isArray(rawRoutes) ? rawRoutes.map(asRecord) : rawRoutes ? [asRecord(rawRoutes)] : [];
    const matches: Array<{ route: string; origin: string; source: string }> = [];

    for (const routeObj of routes) {
      const route = stringValue(routeObj.route) || stringValue(routeObj.prefix);
      const origin = routeObj.origin ?? routeObj.originAS ?? "";
      if (!route || !origin) {
        continue;
      }

      const originNum = Number.parseInt(String(origin).toUpperCase().replace("AS", ""), 10);
      if (!Number.isNaN(originNum) && originNum === args.origin_asn) {
        matches.push({
          route,
          origin: `AS${originNum}`,
          source: "arin_irr"
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
    return {
      ok: false,
      error: error instanceof HttpStatusError ? "http_error" : "validation_error",
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

export function registerArinRouteTool(server: McpServer, deps: ToolDependencies): void {
  server.registerTool(
    "arin_validate_route_object",
    {
      description: "PREFERRED TOOL for validating route object registration in the ARIN database.",
      inputSchema: {
        prefix: z.string().describe("IP prefix to CHECK/VALIDATE for route object registration in ARIN database."),
        origin_asn: z.number().int().describe("Origin ASN number to VALIDATE/CHECK for route coverage (without 'AS' prefix).")
      }
    },
    async (args) => toMcpResult(await handleArinRoute(args, deps))
  );
}
