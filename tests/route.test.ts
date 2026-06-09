import { describe, expect, it } from "vitest";

import { ARIN_REST_BASE, RIPE_REST_BASE, RIRS } from "../src/config.js";
import { HttpStatusError } from "../src/lib/http.js";
import { handleArinRoute } from "../src/tools/arin/route.js";
import { handleRipeRoute } from "../src/tools/ripe/route.js";
import { fakeDeps } from "./helpers.js";
import ripeRouteSearch from "./fixtures/ripe-route-search.json" with { type: "json" };

describe("route validation tools", () => {
  it("finds matching RIPE route objects by prefix and origin ASN", async () => {
    const deps = fakeDeps();
    deps.httpClient.set(`${RIPE_REST_BASE}/search.json?query-string=192.0.2.0/24&type-filter=route`, ripeRouteSearch);

    await expect(handleRipeRoute({ prefix: "192.0.2.0/24", origin_asn: 64496 }, deps)).resolves.toEqual({
      ok: true,
      data: {
        state: "exists",
        matches: [{ route: "192.0.2.0/24", origin: "AS64496", source: "route" }],
        prefix: "192.0.2.0/24",
        origin_asn: 64496
      }
    });
  });

  it("maps RIPE 404 responses to not-found", async () => {
    const deps = fakeDeps();
    deps.httpClient.set(
      `${RIPE_REST_BASE}/search.json?query-string=198.51.100.0/24&type-filter=route`,
      new HttpStatusError(404, "Not Found", "url")
    );

    await expect(handleRipeRoute({ prefix: "198.51.100.0/24", origin_asn: 64496 }, deps)).resolves.toEqual({
      ok: true,
      data: {
        state: "not-found",
        matches: [],
        prefix: "198.51.100.0/24",
        origin_asn: 64496
      }
    });
  });

  it("parses ARIN route response variants", async () => {
    RIRS.arin.enabled = true;
    const deps = fakeDeps();
    deps.httpClient.set(`${ARIN_REST_BASE}/irr/route/203.0.113.0/24`, {
      routes: {
        prefix: "203.0.113.0/24",
        originAS: "AS64496"
      }
    });

    await expect(handleArinRoute({ prefix: "203.0.113.0/24", origin_asn: 64496 }, deps)).resolves.toEqual({
      ok: true,
      data: {
        state: "exists",
        matches: [{ route: "203.0.113.0/24", origin: "AS64496", source: "arin_irr" }],
        prefix: "203.0.113.0/24",
        origin_asn: 64496
      }
    });
  });

  it("rejects invalid prefixes before network lookup", async () => {
    const deps = fakeDeps();
    const result = await handleRipeRoute({ prefix: "not-a-prefix", origin_asn: 64496 }, deps);
    expect(result.ok).toBe(false);
    expect(result).toMatchObject({ error: "invalid_prefix" });
    expect(deps.httpClient.calls).toHaveLength(0);
  });
});
