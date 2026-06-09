import { describe, expect, it } from "vitest";

import { ARIN_REST_BASE, RIPE_REST_BASE, RIRS } from "../src/config.js";
import { HttpStatusError } from "../src/lib/http.js";
import { handleArinAsSet } from "../src/tools/arin/as-set.js";
import { handleRipeAsSet } from "../src/tools/ripe/as-set.js";
import { fakeDeps } from "./helpers.js";
import ripeAsSetNested from "./fixtures/ripe-as-set-nested.json" with { type: "json" };
import ripeAsSetRoot from "./fixtures/ripe-as-set-root.json" with { type: "json" };

describe("AS-SET expansion tools", () => {
  it("recursively expands RIPE AS-SETs with cycle protection", async () => {
    const deps = fakeDeps();
    deps.httpClient.set(`${RIPE_REST_BASE}/ripe/as-set/AS-ROOT.json`, ripeAsSetRoot);
    deps.httpClient.set(`${RIPE_REST_BASE}/ripe/as-set/AS-NESTED.json`, ripeAsSetNested);

    await expect(handleRipeAsSet({ setname: "AS-ROOT", max_depth: 10 }, deps)).resolves.toEqual({
      ok: true,
      data: {
        as_set: "AS-ROOT",
        asns: [64496, 64497],
        count: 2,
        status: "expanded"
      }
    });
  });

  it("uses RIPE max_depth=1 for direct members only", async () => {
    const deps = fakeDeps();
    deps.httpClient.set(`${RIPE_REST_BASE}/ripe/as-set/AS-DIRECT-ONLY.json`, ripeAsSetRoot);

    await expect(handleRipeAsSet({ setname: "AS-DIRECT-ONLY", max_depth: 1 }, deps)).resolves.toEqual({
      ok: true,
      data: {
        as_set: "AS-DIRECT-ONLY",
        asns: [64496],
        count: 1,
        status: "expanded"
      }
    });
  });

  it("preserves ARIN 404-as-empty behavior", async () => {
    RIRS.arin.enabled = true;
    const deps = fakeDeps();
    deps.httpClient.set(`${ARIN_REST_BASE}/irr/as-set/AS-ARIN-MISSING`, new HttpStatusError(404, "Not Found", "url"));

    await expect(handleArinAsSet({ setname: "AS-ARIN-MISSING", max_depth: 10 }, deps)).resolves.toEqual({
      ok: true,
      data: {
        as_set: "AS-ARIN-MISSING",
        asns: [],
        count: 0,
        status: "empty"
      }
    });
  });
});
