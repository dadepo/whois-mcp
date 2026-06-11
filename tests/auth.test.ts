import { describe, expect, it } from "vitest";

import {
  handleAuthenticatedInventory,
  handleAuthenticatedObjectLookup,
  handleAuthStatus,
  handleWhoisDataQualityAudit
} from "../src/tools/auth.js";
import { fakeDeps } from "./helpers.js";

const ripeMntner = {
  objects: {
    object: [
      {
        type: "mntner",
        attributes: {
          attribute: [
            { name: "mntner", value: "TEST-MNT" },
            { name: "admin-c", value: "AA1-TEST" },
            { name: "upd-to", value: "ops@example.test" },
            { name: "auth", value: "SSO should-not-leak" },
            { name: "mnt-by", value: "TEST-MNT" },
            { name: "source", value: "TEST" }
          ]
        }
      }
    ]
  }
};

describe("authenticated registry tools", () => {
  it("reports configured auth profile without exposing secrets", () => {
    const result = handleAuthStatus({
      INET_REGISTRY_MCP_PROFILE: "prod",
      RIPE_API_KEY: "ripe-secret",
      ARIN_API_KEY: "arin-secret"
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.data.profile).toBe("production");
    expect(result.data.rirs.ripe.configured_credentials).toContain("RIPE_API_KEY");
    expect(result.data.rirs.arin.configured_credentials).toContain("ARIN_API_KEY");
    expect(JSON.stringify(result.data)).not.toContain("ripe-secret");
    expect(JSON.stringify(result.data)).not.toContain("arin-secret");
  });

  it("accepts the old auth profile env var as a fallback", () => {
    const result = handleAuthStatus({
      WHOIS_MCP_PROFILE: "test",
      RIPE_API_KEY: "ripe-secret"
    });

    expect(result.ok).toBe(true);
    expect(result.ok && result.data.profile).toBe("test");
  });

  it("uses the RIPE test database profile for authenticated object lookup and returns protected registry values", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://rest-test.db.ripe.net/test/mntner/TEST-MNT.json?unfiltered", ripeMntner);

    const result = await handleAuthenticatedObjectLookup(
      { rir: "ripe", object_type: "mntner", key: "TEST-MNT" },
      deps,
      {
        INET_REGISTRY_MCP_PROFILE: "test",
        RIPE_API_KEY: "encoded-basic-secret",
        RIPE_DATABASE_REST_BASE: ""
      }
    );

    expect(result.ok).toBe(true);
    expect(deps.httpClient.calls[0]?.headers?.Authorization).toBe("Basic encoded-basic-secret");
    expect(JSON.stringify(result)).toContain("should-not-leak");
    expect(JSON.stringify(result)).not.toContain("encoded-basic-secret");
    expect(result.ok && result.data.local_secrets_redacted).toBe(true);
    expect(result.ok && result.data.registry_values_redacted).toBe(false);
  });

  it("ignores legacy redaction flags and still returns authenticated registry values", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://rest-test.db.ripe.net/test/mntner/TEST-MNT.json?unfiltered", ripeMntner);

    const result = await handleAuthenticatedObjectLookup(
      { rir: "ripe", object_type: "mntner", key: "TEST-MNT", redact_sensitive: false } as Parameters<
        typeof handleAuthenticatedObjectLookup
      >[0],
      deps,
      {
        INET_REGISTRY_MCP_PROFILE: "test",
        RIPE_API_KEY: "encoded-basic-secret"
      }
    );

    expect(result.ok).toBe(true);
    expect(JSON.stringify(result)).toContain("should-not-leak");
    expect(JSON.stringify(result)).not.toContain("encoded-basic-secret");
    expect(result.ok && result.data.registry_values_redacted).toBe(false);
  });

  it("requires credentials for authenticated RIPE lookups", async () => {
    const result = await handleAuthenticatedObjectLookup(
      { rir: "ripe", object_type: "mntner", key: "TEST-MNT" },
      fakeDeps(),
      { INET_REGISTRY_MCP_PROFILE: "test" }
    );

    expect(result).toEqual({
      ok: false,
      error: "auth_not_configured",
      detail: "RIPE authenticated object lookup requires RIPE_API_KEY."
    });
  });

  it("fetches RIPE maintained-object inventory with the database API key", async () => {
    const deps = fakeDeps();
    const inventoryUrl =
      "https://rest-test.db.ripe.net/search.json?inverse-attribute=mnt-by&source=test&query-string=TEST-MNT&type-filter=mntner&type-filter=organisation";
    deps.httpClient.set(inventoryUrl, {
      objects: {
        object: [
          { type: "mntner", primaryKey: "TEST-MNT" },
          { type: "organisation", primaryKey: "ORG-TST1-TEST" }
        ]
      }
    });

    const result = await handleAuthenticatedInventory(
      { rir: "ripe", maintainer: "TEST-MNT", object_types: ["mntner", "organisation"] },
      deps,
      {
        INET_REGISTRY_MCP_PROFILE: "test",
        RIPE_API_KEY: "encoded-basic-secret"
      }
    );

    expect(result.ok).toBe(true);
    expect(deps.httpClient.calls[0]).toEqual({
      url: inventoryUrl,
      headers: {
        Accept: "application/json",
        Authorization: "Basic encoded-basic-secret"
      }
    });
    expect(JSON.stringify(result)).not.toContain("encoded-basic-secret");
  });

  it("requires a maintainer for RIPE inventory", async () => {
    const result = await handleAuthenticatedInventory(
      { rir: "ripe" },
      fakeDeps(),
      {
        INET_REGISTRY_MCP_PROFILE: "test",
        RIPE_API_KEY: "encoded-basic-secret"
      }
    );

    expect(result).toEqual({
      ok: false,
      error: "bad_request",
      detail: "RIPE authenticated resource inventory requires a maintainer name for inverse mnt-by lookup."
    });
  });

  it("redacts ARIN API keys from object lookup output", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://reg.ote.arin.net/rest/org/EXAMPLE?apikey=API-SECRET", {
      org: {
        handle: "EXAMPLE",
        name: "Example Org"
      }
    });

    const result = await handleAuthenticatedObjectLookup(
      { rir: "arin", object_type: "org", key: "EXAMPLE" },
      deps,
      {
        INET_REGISTRY_MCP_PROFILE: "test",
        ARIN_API_KEY: "API-SECRET"
      }
    );

    expect(result.ok).toBe(true);
    expect(JSON.stringify(result)).not.toContain("API-SECRET");
    expect(result.ok && result.data.endpoint).toBe("https://reg.ote.arin.net/rest/org/EXAMPLE?apikey=%3Credacted%3E");
  });

  it("requires configured ARIN inventory handles before inventory calls", async () => {
    const result = await handleAuthenticatedInventory(
      { rir: "arin" },
      fakeDeps(),
      {
        INET_REGISTRY_MCP_PROFILE: "test",
        ARIN_API_KEY: "API-SECRET"
      }
    );

    expect(result).toEqual({
      ok: false,
      error: "inventory_handles_not_configured",
      detail:
        "Set one or more ARIN_INVENTORY_* variables, for example ARIN_INVENTORY_ORG_HANDLES or ARIN_INVENTORY_NET_HANDLES."
    });
  });

  it("audits authenticated RIPE objects using read-only lookup results", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://rest-test.db.ripe.net/test/mntner/TEST-MNT.json?unfiltered", ripeMntner);

    const result = await handleWhoisDataQualityAudit(
      { rir: "ripe", object_type: "mntner", key: "TEST-MNT" },
      deps,
      {
        INET_REGISTRY_MCP_PROFILE: "test",
        RIPE_API_KEY: "encoded-basic-secret"
      }
    );

    expect(result.ok).toBe(true);
    expect(result.ok && result.data.summary.errors).toBe(0);
    expect(result.ok && result.data.issues.map((issue) => issue.code)).toContain("sensitive_auth_attributes_present");
    expect(result.ok && result.data.issues.find((issue) => issue.field === "tech-c")).toBeUndefined();
  });
});
