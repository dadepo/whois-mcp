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

const apnicMntner = {
  attributes: [
    { name: "mntner", value: "APNIC-TEST-MNT" },
    { name: "admin-c", value: "AA1-AP" },
    { name: "upd-to", value: "ops@example.test" },
    { name: "auth", value: "APITOKEN MEM-EXAMPLE token-tag" },
    { name: "mnt-by", value: "APNIC-TEST-MNT" },
    { name: "source", value: "APNIC" }
  ]
};

describe("authenticated WHOIS tools", () => {
  it("reports configured auth profile without exposing secrets", () => {
    const result = handleAuthStatus({
      WHOIS_MCP_PROFILE: "prod",
      RIPE_API_KEY: "ripe-secret",
      ARIN_API_KEY: "arin-secret",
      APNIC_API_KEY: "apnic-secret"
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.data.profile).toBe("production");
    expect(result.data.rirs.ripe.configured_credentials).toContain("RIPE_API_KEY");
    expect(result.data.rirs.arin.configured_credentials).toContain("ARIN_API_KEY");
    expect(result.data.rirs.apnic.configured_credentials).toContain("APNIC_API_KEY");
    expect(result.data.rirs.apnic.capabilities.inventory).toBe("available");
    expect(result.data.rirs.apnic.capabilities.object_lookup).toBe("available");
    expect(result.data.rirs.apnic.capabilities.data_quality_audit).toBe("available");
    expect(JSON.stringify(result.data)).not.toContain("ripe-secret");
    expect(JSON.stringify(result.data)).not.toContain("arin-secret");
    expect(JSON.stringify(result.data)).not.toContain("apnic-secret");
  });

  it("uses the RIPE test database profile for authenticated object lookup and returns protected registry values", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://rest-test.db.ripe.net/test/mntner/TEST-MNT.json?unfiltered", ripeMntner);

    const result = await handleAuthenticatedObjectLookup(
      { rir: "ripe", object_type: "mntner", key: "TEST-MNT" },
      deps,
      {
        WHOIS_MCP_PROFILE: "test",
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
        WHOIS_MCP_PROFILE: "test",
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
      { WHOIS_MCP_PROFILE: "test" }
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
        WHOIS_MCP_PROFILE: "test",
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
        WHOIS_MCP_PROFILE: "test",
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
        WHOIS_MCP_PROFILE: "test",
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
        WHOIS_MCP_PROFILE: "test",
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

  it("uses APNIC Registry API bearer auth for account-scoped object lookup", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://registry-api.apnic.net/v1/MEM-EXAMPLE/whois/mntner/APNIC-TEST-MNT", apnicMntner);

    const result = await handleAuthenticatedObjectLookup(
      { rir: "apnic", account: "MEM-EXAMPLE", object_type: "mntner", key: "APNIC-TEST-MNT" },
      deps,
      {
        APNIC_API_KEY: "APNIC-SECRET"
      }
    );

    expect(result.ok).toBe(true);
    expect(deps.httpClient.calls[0]).toEqual({
      url: "https://registry-api.apnic.net/v1/MEM-EXAMPLE/whois/mntner/APNIC-TEST-MNT",
      headers: {
        Accept: "application/json",
        Authorization: "Bearer APNIC-SECRET"
      }
    });
    expect(JSON.stringify(result)).toContain("APITOKEN MEM-EXAMPLE token-tag");
    expect(JSON.stringify(result)).not.toContain("APNIC-SECRET");
    expect(result.ok && result.data.account).toBe("MEM-EXAMPLE");
    expect(result.ok && result.data.registry_values_redacted).toBe(false);
  });

  it("accepts APNIC_REGISTRY_BASE overrides that already include v1", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://registry.example.test/v1/MEM-EXAMPLE/whois/mntner/APNIC-TEST-MNT", apnicMntner);

    const result = await handleAuthenticatedObjectLookup(
      { rir: "apnic", account: "MEM-EXAMPLE", object_type: "mntner", key: "APNIC-TEST-MNT" },
      deps,
      {
        APNIC_API_KEY: "APNIC-SECRET",
        APNIC_REGISTRY_BASE: "https://registry.example.test/v1"
      }
    );

    expect(result.ok).toBe(true);
    expect(deps.httpClient.calls[0]?.url).toBe("https://registry.example.test/v1/MEM-EXAMPLE/whois/mntner/APNIC-TEST-MNT");
  });

  it("requires an APNIC account for account-scoped object lookup", async () => {
    const result = await handleAuthenticatedObjectLookup(
      { rir: "apnic", object_type: "mntner", key: "APNIC-TEST-MNT" },
      fakeDeps(),
      {
        APNIC_API_KEY: "APNIC-SECRET"
      }
    );

    expect(result).toEqual({
      ok: false,
      error: "bad_request",
      detail:
        "APNIC authenticated object lookup requires an APNIC member account. APNIC Registry API calls are account-scoped, so include the account in the prompt or tool arguments."
    });
  });

  it("fetches APNIC account inventory from read-only Registry API endpoints", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://registry-api.apnic.net/v1/MEM-EXAMPLE/delegation/ipv4", {
      _embedded: { "delegation-ipv4": [{ range: "203.0.113.0/24" }] }
    });
    deps.httpClient.set("https://registry-api.apnic.net/v1/MEM-EXAMPLE/delegation/ipv6", {
      _embedded: { "delegation-ipv6": [{ range: "2001:db8::/32" }] }
    });
    deps.httpClient.set("https://registry-api.apnic.net/v1/MEM-EXAMPLE/delegation/autnum", {
      _embedded: { "delegation-autnum": [{ range: "AS64500" }] }
    });
    deps.httpClient.set("https://registry-api.apnic.net/v1/MEM-EXAMPLE/mntner", {
      _embedded: { mntner: [{ mntner: "APNIC-TEST-MNT" }] }
    });
    deps.httpClient.set("https://registry-api.apnic.net/v1/MEM-EXAMPLE/irt", {
      _embedded: { irt: [{ irt: "IRT-EXAMPLE-AP" }] }
    });

    const result = await handleAuthenticatedInventory(
      { rir: "apnic", account: "MEM-EXAMPLE" },
      deps,
      {
        APNIC_API_KEY: "APNIC-SECRET"
      }
    );

    expect(result.ok).toBe(true);
    expect(deps.httpClient.calls).toHaveLength(5);
    expect(deps.httpClient.calls.every((call) => call.headers?.Authorization === "Bearer APNIC-SECRET")).toBe(true);
    expect(result.ok && result.data.account).toBe("MEM-EXAMPLE");
    expect(result.ok && result.data.dataset).toBe("account:MEM-EXAMPLE");
    expect(JSON.stringify(result)).toContain("APNIC-TEST-MNT");
    expect(JSON.stringify(result)).not.toContain("APNIC-SECRET");
  });

  it("audits authenticated RIPE objects using read-only lookup results", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://rest-test.db.ripe.net/test/mntner/TEST-MNT.json?unfiltered", ripeMntner);

    const result = await handleWhoisDataQualityAudit(
      { rir: "ripe", object_type: "mntner", key: "TEST-MNT" },
      deps,
      {
        WHOIS_MCP_PROFILE: "test",
        RIPE_API_KEY: "encoded-basic-secret"
      }
    );

    expect(result.ok).toBe(true);
    expect(result.ok && result.data.summary.errors).toBe(0);
    expect(result.ok && result.data.issues.map((issue) => issue.code)).toContain("sensitive_auth_attributes_present");
    expect(result.ok && result.data.issues.find((issue) => issue.field === "tech-c")).toBeUndefined();
  });

  it("audits authenticated APNIC objects using read-only lookup results", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://registry-api.apnic.net/v1/MEM-EXAMPLE/whois/mntner/APNIC-TEST-MNT", apnicMntner);

    const result = await handleWhoisDataQualityAudit(
      { rir: "apnic", account: "MEM-EXAMPLE", object_type: "mntner", key: "APNIC-TEST-MNT" },
      deps,
      {
        APNIC_API_KEY: "APNIC-SECRET"
      }
    );

    expect(result.ok).toBe(true);
    expect(result.ok && result.data.account).toBe("MEM-EXAMPLE");
    expect(result.ok && result.data.summary.errors).toBe(0);
    expect(result.ok && result.data.issues.map((issue) => issue.code)).toContain("sensitive_auth_attributes_present");
  });

  it("reports APNIC data-quality gaps for missing expected fields and abuse references", async () => {
    const deps = fakeDeps();
    deps.httpClient.set("https://registry-api.apnic.net/v1/MEM-EXAMPLE/whois/organisation/ORG-EXAMPLE-AP", {
      attributes: [
        { name: "organisation", value: "ORG-EXAMPLE-AP" },
        { name: "org-name", value: "Example APNIC Org" },
        { name: "org-type", value: "LIR" },
        { name: "address", value: "Example Street" },
        { name: "mnt-ref", value: "APNIC-TEST-MNT" },
        { name: "mnt-by", value: "APNIC-TEST-MNT" },
        { name: "source", value: "APNIC" }
      ]
    });

    const result = await handleWhoisDataQualityAudit(
      { rir: "apnic", account: "MEM-EXAMPLE", object_type: "organisation", key: "ORG-EXAMPLE-AP" },
      deps,
      {
        APNIC_API_KEY: "APNIC-SECRET"
      }
    );

    expect(result.ok).toBe(true);
    expect(result.ok && result.data.issues.map((issue) => issue.code)).toContain("missing_required_attribute");
    expect(result.ok && result.data.issues.map((issue) => issue.code)).toContain("missing_abuse_or_irt_reference");
  });
});
