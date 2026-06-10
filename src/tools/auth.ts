import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import {
  apnicAuthorizationHeader,
  arinUrlWithApiKey,
  authEndpoints,
  envList,
  parseWhoisMcpProfile,
  readAuthConfig,
  redactUrlSecrets,
  ripeAuthorizationHeader,
  secretValue,
  type AuthEnv,
  type AuthConfig
} from "../auth.js";
import type { RirId } from "../config.js";
import type { ToolDependencies } from "../deps.js";
import { asArray, asRecord, stringValue } from "../lib/object.js";
import { ripeAttrs, ripeObjects } from "../lib/ripe-object.js";
import { toMcpResult, type ToolResult } from "../types.js";

interface AuthStatusData extends AuthConfig {
  note: string;
}

interface InventoryArgs {
  rir?: RirId | null | undefined;
  account?: string | null | undefined;
  maintainer?: string | null | undefined;
  object_types?: string[] | null | undefined;
}

interface InventoryData {
  profile: string;
  rir: RirId;
  account?: string;
  dataset: string;
  records: unknown;
  endpoint: string;
}

interface ObjectLookupArgs {
  rir: RirId;
  account?: string | null | undefined;
  object_type: string;
  key: string;
}

interface ObjectLookupData {
  profile: string;
  rir: RirId;
  account?: string;
  object_type: string;
  key: string;
  endpoint: string;
  local_secrets_redacted: boolean;
  registry_values_redacted: boolean;
  object: unknown;
}

interface DataQualityAuditArgs {
  rir: RirId;
  account?: string | null | undefined;
  object_type: string;
  key: string;
}

interface AuditIssue {
  severity: "error" | "warning" | "info";
  code: string;
  message: string;
  field?: string;
}

interface DataQualityAuditData {
  profile: string;
  rir: RirId;
  account?: string;
  object_type: string;
  key: string;
  issues: AuditIssue[];
  summary: {
    errors: number;
    warnings: number;
    info: number;
  };
}

const rirSchema = z.enum(["ripe", "arin", "apnic", "afrinic", "lacnic"]);

const arinInventorySources: Array<{ objectType: string; envKey: string; path: string }> = [
  { objectType: "org", envKey: "ARIN_INVENTORY_ORG_HANDLES", path: "org" },
  { objectType: "net", envKey: "ARIN_INVENTORY_NET_HANDLES", path: "net" },
  { objectType: "poc", envKey: "ARIN_INVENTORY_POC_HANDLES", path: "poc" },
  { objectType: "customer", envKey: "ARIN_INVENTORY_CUSTOMER_HANDLES", path: "customer" },
  { objectType: "delegation", envKey: "ARIN_INVENTORY_DELEGATION_NAMES", path: "delegation" },
  { objectType: "ticket", envKey: "ARIN_INVENTORY_TICKET_NUMBERS", path: "ticket" }
];

const arinObjectPaths: Record<string, string> = {
  org: "org",
  net: "net",
  poc: "poc",
  customer: "customer",
  delegation: "delegation",
  ticket: "ticket"
};

const apnicInventorySources: Array<{ dataset: string; path: string[] }> = [
  { dataset: "delegation-ipv4", path: ["delegation", "ipv4"] },
  { dataset: "delegation-ipv6", path: ["delegation", "ipv6"] },
  { dataset: "delegation-autnum", path: ["delegation", "autnum"] },
  { dataset: "mntner", path: ["mntner"] },
  { dataset: "irt", path: ["irt"] }
];

export function handleAuthStatus(env: AuthEnv = process.env): ToolResult<AuthStatusData> {
  try {
    return {
      ok: true,
      data: {
        ...readAuthConfig(env),
        note: "Credential values are intentionally omitted. A configured credential means the variable is present and non-empty."
      }
    };
  } catch (error) {
    return {
      ok: false,
      error: "invalid_auth_profile",
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

export async function handleAuthenticatedInventory(
  args: InventoryArgs,
  deps: ToolDependencies,
  env: AuthEnv = process.env
): Promise<ToolResult<InventoryData>> {
  const rir = args.rir ?? "ripe";
  if (rir === "ripe") {
    return getRipeInventory(args.maintainer, args.object_types, deps, env);
  }
  if (rir === "arin") {
    return getArinInventory(deps, env);
  }
  if (rir === "apnic") {
    return getApnicInventory(args.account, deps, env);
  }
  return unsupportedRir(rir, "authenticated resource inventory");
}

export async function handleAuthenticatedObjectLookup(
  args: ObjectLookupArgs,
  deps: ToolDependencies,
  env: AuthEnv = process.env
): Promise<ToolResult<ObjectLookupData>> {
  if (args.rir === "ripe") {
    return getRipeObject(args.object_type, args.key, deps, env);
  }
  if (args.rir === "arin") {
    return getArinObject(args.object_type, args.key, deps, env);
  }
  if (args.rir === "apnic") {
    return getApnicObject(args.account, args.object_type, args.key, deps, env);
  }
  return unsupportedRir(args.rir, "authenticated object lookup");
}

export async function handleWhoisDataQualityAudit(
  args: DataQualityAuditArgs,
  deps: ToolDependencies,
  env: AuthEnv = process.env
): Promise<ToolResult<DataQualityAuditData>> {
  if (args.rir !== "ripe" && args.rir !== "arin" && args.rir !== "apnic") {
    return unsupportedRir(args.rir, "WHOIS data quality audit");
  }

  const lookup = await handleAuthenticatedObjectLookup(args, deps, env);
  if (!lookup.ok) {
    return lookup;
  }

  const issues = args.rir === "ripe"
    ? auditRipeObject(args.object_type, lookup.data.object)
    : args.rir === "arin"
      ? auditArinObject(args.object_type, lookup.data.object)
      : auditApnicObject(args.object_type, lookup.data.object);

  return {
    ok: true,
    data: {
      profile: lookup.data.profile,
      rir: args.rir,
      ...(lookup.data.account ? { account: lookup.data.account } : {}),
      object_type: args.object_type,
      key: args.key,
      issues,
      summary: summarizeIssues(issues)
    }
  };
}

export function registerAuthTools(server: McpServer, deps: ToolDependencies): void {
  server.registerTool(
    "whois_auth_status",
    {
      description:
        "Show the read-only authenticated WHOIS profile, configured RIR credentials, endpoints, and available authenticated capabilities. Never returns secret values.",
      inputSchema: {}
    },
    async () => toMcpResult(handleAuthStatus())
  );

  server.registerTool(
    "whois_authenticated_resource_inventory",
    {
      description:
        "Read-only authenticated WHOIS resource inventory. RIPE lists objects maintained by a mntner using an authenticated RIPE Database inverse lookup. ARIN reads configured inventory handles through Reg-RWS. APNIC reads account-scoped Registry API delegations, maintainers, and IRTs.",
      inputSchema: {
        rir: rirSchema.nullable().optional().describe("RIR to query. Defaults to RIPE. Currently implemented for RIPE, ARIN, and APNIC."),
        account: z
          .string()
          .nullable()
          .optional()
          .describe("APNIC member account to query. Required for APNIC because APNIC Registry API calls are account-scoped."),
        maintainer: z
          .string()
          .nullable()
          .optional()
          .describe("RIPE mntner name to inventory by inverse mnt-by lookup, for example DADEPO-TEST-MNT."),
        object_types: z
          .array(z.string())
          .nullable()
          .optional()
          .describe("Optional RIPE object type filters, for example ['mntner', 'person', 'role', 'organisation'].")
      }
    },
    async (args) => toMcpResult(await handleAuthenticatedInventory(args, deps))
  );

  server.registerTool(
    "whois_authenticated_object_lookup",
    {
      description:
        "Read-only authenticated lookup for a specific WHOIS registry object. Supports RIPE Database REST API, ARIN Reg-RWS, and APNIC Registry API. Local MCP credential secrets are redacted, but authenticated registry object values are returned as received.",
      inputSchema: {
        rir: rirSchema.describe("RIR to query. Currently implemented for RIPE, ARIN, and APNIC."),
        account: z
          .string()
          .nullable()
          .optional()
          .describe("APNIC member account to query. Required for APNIC because APNIC Registry API calls are account-scoped."),
        object_type: z.string().describe("Registry object type, for example organisation, mntner, inetnum, aut-num, route, org, net, poc."),
        key: z.string().describe("Object key or handle to retrieve. Local configured secret values are always redacted if they appear in responses.")
      }
    },
    async (args) => toMcpResult(await handleAuthenticatedObjectLookup(args, deps))
  );

  server.registerTool(
    "whois_data_quality_audit",
    {
      description:
        "Read-only WHOIS data quality audit for an authenticated RIPE, ARIN, or APNIC object lookup. Reports missing expected fields and risky data-quality gaps without making changes.",
      inputSchema: {
        rir: rirSchema.describe("RIR to query. Currently implemented for RIPE, ARIN, and APNIC."),
        account: z
          .string()
          .nullable()
          .optional()
          .describe("APNIC member account to query. Required for APNIC because APNIC Registry API calls are account-scoped."),
        object_type: z.string().describe("Registry object type to audit."),
        key: z.string().describe("Object key or handle to retrieve and audit.")
      }
    },
    async (args) => toMcpResult(await handleWhoisDataQualityAudit(args, deps))
  );
}

async function getRipeInventory(
  maintainer: string | null | undefined,
  objectTypes: string[] | null | undefined,
  deps: ToolDependencies,
  env: AuthEnv
): Promise<ToolResult<InventoryData>> {
  let profile;
  try {
    profile = parseWhoisMcpProfile(env.WHOIS_MCP_PROFILE);
  } catch (error) {
    return invalidProfile(error);
  }

  const authHeader = ripeAuthorizationHeader(env);
  if (!authHeader) {
    return missingCredential("RIPE_API_KEY", "RIPE authenticated resource inventory");
  }

  const normalizedMaintainer = maintainer?.trim();
  if (!normalizedMaintainer) {
    return {
      ok: false,
      error: "bad_request",
      detail: "RIPE authenticated resource inventory requires a maintainer name for inverse mnt-by lookup."
    };
  }

  const endpoints = authEndpoints(profile, env);
  const endpoint = ripeSearchEndpoint(endpoints.ripeDatabaseRestBase, normalizedMaintainer, objectTypes ?? []);
  try {
    const records = await deps.httpClient.getJson(endpoint, {
      headers: {
        Accept: "application/json",
        Authorization: authHeader
      }
    });
    return {
      ok: true,
      data: {
        profile,
        rir: "ripe",
        dataset: `mnt-by:${normalizedMaintainer}`,
        records: redactKnownSecrets(records, env),
        endpoint
      }
    };
  } catch (error) {
    return lookupError(error);
  }
}

async function getArinInventory(deps: ToolDependencies, env: AuthEnv): Promise<ToolResult<InventoryData>> {
  let profile;
  try {
    profile = parseWhoisMcpProfile(env.WHOIS_MCP_PROFILE);
  } catch (error) {
    return invalidProfile(error);
  }

  if (!secretValue("ARIN_API_KEY", env)) {
    return missingCredential("ARIN_API_KEY", "ARIN authenticated resource inventory");
  }

  const endpoints = authEndpoints(profile, env);
  const requestedObjects = arinInventorySources.flatMap((source) =>
    envList(source.envKey, env).map((handle) => ({
      ...source,
      handle
    }))
  );

  if (requestedObjects.length === 0) {
    return {
      ok: false,
      error: "inventory_handles_not_configured",
      detail:
        "Set one or more ARIN_INVENTORY_* variables, for example ARIN_INVENTORY_ORG_HANDLES or ARIN_INVENTORY_NET_HANDLES."
    };
  }

  try {
    const records = [];
    for (const requested of requestedObjects) {
      const baseUrl = joinUrl(endpoints.arinRegRestBase, requested.path, requested.handle);
      const url = arinUrlWithApiKey(baseUrl, env);
      if (!url) {
        return missingCredential("ARIN_API_KEY", "ARIN authenticated resource inventory");
      }
      const raw = await deps.httpClient.getText(url, { headers: { Accept: "application/json, application/xml, text/plain" } });
      records.push({
        object_type: requested.objectType,
        key: requested.handle,
        endpoint: redactUrlSecrets(url),
        object: redactKnownSecrets(parseMaybeJson(raw), env)
      });
    }

    return {
      ok: true,
      data: {
        profile,
        rir: "arin",
        dataset: "configured-handles",
        records,
        endpoint: endpoints.arinRegRestBase
      }
    };
  } catch (error) {
    return lookupError(error);
  }
}

async function getApnicInventory(
  account: string | null | undefined,
  deps: ToolDependencies,
  env: AuthEnv
): Promise<ToolResult<InventoryData>> {
  let profile;
  try {
    profile = parseWhoisMcpProfile(env.WHOIS_MCP_PROFILE);
  } catch (error) {
    return invalidProfile(error);
  }

  const authHeader = apnicAuthorizationHeader(env);
  if (!authHeader) {
    return missingCredential("APNIC_API_KEY", "APNIC authenticated resource inventory");
  }

  const normalizedAccount = normalizedApnicAccount(account);
  if (!normalizedAccount) {
    return missingApnicAccount("APNIC authenticated resource inventory");
  }

  const endpointBase = authEndpoints(profile, env).apnicRegistryBase;
  try {
    const records = [];
    for (const source of apnicInventorySources) {
      const endpoint = apnicEndpoint(endpointBase, normalizedAccount, ...source.path);
      const object = await deps.httpClient.getJson(endpoint, {
        headers: {
          Accept: "application/json",
          Authorization: authHeader
        }
      });
      records.push({
        dataset: source.dataset,
        endpoint,
        object: redactKnownSecrets(object, env)
      });
    }

    return {
      ok: true,
      data: {
        profile,
        rir: "apnic",
        account: normalizedAccount,
        dataset: `account:${normalizedAccount}`,
        records,
        endpoint: endpointBase
      }
    };
  } catch (error) {
    return lookupError(error);
  }
}

async function getRipeObject(
  objectType: string,
  key: string,
  deps: ToolDependencies,
  env: AuthEnv
): Promise<ToolResult<ObjectLookupData>> {
  let profile;
  try {
    profile = parseWhoisMcpProfile(env.WHOIS_MCP_PROFILE);
  } catch (error) {
    return invalidProfile(error);
  }

  const authHeader = ripeAuthorizationHeader(env);
  if (!authHeader) {
    return missingCredential("RIPE_API_KEY", "RIPE authenticated object lookup");
  }

  const endpoint = `${joinUrl(authEndpoints(profile, env).ripeDatabaseRestBase, objectType, key)}.json?unfiltered`;
  try {
    const object = await deps.httpClient.getJson(endpoint, {
      headers: {
        Accept: "application/json",
        Authorization: authHeader
      }
    });
    return {
      ok: true,
      data: {
        profile,
        rir: "ripe",
        object_type: objectType,
        key,
        endpoint,
        local_secrets_redacted: true,
        registry_values_redacted: false,
        object: redactKnownSecrets(object, env)
      }
    };
  } catch (error) {
    return lookupError(error);
  }
}

async function getArinObject(
  objectType: string,
  key: string,
  deps: ToolDependencies,
  env: AuthEnv
): Promise<ToolResult<ObjectLookupData>> {
  let profile;
  try {
    profile = parseWhoisMcpProfile(env.WHOIS_MCP_PROFILE);
  } catch (error) {
    return invalidProfile(error);
  }

  const path = arinObjectPaths[objectType.toLowerCase()];
  if (!path) {
    return {
      ok: false,
      error: "bad_request",
      detail: `Unsupported ARIN object type '${objectType}'. Supported: ${Object.keys(arinObjectPaths).join(", ")}.`
    };
  }

  const baseUrl = joinUrl(authEndpoints(profile, env).arinRegRestBase, path, key);
  const url = arinUrlWithApiKey(baseUrl, env);
  if (!url) {
    return missingCredential("ARIN_API_KEY", "ARIN authenticated object lookup");
  }

  try {
    const raw = await deps.httpClient.getText(url, { headers: { Accept: "application/json, application/xml, text/plain" } });
    return {
      ok: true,
      data: {
        profile,
        rir: "arin",
        object_type: objectType,
        key,
        endpoint: redactUrlSecrets(url),
        local_secrets_redacted: true,
        registry_values_redacted: false,
        object: redactKnownSecrets(parseMaybeJson(raw), env)
      }
    };
  } catch (error) {
    return lookupError(error);
  }
}

async function getApnicObject(
  account: string | null | undefined,
  objectType: string,
  key: string,
  deps: ToolDependencies,
  env: AuthEnv
): Promise<ToolResult<ObjectLookupData>> {
  let profile;
  try {
    profile = parseWhoisMcpProfile(env.WHOIS_MCP_PROFILE);
  } catch (error) {
    return invalidProfile(error);
  }

  const authHeader = apnicAuthorizationHeader(env);
  if (!authHeader) {
    return missingCredential("APNIC_API_KEY", "APNIC authenticated object lookup");
  }

  const normalizedAccount = normalizedApnicAccount(account);
  if (!normalizedAccount) {
    return missingApnicAccount("APNIC authenticated object lookup");
  }

  const endpoint = apnicEndpoint(authEndpoints(profile, env).apnicRegistryBase, normalizedAccount, "whois", objectType, key);
  try {
    const object = await deps.httpClient.getJson(endpoint, {
      headers: {
        Accept: "application/json",
        Authorization: authHeader
      }
    });
    return {
      ok: true,
      data: {
        profile,
        rir: "apnic",
        account: normalizedAccount,
        object_type: objectType,
        key,
        endpoint,
        local_secrets_redacted: true,
        registry_values_redacted: false,
        object: redactKnownSecrets(object, env)
      }
    };
  } catch (error) {
    return lookupError(error);
  }
}

function auditRipeObject(objectType: string, data: unknown): AuditIssue[] {
  const objects = ripeObjects(data);
  if (objects.length === 0) {
    return [
      {
        severity: "error",
        code: "object_not_found_in_response",
        message: "The RIPE response did not contain a WHOIS object."
      }
    ];
  }

  const object = objects[0];
  const issues: AuditIssue[] = [];
  const required = ripeRequiredAttributes(objectType.toLowerCase());
  for (const attr of required) {
    if (ripeAttrs(object, attr).length === 0) {
      issues.push({
        severity: "error",
        code: "missing_required_attribute",
        field: attr,
        message: `Missing expected RIPE attribute '${attr}'.`
      });
    }
  }

  if (["organisation", "aut-num", "inetnum", "inet6num"].includes(objectType.toLowerCase())) {
    if (ripeAttrs(object, "abuse-c").length === 0) {
      issues.push({
        severity: "warning",
        code: "missing_abuse_reference",
        field: "abuse-c",
        message: "No abuse-c reference is present on this object. Check related organisation objects if abuse is delegated there."
      });
    }
  }

  const authAttrs = ripeAttrs(object, "auth");
  if (authAttrs.length > 0) {
    issues.push({
      severity: "info",
      code: "sensitive_auth_attributes_present",
      field: "auth",
      message: "auth attributes are present in authenticated WHOIS output."
    });
  }

  if (issues.length === 0) {
    issues.push({
      severity: "info",
      code: "no_basic_issues_found",
      message: "No basic RIPE data-quality issues were found by the read-only audit rules."
    });
  }
  return issues;
}

function auditApnicObject(objectType: string, data: unknown): AuditIssue[] {
  const attrs = apnicAttributeMap(data);
  if (attrs.size === 0) {
    return [
      {
        severity: "error",
        code: "object_not_found_in_response",
        message: "The APNIC response did not contain a WHOIS object with attributes."
      }
    ];
  }

  const issues: AuditIssue[] = [];
  const required = apnicRequiredAttributes(objectType.toLowerCase());
  for (const attr of required) {
    if (!attrs.has(attr)) {
      issues.push({
        severity: "error",
        code: "missing_required_attribute",
        field: attr,
        message: `Missing expected APNIC attribute '${attr}'.`
      });
    }
  }

  if (["organisation", "aut-num", "inetnum", "inet6num"].includes(objectType.toLowerCase())) {
    if (!attrs.has("mnt-irt") && !attrs.has("abuse-c")) {
      issues.push({
        severity: "warning",
        code: "missing_abuse_or_irt_reference",
        field: "mnt-irt",
        message: "No mnt-irt or abuse-c reference is present on this APNIC object."
      });
    }
  }

  if (attrs.has("auth")) {
    issues.push({
      severity: "info",
      code: "sensitive_auth_attributes_present",
      field: "auth",
      message: "auth attributes are present in authenticated WHOIS output."
    });
  }

  if (issues.length === 0) {
    issues.push({
      severity: "info",
      code: "no_basic_issues_found",
      message: "No basic APNIC data-quality issues were found by the read-only audit rules."
    });
  }
  return issues;
}

function auditArinObject(objectType: string, data: unknown): AuditIssue[] {
  if (typeof data === "string") {
    return [
      {
        severity: "info",
        code: "raw_response_not_structurally_audited",
        message: "ARIN returned a non-JSON response, so only retrieval was verified. Use JSON-capable ARIN responses for structural audit checks."
      }
    ];
  }

  const record = asRecord(data);
  const nestedRoot = asRecord(record[objectType.toLowerCase()]);
  const root = Object.keys(nestedRoot).length > 0 ? nestedRoot : record;
  const issues: AuditIssue[] = [];

  if (objectType.toLowerCase() === "org") {
    if (!hasAnyPath(root, [["handle"], ["orgHandle"]])) {
      issues.push(missingField("handle"));
    }
    if (!hasAnyPath(root, [["name"], ["orgName"]])) {
      issues.push(missingField("name"));
    }
    if (!hasArinPocLinks(root)) {
      issues.push({
        severity: "warning",
        code: "missing_poc_links",
        field: "pocLinks",
        message: "No POC links were found on the ARIN org response."
      });
    }
  } else if (objectType.toLowerCase() === "net") {
    if (!hasAnyPath(root, [["handle"], ["netHandle"]])) {
      issues.push(missingField("handle"));
    }
    if (!hasAnyPath(root, [["netBlocks"], ["netBlock"]])) {
      issues.push(missingField("netBlocks"));
    }
    if (!hasAnyPath(root, [["orgRef"]])) {
      issues.push(missingField("orgRef"));
    }
  }

  if (issues.length === 0) {
    issues.push({
      severity: "info",
      code: "no_basic_issues_found",
      message: "No basic ARIN data-quality issues were found by the read-only audit rules."
    });
  }
  return issues;
}

function apnicRequiredAttributes(objectType: string): string[] {
  const common = ["mnt-by", "source"];
  const byType: Record<string, string[]> = {
    organisation: ["organisation", "org-name", "org-type", "address", "e-mail", "mnt-ref", ...common],
    inetnum: ["inetnum", "netname", "descr", "country", "admin-c", "tech-c", "status", ...common],
    inet6num: ["inet6num", "netname", "descr", "country", "admin-c", "tech-c", "status", ...common],
    "aut-num": ["aut-num", "as-name", "descr", "country", "admin-c", "tech-c", ...common],
    mntner: ["mntner", "admin-c", "upd-to", "auth", ...common],
    route: ["route", "origin", ...common],
    route6: ["route6", "origin", ...common],
    "as-set": ["as-set", "descr", "admin-c", "tech-c", ...common],
    person: ["person", "address", "phone", "e-mail", "nic-hdl", ...common],
    role: ["role", "address", "e-mail", "nic-hdl", ...common],
    irt: ["irt", "address", "e-mail", "abuse-mailbox", ...common]
  };
  return byType[objectType] ?? common;
}

function ripeRequiredAttributes(objectType: string): string[] {
  const common = ["mnt-by", "source"];
  const byType: Record<string, string[]> = {
    organisation: ["organisation", "org-name", "org-type", "address", "e-mail", "mnt-ref", ...common],
    inetnum: ["inetnum", "netname", "country", "admin-c", "tech-c", "status", ...common],
    inet6num: ["inet6num", "netname", "country", "admin-c", "tech-c", "status", ...common],
    "aut-num": ["aut-num", "as-name", "admin-c", "tech-c", "status", ...common],
    mntner: ["mntner", "admin-c", "upd-to", "auth", ...common],
    route: ["route", "origin", ...common],
    route6: ["route6", "origin", ...common],
    "as-set": ["as-set", "admin-c", "tech-c", ...common],
    person: ["person", "nic-hdl", ...common],
    role: ["role", "nic-hdl", ...common]
  };
  return byType[objectType] ?? common;
}

function apnicAttributeMap(data: unknown): Map<string, string[]> {
  const attrs = asArray(asRecord(data).attributes);
  const mapped = new Map<string, string[]>();
  for (const attr of attrs) {
    const record = asRecord(attr);
    const name = stringValue(record.name).trim().toLowerCase();
    const value = stringValue(record.value);
    if (!name) {
      continue;
    }
    mapped.set(name, [...(mapped.get(name) ?? []), value]);
  }
  return mapped;
}

function hasArinPocLinks(root: Record<string, unknown>): boolean {
  const pocLinks = asRecord(root.pocLinks).pocLinkRef ?? asRecord(root.pocs).pocLinkRef;
  return asArray(pocLinks).length > 0 || Object.keys(asRecord(pocLinks)).length > 0;
}

function hasAnyPath(value: unknown, paths: string[][]): boolean {
  return paths.some((path) => {
    let cursor: unknown = value;
    for (const segment of path) {
      cursor = asRecord(cursor)[segment];
    }
    if (typeof cursor === "string") {
      return cursor.trim() !== "";
    }
    if (Array.isArray(cursor)) {
      return cursor.length > 0;
    }
    if (cursor !== null && typeof cursor === "object") {
      return Object.keys(asRecord(cursor)).length > 0;
    }
    return cursor !== undefined && cursor !== null;
  });
}

function missingField(field: string): AuditIssue {
  return {
    severity: "error",
    code: "missing_expected_field",
    field,
    message: `Missing expected ARIN field '${field}'.`
  };
}

function summarizeIssues(issues: AuditIssue[]): DataQualityAuditData["summary"] {
  return {
    errors: issues.filter((issue) => issue.severity === "error").length,
    warnings: issues.filter((issue) => issue.severity === "warning").length,
    info: issues.filter((issue) => issue.severity === "info").length
  };
}

function unsupportedRir<T>(rir: RirId, capability: string): ToolResult<T> {
  return {
    ok: false,
    error: "not_supported",
    detail: `${capability} is not implemented for ${rir}. The tool remains read-only and only exposes provider-specific authenticated paths once they are implemented.`
  };
}

function missingCredential<T>(credential: string, capability: string): ToolResult<T> {
  return {
    ok: false,
    error: "auth_not_configured",
    detail: `${capability} requires ${credential}.`
  };
}

function missingApnicAccount<T>(capability: string): ToolResult<T> {
  return {
    ok: false,
    error: "bad_request",
    detail: `${capability} requires an APNIC member account. APNIC Registry API calls are account-scoped, so include the account in the prompt or tool arguments.`
  };
}

function invalidProfile<T>(error: unknown): ToolResult<T> {
  return {
    ok: false,
    error: "invalid_auth_profile",
    detail: error instanceof Error ? error.message : String(error)
  };
}

function lookupError<T>(error: unknown): ToolResult<T> {
  return {
    ok: false,
    error: "lookup_error",
    detail: error instanceof Error ? error.message : String(error)
  };
}

function normalizedApnicAccount(account: string | null | undefined): string | null {
  const normalized = account?.trim();
  return normalized ? normalized : null;
}

function joinUrl(base: string, ...segments: string[]): string {
  const trimmedBase = base.replace(/\/+$/, "");
  const path = segments
    .filter((segment) => segment !== "")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return path ? `${trimmedBase}/${path}` : trimmedBase;
}

function apnicEndpoint(base: string, account: string, ...segments: string[]): string {
  const parsed = new URL(base);
  const path = parsed.pathname.replace(/\/+$/, "");
  const pathSegments = path.endsWith("/v1") ? [account, ...segments] : ["v1", account, ...segments];
  return joinUrl(base, ...pathSegments);
}

function ripeSearchEndpoint(databaseRestBase: string, maintainer: string, objectTypes: string[]): string {
  const baseUrl = new URL(databaseRestBase);
  const source = baseUrl.pathname.replace(/^\/+|\/+$/g, "").split("/").filter(Boolean).at(-1) ?? "ripe";
  const params = new URLSearchParams();
  params.set("inverse-attribute", "mnt-by");
  params.set("source", source);
  params.set("query-string", maintainer);
  for (const objectType of objectTypes.map((value) => value.trim()).filter(Boolean)) {
    params.append("type-filter", objectType);
  }
  return `${baseUrl.origin}/search.json?${params.toString()}`;
}

function withQuery(url: string, query: string): string {
  return url.includes("?") ? `${url}&${query}` : `${url}?${query}`;
}

function parseMaybeJson(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
}

function redactKnownSecrets(value: unknown, env: AuthEnv): unknown {
  const secrets = [
    "RIPE_API_KEY",
    "ARIN_API_KEY",
    "APNIC_API_KEY",
    "LACNIC_ACCESS_TOKEN",
    "LACNIC_CLIENT_SECRET"
  ]
    .map((key) => secretValue(key, env))
    .filter((secret): secret is string => secret !== null);

  return redactSecrets(value, secrets);
}

function redactSecrets(value: unknown, secrets: string[]): unknown {
  if (typeof value === "string") {
    return secrets.reduce((redacted, secret) => redacted.split(secret).join("<redacted>"), value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item, secrets));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, redactSecrets(child, secrets)])
    );
  }
  return value;
}
