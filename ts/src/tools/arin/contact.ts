import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import { TTLCache } from "../../cache.js";
import { ARIN_REST_BASE, RIRS } from "../../config.js";
import type { ToolDependencies } from "../../deps.js";
import { asArray, asRecord, dollarString, normalizeList } from "../../lib/object.js";
import { toMcpResult, type ToolResult } from "../../types.js";
import type { ContactArgs } from "../rdap-contact.js";

interface ArinContactData {
  query: { type: string; value: string | null | undefined };
  organization: Record<string, unknown>;
  abuse: Record<string, unknown> | null;
  admin_contacts: Record<string, unknown>[];
  tech_contacts: Record<string, unknown>[];
  noc_contacts: Record<string, unknown>[];
}

const cache = new TTLCache<string, ToolResult<ArinContactData>>({
  maxItems: 500,
  ttlSeconds: 600
});

interface PocLink {
  handle: string;
  function: string;
  description: string;
}

async function getJson(deps: ToolDependencies, url: string): Promise<Record<string, unknown>> {
  return asRecord(await deps.httpClient.getJson(url, { notFoundValue: {}, headers: { Accept: "application/json" } }));
}

function dollarStringList(value: unknown): string[] {
  return normalizeList(value)
    .map((item) => dollarString(item) || dollarString(asRecord(item).number))
    .filter(Boolean);
}

async function getPocDetails(deps: ToolDependencies, pocHandle: string): Promise<Record<string, unknown> | null> {
  try {
    const pocData = await getJson(deps, `${ARIN_REST_BASE}/poc/${pocHandle}`);
    if (Object.keys(pocData).length === 0) {
      return null;
    }

    const poc = asRecord(pocData.poc);
    const emails = dollarStringList(asRecord(poc.emails).email);
    const phones = dollarStringList(asRecord(poc.phones).phone);

    return {
      handle: pocHandle,
      name: dollarString(poc.companyName) || dollarString(poc.contactName),
      emails,
      phones,
      type: dollarString(poc.contactType)
    };
  } catch {
    return null;
  }
}

function extractPocLinks(source: Record<string, unknown>): PocLink[] {
  const rawPocRefs = asRecord(source.pocLinks).pocLinkRef ?? asRecord(source.pocs).pocLinkRef;
  return normalizeList(rawPocRefs as Record<string, unknown> | Record<string, unknown>[] | undefined)
    .map((rawPocRef) => {
      const pocRef = asRecord(rawPocRef);
      return {
        handle: String(pocRef["@handle"] ?? ""),
        function: String(pocRef["@function"] ?? ""),
        description: String(pocRef["@description"] ?? "")
      };
    })
    .filter((pocLink) => pocLink.handle);
}

async function getOrgPocLinks(deps: ToolDependencies, orgHandle: unknown): Promise<PocLink[]> {
  if (typeof orgHandle !== "string" || !orgHandle) {
    return [];
  }

  const orgPocs = await getJson(deps, `${ARIN_REST_BASE}/org/${orgHandle}/pocs`);
  return extractPocLinks(orgPocs);
}

function pocLinkRole(pocLink: PocLink): string {
  return `${pocLink.function} ${pocLink.description}`.toLowerCase();
}

function isAbusePoc(pocLink: PocLink): boolean {
  const func = pocLink.function.toLowerCase();
  return func === "ab" || pocLinkRole(pocLink).includes("abuse");
}

function isAdminPoc(pocLink: PocLink): boolean {
  const func = pocLink.function.toLowerCase();
  const role = pocLinkRole(pocLink);
  return func === "ad" || role.includes("admin") || role.includes("administrative");
}

function isTechPoc(pocLink: PocLink): boolean {
  const func = pocLink.function.toLowerCase();
  const role = pocLinkRole(pocLink);
  return func === "t" || role.includes("tech") || role.includes("technical");
}

function isNocPoc(pocLink: PocLink): boolean {
  const func = pocLink.function.toLowerCase();
  return func === "n" || pocLinkRole(pocLink).includes("noc");
}

export async function handleArinContact(args: ContactArgs, deps: ToolDependencies): Promise<ToolResult<ArinContactData>> {
  const rir = RIRS.arin;
  if (!rir.enabled) {
    return {
      ok: false,
      error: "service_disabled",
      detail: "ARIN contact card support is disabled. Set SUPPORT_ARIN=true to enable."
    };
  }

  const providedParams = [args.ip, args.asn, args.org].filter((value) => value !== undefined && value !== null).length;
  if (providedParams !== 1) {
    return {
      ok: false,
      error: "bad_request",
      detail: "Provide exactly one of: ip, asn, or org"
    };
  }

  let cacheKey: string;
  let queryType: string;
  let queryValue: string | null | undefined;
  if (args.ip) {
    cacheKey = `arin:contact_ip:${args.ip}`;
    queryType = "ip";
    queryValue = args.ip;
  } else if (args.asn !== undefined && args.asn !== null) {
    cacheKey = `arin:contact_asn:${args.asn}`;
    queryType = "asn";
    queryValue = String(args.asn);
  } else {
    cacheKey = `arin:contact_org:${args.org}`;
    queryType = "org";
    queryValue = args.org;
  }

  const cached = cache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }

  try {
    let url: string;
    if (args.ip) {
      url = `${ARIN_REST_BASE}/ip/${args.ip}`;
    } else if (args.asn !== undefined && args.asn !== null) {
      url = `${ARIN_REST_BASE}/asn/AS${args.asn}`;
    } else {
      url = `${ARIN_REST_BASE}/org/${args.org}`;
    }

    const data = await getJson(deps, url);
    if (Object.keys(data).length === 0) {
      const result: ToolResult<ArinContactData> = {
        ok: false,
        error: "not_found",
        detail: `No records found for ${queryType}='${queryValue}'`
      };
      cache.set(cacheKey, result);
      return result;
    }

    let organization: Record<string, unknown> = {};
    if ("net" in data) {
      const orgRef = asRecord(asRecord(data.net).orgRef);
      organization = {
        key: orgRef["@handle"] ?? "",
        name: orgRef["@name"] ?? "",
        country: "US"
      };
    } else if ("asn" in data) {
      const orgRef = asRecord(asRecord(data.asn).orgRef);
      organization = {
        key: orgRef["@handle"] ?? "",
        name: orgRef["@name"] ?? "",
        country: "US"
      };
    } else if ("org" in data) {
      const orgData = asRecord(data.org);
      organization = {
        key: dollarString(orgData.handle),
        name: dollarString(orgData.name),
        country: "US"
      };
    }

    const source = "net" in data ? asRecord(data.net) : "asn" in data ? asRecord(data.asn) : asRecord(data.org);
    let pocLinks = extractPocLinks(source);
    if (pocLinks.length === 0) {
      pocLinks = await getOrgPocLinks(deps, organization.key);
    }

    let abuseContact: Record<string, unknown> | null = null;
    const adminContacts: Record<string, unknown>[] = [];
    const techContacts: Record<string, unknown>[] = [];
    const nocContacts: Record<string, unknown>[] = [];

    for (const pocLink of pocLinks) {
      const details = await getPocDetails(deps, pocLink.handle);
      if (!details) {
        continue;
      }

      if (isAbusePoc(pocLink)) {
        abuseContact = details;
      } else if (isAdminPoc(pocLink)) {
        adminContacts.push(details);
      } else if (isTechPoc(pocLink)) {
        techContacts.push(details);
      } else if (isNocPoc(pocLink)) {
        nocContacts.push(details);
      }
    }

    const result: ToolResult<ArinContactData> = {
      ok: true,
      data: {
        query: { type: queryType, value: queryValue },
        organization,
        abuse: abuseContact,
        admin_contacts: adminContacts,
        tech_contacts: techContacts,
        noc_contacts: nocContacts
      }
    };
    cache.set(cacheKey, result);
    return result;
  } catch (error) {
    return {
      ok: false,
      error: "lookup_error",
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

export function registerArinContactTool(server: McpServer, deps: ToolDependencies): void {
  server.registerTool(
    "arin_contact_card",
    {
      description:
        "PREFERRED TOOL for retrieving contact information (abuse, NOC, admin, tech) for IP addresses, ASNs, or organizations from the ARIN database.",
      inputSchema: {
        ip: z.string().nullable().optional().describe("IP address to look up contact information for in ARIN database (IPv4 or IPv6)"),
        asn: z.number().int().nullable().optional().describe("ASN number to look up contact information for in ARIN database (without 'AS' prefix)"),
        org: z.string().nullable().optional().describe("Organization handle/key to look up contact information for directly")
      }
    },
    async (args) => toMcpResult(await handleArinContact(args, deps))
  );
}
