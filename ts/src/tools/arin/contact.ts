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

async function getJson(deps: ToolDependencies, url: string): Promise<Record<string, unknown>> {
  return asRecord(await deps.httpClient.getJson(url, { notFoundValue: {}, headers: { Accept: "application/json" } }));
}

async function getPocDetails(deps: ToolDependencies, pocHandle: string): Promise<Record<string, unknown> | null> {
  try {
    const pocData = await getJson(deps, `${ARIN_REST_BASE}/poc/${pocHandle}`);
    if (Object.keys(pocData).length === 0) {
      return null;
    }

    const poc = asRecord(pocData.poc);
    const emailValue = asRecord(asRecord(poc.emails).email);
    const emails =
      Array.isArray(asRecord(poc.emails).email)
        ? asArray(asRecord(poc.emails).email)
            .map((email) => dollarString(email))
            .filter(Boolean)
        : dollarString(emailValue)
          ? [dollarString(emailValue)]
          : [];

    const phoneValue = asRecord(asRecord(poc.phones).phone);
    const phones =
      Array.isArray(asRecord(poc.phones).phone)
        ? asArray(asRecord(poc.phones).phone)
            .map((phone) => dollarString(phone))
            .filter(Boolean)
        : dollarString(phoneValue)
          ? [dollarString(phoneValue)]
          : [];

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
    const rawPocRefs = asRecord(source.pocLinks).pocLinkRef as Record<string, unknown> | Record<string, unknown>[] | undefined;
    const pocRefs = normalizeList(rawPocRefs);
    const pocLinks = pocRefs
      .map((rawPocRef) => {
        const pocRef = asRecord(rawPocRef);
        return {
          handle: String(pocRef["@handle"] ?? ""),
          function: String(pocRef["@function"] ?? "")
        };
      })
      .filter((pocLink) => pocLink.handle);

    let abuseContact: Record<string, unknown> | null = null;
    const adminContacts: Record<string, unknown>[] = [];
    const techContacts: Record<string, unknown>[] = [];
    const nocContacts: Record<string, unknown>[] = [];

    for (const pocLink of pocLinks) {
      const details = await getPocDetails(deps, pocLink.handle);
      if (!details) {
        continue;
      }

      const func = pocLink.function.toLowerCase();
      if (func.includes("abuse")) {
        abuseContact = details;
      } else if (func.includes("admin") || func.includes("administrative")) {
        adminContacts.push(details);
      } else if (func.includes("tech") || func.includes("technical")) {
        techContacts.push(details);
      } else if (func.includes("noc")) {
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
