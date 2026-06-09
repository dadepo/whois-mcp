import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import { TTLCache } from "../cache.js";
import type { RirConfig } from "../config.js";
import type { ToolDependencies } from "../deps.js";
import { asArray, asRecord, stringValue } from "../lib/object.js";
import { toMcpResult, type ToolResult } from "../types.js";

export interface ContactArgs {
  ip?: string | null | undefined;
  asn?: number | null | undefined;
  org?: string | null | undefined;
}

interface RdapContact {
  name: unknown;
  emails: unknown[];
  phones: unknown[];
  address: unknown;
  handle?: unknown;
}

interface RdapContactData {
  query: {
    type: string;
    value: string | null | undefined;
  };
  organization: {
    name: unknown;
    country: unknown;
    handle: unknown;
  };
  abuse: RdapContact | null;
  admin_contacts: RdapContact[];
  tech_contacts: RdapContact[];
  registrant: RdapContact | null;
}

const contactCache = new TTLCache<string, ToolResult<RdapContactData>>({
  maxItems: 500,
  ttlSeconds: 600
});

const labels: Record<string, string> = {
  apnic: "APNIC",
  afrinic: "AfriNIC",
  lacnic: "LACNIC"
};

function parseVcard(vcardArray: unknown): RdapContact {
  const contact: RdapContact = {
    name: null,
    emails: [],
    phones: [],
    address: null
  };

  const vcard = asArray(vcardArray);
  const properties = asArray(vcard[1]);

  for (const rawProp of properties) {
    const prop = asArray(rawProp);
    if (prop.length < 4) {
      continue;
    }

    const propName = String(prop[0] ?? "");
    const propValue = prop[3];
    if (propName === "fn" && propValue) {
      contact.name = propValue;
    } else if (propName === "email" && propValue) {
      contact.emails.push(propValue);
    } else if (propName === "tel" && propValue) {
      contact.phones.push(propValue);
    } else if (propName === "adr") {
      const params = asRecord(prop[1]);
      if ("label" in params) {
        contact.address = params.label;
      }
    }
  }

  contact.emails = uniqueValues(contact.emails);
  contact.phones = uniqueValues(contact.phones);
  return contact;
}

function uniqueValues(values: unknown[]): unknown[] {
  return [...new Set(values.filter(Boolean))];
}

function* rdapEntities(rawEntities: unknown): Generator<Record<string, unknown>> {
  for (const rawEntity of asArray(rawEntities)) {
    const entity = asRecord(rawEntity);
    yield entity;
    yield* rdapEntities(entity.entities);
  }
}

function hasEmail(contact: RdapContact | null): boolean {
  return contact !== null && contact.emails.length > 0;
}

function extractEmails(text: string): string[] {
  return [...text.matchAll(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)].map((match) => match[0]);
}

function parseWhoisAbuseContact(rpsl: string): { emails: string[]; handle: string | null } {
  const emails: string[] = [];
  let handle: string | null = null;
  let previousLineWasAbuseRelated = false;

  for (const line of rpsl.split(/\r?\n/)) {
    const abuseHeader = line.match(/^%\s*Abuse contact for .* is '([^']+)'/i);
    if (abuseHeader?.[1]) {
      emails.push(abuseHeader[1]);
    }

    const abuseMailbox = line.match(/^abuse-mailbox:\s*(\S+)/i);
    if (abuseMailbox?.[1]) {
      emails.push(abuseMailbox[1]);
    }

    const abuseHandle = line.match(/^abuse-c:\s*(\S+)/i) ?? line.match(/^mnt-irt:\s*(\S+)/i);
    if (abuseHandle?.[1] && !handle) {
      handle = abuseHandle[1];
    }

    const lineIsAbuseRelated = /\b(abuse|security)\b/i.test(line);
    if (lineIsAbuseRelated || previousLineWasAbuseRelated) {
      emails.push(...extractEmails(line));
    }
    previousLineWasAbuseRelated = lineIsAbuseRelated && extractEmails(line).length === 0;
  }

  return {
    emails: uniqueValues(emails) as string[],
    handle
  };
}

async function getWhoisAbuseContact(
  rir: RirConfig,
  queryType: string,
  queryValue: string | null | undefined,
  deps: ToolDependencies
): Promise<RdapContact | null> {
  if (!queryValue || queryType === "org") {
    return null;
  }

  const whoisQuery = queryType === "asn" ? `AS${queryValue}` : queryValue;
  try {
    const rpsl = await deps.whoisClient.query(rir.whois, `${whoisQuery}\r\n`, {
      chunkSize: 8192,
      readTimeoutReturnsPartial: true
    });
    const parsed = parseWhoisAbuseContact(rpsl);
    if (parsed.emails.length === 0 && !parsed.handle) {
      return null;
    }

    return {
      name: `${rir.label} abuse contact`,
      emails: parsed.emails,
      phones: [],
      address: null,
      handle: parsed.handle
    };
  } catch {
    return null;
  }
}

function mergeAbuseContact(primary: RdapContact | null, fallback: RdapContact | null): RdapContact | null {
  if (!fallback) {
    return primary;
  }
  if (!primary) {
    return fallback;
  }

  return {
    ...primary,
    name: primary.name ?? fallback.name,
    handle: primary.handle ?? fallback.handle,
    emails: uniqueValues([...primary.emails, ...fallback.emails]),
    phones: uniqueValues([...primary.phones, ...fallback.phones]),
    address: primary.address ?? fallback.address
  };
}

export async function handleRdapContact(
  rir: RirConfig,
  args: ContactArgs,
  deps: ToolDependencies
): Promise<ToolResult<RdapContactData>> {
  const label = labels[rir.id] ?? rir.label;
  if (!rir.enabled) {
    return {
      ok: false,
      error: "service_disabled",
      detail: `${label} contact card support is disabled. Set ${rir.supportEnv}=true to enable.`
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
    cacheKey = `${rir.id}:contact_ip:${args.ip}`;
    queryType = "ip";
    queryValue = args.ip;
  } else if (args.asn !== undefined && args.asn !== null) {
    cacheKey = `${rir.id}:contact_asn:${args.asn}`;
    queryType = "asn";
    queryValue = String(args.asn);
  } else {
    cacheKey = `${rir.id}:contact_org:${args.org}`;
    queryType = "org";
    queryValue = args.org;
  }

  const cached = contactCache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }

  try {
    let url: string;
    if (args.ip) {
      const rdapQuery = args.ip.includes("/") ? args.ip : `${args.ip}/${args.ip.includes(":") ? "128" : "32"}`;
      url = `${rir.rdapBase}/ip/${rdapQuery}`;
    } else if (args.asn !== undefined && args.asn !== null) {
      url = `${rir.rdapBase}/autnum/${args.asn}`;
    } else if (args.org) {
      return {
        ok: false,
        error: "not_supported",
        detail: "Direct organization queries are not supported. Please use an IP address or ASN instead."
      };
    } else {
      return {
        ok: false,
        error: "bad_request",
        detail: "Internal error: no valid query parameter"
      };
    }

    const data = asRecord(await deps.httpClient.getJson(url, { notFoundValue: {} }));
    if (Object.keys(data).length === 0 || !("objectClassName" in data)) {
      const result: ToolResult<RdapContactData> = {
        ok: false,
        error: "not_found",
        detail: `No records found for ${queryType}='${queryValue}'`
      };
      contactCache.set(cacheKey, result);
      return result;
    }

    const orgName = data.name ?? "Unknown";
    const country = data.country ?? "Unknown";
    let handle: unknown = data.handle ?? "";
    let abuseContact: RdapContact | null = null;
    const adminContacts: RdapContact[] = [];
    const techContacts: RdapContact[] = [];
    let registrantContact: RdapContact | null = null;

    for (const entity of rdapEntities(data.entities)) {
      const roles = asArray(entity.roles).map((role) => stringValue(role));
      handle = entity.handle ?? "";
      const vcard = entity.vcardArray;
      if (!vcard) {
        continue;
      }

      const contact = parseVcard(vcard);
      contact.handle = handle;

      if (roles.includes("abuse")) {
        abuseContact = contact;
      }
      if (roles.includes("administrative")) {
        adminContacts.push(contact);
      }
      if (roles.includes("technical")) {
        techContacts.push(contact);
      }
      if (roles.includes("registrant")) {
        registrantContact = contact;
      }
    }

    const whoisAbuseContact = await getWhoisAbuseContact(rir, queryType, queryValue, deps);
    if (whoisAbuseContact && (!hasEmail(abuseContact) || whoisAbuseContact.emails.length > 0)) {
      abuseContact = mergeAbuseContact(abuseContact, whoisAbuseContact);
    }

    const result: ToolResult<RdapContactData> = {
      ok: true,
      data: {
        query: {
          type: queryType,
          value: queryValue
        },
        organization: {
          name: orgName,
          country,
          handle
        },
        abuse: abuseContact,
        admin_contacts: adminContacts,
        tech_contacts: techContacts,
        registrant: registrantContact
      }
    };
    contactCache.set(cacheKey, result);
    return result;
  } catch (error) {
    return {
      ok: false,
      error: "lookup_error",
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

export function registerRdapContactTool(server: McpServer, rir: RirConfig, deps: ToolDependencies): void {
  const label = labels[rir.id] ?? rir.label;
  server.registerTool(
    `${rir.id}_contact_card`,
    {
      description: `PREFERRED TOOL for retrieving contact information (abuse, NOC, admin, tech) for IP addresses, ASNs, or organizations from the ${label} database.`,
      inputSchema: {
        ip: z.string().nullable().optional().describe(`IP address to look up contact information for in ${label} database (IPv4 or IPv6)`),
        asn: z.number().int().nullable().optional().describe(`ASN number to look up contact information for in ${label} database (without 'AS' prefix)`),
        org: z.string().nullable().optional().describe("Organization handle/key to look up contact information for directly")
      }
    },
    async (args) => toMcpResult(await handleRdapContact(rir, args, deps))
  );
}
