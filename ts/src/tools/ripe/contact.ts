import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

import { TTLCache } from "../../cache.js";
import { RIRS } from "../../config.js";
import type { ToolDependencies } from "../../deps.js";
import { ripeAttrs, ripeObjects } from "../../lib/ripe-object.js";
import { toMcpResult, type ToolResult } from "../../types.js";
import type { ContactArgs } from "../rdap-contact.js";

interface RipeContactData {
  query: { type: string; value: string | null | undefined };
  organization: {
    key: string | null | undefined;
    name: unknown;
    country: unknown;
    remarks: string[];
  };
  abuse: unknown;
  admin_contacts: unknown[];
  tech_contacts: unknown[];
}

const cache = new TTLCache<string, ToolResult<RipeContactData>>({
  maxItems: 500,
  ttlSeconds: 600
});

async function getRipeJson(deps: ToolDependencies, url: string): Promise<unknown> {
  return deps.httpClient.getJson(url, { notFoundValue: { objects: { object: [] } } });
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

async function getRipeObject(deps: ToolDependencies, handle: string, preferredType: "person" | "role"): Promise<unknown | null> {
  const objectTypes = preferredType === "person" ? ["person", "role"] : ["role", "person"];
  for (const objectType of objectTypes) {
    const objects = ripeObjects(await getRipeJson(deps, `${RIRS.ripe.restBase}/ripe/${objectType}/${handle}.json`));
    if (objects.length > 0) {
      return objects[0];
    }
  }

  return null;
}

export async function handleRipeContact(args: ContactArgs, deps: ToolDependencies): Promise<ToolResult<RipeContactData>> {
  const rir = RIRS.ripe;
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
    cacheKey = `contact_ip:${args.ip}`;
    queryType = "ip";
    queryValue = args.ip;
  } else if (args.asn !== undefined && args.asn !== null) {
    cacheKey = `contact_asn:${args.asn}`;
    queryType = "asn";
    queryValue = String(args.asn);
  } else {
    cacheKey = `contact_org:${args.org}`;
    queryType = "org";
    queryValue = args.org;
  }

  const cached = cache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }

  try {
    let orgKey = args.org;
    if (!orgKey) {
      const data =
        args.ip !== undefined && args.ip !== null
          ? await getRipeJson(
              deps,
              `${rir.restBase}/search.json?query-string=${args.ip}&type-filter=inetnum&type-filter=inet6num`
            )
          : await getRipeJson(deps, `${rir.restBase}/ripe/aut-num/AS${args.asn}.json`);

      const objects = ripeObjects(data);
      if (objects.length === 0) {
        const result: ToolResult<RipeContactData> = {
          ok: false,
          error: "not_found",
          detail: `No records found for ${queryType}='${queryValue}'`
        };
        cache.set(cacheKey, result);
        return result;
      }

      for (const obj of objects) {
        const orgRefs = ripeAttrs(obj, "org");
        const organisationRefs = orgRefs.length > 0 ? orgRefs : ripeAttrs(obj, "organisation");
        if (organisationRefs.length > 0) {
          orgKey = organisationRefs[0];
          break;
        }
      }

      if (!orgKey) {
        const result: ToolResult<RipeContactData> = {
          ok: false,
          error: "no_organisation",
          detail: `No organization found for ${queryType}='${queryValue}'`
        };
        cache.set(cacheKey, result);
        return result;
      }
    }

    const orgObjects = ripeObjects(await getRipeJson(deps, `${rir.restBase}/ripe/organisation/${orgKey}.json`));
    if (orgObjects.length === 0) {
      const result: ToolResult<RipeContactData> = {
        ok: false,
        error: "org_not_found",
        detail: `Organization '${orgKey}' not found`
      };
      cache.set(cacheKey, result);
      return result;
    }

    const orgObj = orgObjects[0];
    const orgName = ripeAttrs(orgObj, "org-name")[0] ?? null;
    const country = ripeAttrs(orgObj, "country")[0] ?? null;
    const remarks = ripeAttrs(orgObj, "remarks");
    const abuseC = ripeAttrs(orgObj, "abuse-c")[0] ?? null;
    let abuseInfo: unknown = null;

    if (abuseC) {
      try {
        const abuseObj = await getRipeObject(deps, abuseC, "role");
        if (abuseObj) {
          abuseInfo = {
            handle: abuseC,
            role: ripeAttrs(abuseObj, "role")[0] ?? null,
            emails: uniqueStrings([...ripeAttrs(abuseObj, "e-mail"), ...ripeAttrs(abuseObj, "abuse-mailbox")]),
            phones: ripeAttrs(abuseObj, "phone"),
            remarks: ripeAttrs(abuseObj, "remarks")
          };
        }
      } catch {
        abuseInfo = null;
      }
    }

    const adminContacts: unknown[] = [];
    const techContacts: unknown[] = [];
    for (const [contactType, target] of [
      ["admin-c", adminContacts],
      ["tech-c", techContacts]
    ] as const) {
      for (const handle of ripeAttrs(orgObj, contactType)) {
        try {
          const contactObj = await getRipeObject(deps, handle, "person");
          if (contactObj) {
            target.push({
              handle,
              person: ripeAttrs(contactObj, "person")[0] ?? null,
              role: ripeAttrs(contactObj, "role")[0] ?? null,
              emails: uniqueStrings([...ripeAttrs(contactObj, "e-mail"), ...ripeAttrs(contactObj, "abuse-mailbox")]),
              phones: ripeAttrs(contactObj, "phone"),
              remarks: ripeAttrs(contactObj, "remarks")
            });
          }
        } catch {
          // Match Python behavior: ignore individual contact lookup failures.
        }
      }
    }

    const result: ToolResult<RipeContactData> = {
      ok: true,
      data: {
        query: { type: queryType, value: queryValue },
        organization: {
          key: orgKey,
          name: orgName,
          country,
          remarks
        },
        abuse: abuseInfo,
        admin_contacts: adminContacts,
        tech_contacts: techContacts
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

export function registerRipeContactTool(server: McpServer, deps: ToolDependencies): void {
  server.registerTool(
    "ripe_contact_card",
    {
      description:
        "PREFERRED TOOL for retrieving contact information (abuse, NOC, admin, tech) for IP addresses, ASNs, or organizations from the RIPE NCC database.",
      inputSchema: {
        ip: z.string().nullable().optional().describe("IP address to look up contact information for in RIPE database (IPv4 or IPv6)"),
        asn: z.number().int().nullable().optional().describe("ASN number to look up contact information for in RIPE database (without 'AS' prefix)"),
        org: z.string().nullable().optional().describe("Organization handle/key to look up contact information for directly")
      }
    },
    async (args) => toMcpResult(await handleRipeContact(args, deps))
  );
}
