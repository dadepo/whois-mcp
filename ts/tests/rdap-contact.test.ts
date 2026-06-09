import { describe, expect, it } from "vitest";

import { APNIC_RDAP_BASE, RIRS } from "../src/config.js";
import { handleRdapContact } from "../src/tools/rdap-contact.js";
import { fakeDeps } from "./helpers.js";
import rdapApnic from "./fixtures/rdap-apnic-ip.json" with { type: "json" };

describe("RDAP contact tools", () => {
  it("parses APNIC-style RDAP vCards and categorizes roles", async () => {
    const deps = fakeDeps();
    deps.httpClient.set(`${APNIC_RDAP_BASE}/ip/1.1.1.1/32`, rdapApnic);

    const result = await handleRdapContact(RIRS.apnic, { ip: "1.1.1.1" }, deps);

    expect(result).toEqual({
      ok: true,
      data: {
        query: { type: "ip", value: "1.1.1.1" },
        organization: {
          name: "Example APNIC Network",
          country: "AU",
          handle: "TECH1-AP"
        },
        abuse: {
          name: "Example Abuse",
          emails: ["abuse@example.net"],
          phones: ["+61-1-1111"],
          address: "1 Example Street",
          handle: "ABUSE1-AP"
        },
        admin_contacts: [
          {
            name: "Example Tech",
            emails: ["tech@example.net"],
            phones: [],
            address: null,
            handle: "TECH1-AP"
          }
        ],
        tech_contacts: [
          {
            name: "Example Tech",
            emails: ["tech@example.net"],
            phones: [],
            address: null,
            handle: "TECH1-AP"
          }
        ],
        registrant: null
      }
    });
  });

  it("rejects direct organization lookup for RDAP-only providers", async () => {
    await expect(handleRdapContact(RIRS.lacnic, { org: "ORG" }, fakeDeps())).resolves.toEqual({
      ok: false,
      error: "not_supported",
      detail: "Direct organization queries are not supported. Please use an IP address or ASN instead."
    });
  });
});
