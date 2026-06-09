import { describe, expect, it } from "vitest";

import { AFRINIC_RDAP_BASE, APNIC_RDAP_BASE, LACNIC_RDAP_BASE, RIRS } from "../src/config.js";
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

  it("uses raw WHOIS abuse headers when AfriNIC RDAP omits an abuse entity", async () => {
    RIRS.afrinic.enabled = true;
    const deps = fakeDeps();
    deps.httpClient.set(`${AFRINIC_RDAP_BASE}/ip/196.216.2.1/32`, {
      objectClassName: "ip network",
      name: "ORG-AFNC1-AFRINIC",
      country: "ZA",
      handle: "196.216.2.0 - 196.216.3.255",
      entities: [
        {
          handle: "IT7-AFRINIC",
          roles: ["technical"],
          vcardArray: ["vcard", [["fn", {}, "text", "Infrastructure Team"], ["email", {}, "text", "sysadmin@afrinic.net"]]]
        }
      ]
    });
    deps.whoisClient.response =
      "% Abuse contact for '196.216.2.0 - 196.216.3.255' is 'abuse@afrinic.net'\n" +
      "mnt-irt:        IRT-AFRINIC-IT\n";

    const result = await handleRdapContact(RIRS.afrinic, { ip: "196.216.2.1" }, deps);

    expect(result).toMatchObject({
      ok: true,
      data: {
        abuse: {
          handle: "IRT-AFRINIC-IT",
          emails: ["abuse@afrinic.net"]
        },
        tech_contacts: [
          {
            handle: "IT7-AFRINIC",
            emails: ["sysadmin@afrinic.net"]
          }
        ]
      }
    });
  });

  it("walks nested LACNIC RDAP entities and fills filtered abuse emails from WHOIS", async () => {
    RIRS.lacnic.enabled = true;
    const deps = fakeDeps();
    deps.httpClient.set(`${LACNIC_RDAP_BASE}/ip/200.160.0.1/32`, {
      objectClassName: "ip network",
      name: "22817",
      country: "BR",
      handle: "200.160.0.0/20",
      entities: [
        {
          handle: "05506560000136",
          roles: ["registrant"],
          vcardArray: ["vcard", [["fn", {}, "text", "NIC.BR"]]],
          entities: [
            {
              handle: "FAN",
              roles: ["administrative"],
              vcardArray: ["vcard", [["fn", {}, "text", "Frederico Augusto de Carvalho Neves"]]]
            }
          ]
        },
        {
          handle: "FAN",
          roles: ["technical", "abuse"],
          vcardArray: ["vcard", [["fn", {}, "text", "Frederico Augusto de Carvalho Neves"]]]
        }
      ]
    });
    deps.whoisClient.response =
      "abuse-c:     FAN\n" +
      "% Security and mail abuse issues should also be addressed to cert.br,\n" +
      "% respectivelly to cert@cert.br and mail-abuse@cert.br\n";

    const result = await handleRdapContact(RIRS.lacnic, { ip: "200.160.0.1" }, deps);

    expect(result).toMatchObject({
      ok: true,
      data: {
        abuse: {
          handle: "FAN",
          emails: ["cert@cert.br", "mail-abuse@cert.br"]
        },
        admin_contacts: [
          {
            handle: "FAN",
            name: "Frederico Augusto de Carvalho Neves"
          }
        ],
        tech_contacts: [
          {
            handle: "FAN",
            name: "Frederico Augusto de Carvalho Neves"
          }
        ]
      }
    });
  });
});
