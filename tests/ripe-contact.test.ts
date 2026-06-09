import { describe, expect, it } from "vitest";

import { RIPE_REST_BASE } from "../src/config.js";
import { handleRipeContact } from "../src/tools/ripe/contact.js";
import { fakeDeps } from "./helpers.js";

function ripeObject(type: string, attrs: Array<{ name: string; value: string }>): unknown {
  return {
    objects: {
      object: [
        {
          type,
          attributes: {
            attribute: attrs
          }
        }
      ]
    }
  };
}

describe("RIPE contact tool", () => {
  it("extracts abuse-mailbox and resolves role contacts", async () => {
    const deps = fakeDeps();
    deps.httpClient.set(
      `${RIPE_REST_BASE}/ripe/organisation/ORG-TEST-RIPE.json`,
      ripeObject("organisation", [
        { name: "org-name", value: "Example RIPE Org" },
        { name: "country", value: "NL" },
        { name: "abuse-c", value: "OPS4-RIPE" },
        { name: "admin-c", value: "MDIR-RIPE" },
        { name: "tech-c", value: "OPS4-RIPE" }
      ])
    );
    deps.httpClient.set(`${RIPE_REST_BASE}/ripe/person/MDIR-RIPE.json`, { objects: { object: [] } });
    deps.httpClient.set(
      `${RIPE_REST_BASE}/ripe/role/MDIR-RIPE.json`,
      ripeObject("role", [
        { name: "role", value: "Managing Director" },
        { name: "phone", value: "+31 20 535 4444" }
      ])
    );
    deps.httpClient.set(
      `${RIPE_REST_BASE}/ripe/role/OPS4-RIPE.json`,
      ripeObject("role", [
        { name: "role", value: "RIPE NCC Operations" },
        { name: "abuse-mailbox", value: "abuse@ripe.net" },
        { name: "phone", value: "+31 20 535 4444" }
      ])
    );

    const result = await handleRipeContact({ org: "ORG-TEST-RIPE" }, deps);

    expect(result).toMatchObject({
      ok: true,
      data: {
        abuse: {
          handle: "OPS4-RIPE",
          role: "RIPE NCC Operations",
          emails: ["abuse@ripe.net"],
          phones: ["+31 20 535 4444"]
        },
        admin_contacts: [
          {
            handle: "MDIR-RIPE",
            role: "Managing Director",
            phones: ["+31 20 535 4444"]
          }
        ],
        tech_contacts: [
          {
            handle: "OPS4-RIPE",
            role: "RIPE NCC Operations",
            emails: ["abuse@ripe.net"]
          }
        ]
      }
    });
  });
});
