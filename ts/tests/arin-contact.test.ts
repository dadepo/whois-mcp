import { describe, expect, it } from "vitest";

import { ARIN_REST_BASE, RIRS } from "../src/config.js";
import { handleArinContact } from "../src/tools/arin/contact.js";
import { fakeDeps } from "./helpers.js";
import arinNet from "./fixtures/arin-net.json" with { type: "json" };
import arinPocAbuse from "./fixtures/arin-poc-abuse.json" with { type: "json" };
import arinPocNoc from "./fixtures/arin-poc-noc.json" with { type: "json" };
import arinPocTech from "./fixtures/arin-poc-tech.json" with { type: "json" };

describe("ARIN contact tool", () => {
  it("parses ARIN org refs and POC links", async () => {
    RIRS.arin.enabled = true;
    const deps = fakeDeps();
    deps.httpClient.set(`${ARIN_REST_BASE}/ip/8.8.8.8`, arinNet);
    deps.httpClient.set(`${ARIN_REST_BASE}/poc/ABUSE-ARIN`, arinPocAbuse);
    deps.httpClient.set(`${ARIN_REST_BASE}/poc/TECH-ARIN`, arinPocTech);
    deps.httpClient.set(`${ARIN_REST_BASE}/poc/NOC-ARIN`, arinPocNoc);

    const result = await handleArinContact({ ip: "8.8.8.8" }, deps);

    expect(result).toEqual({
      ok: true,
      data: {
        query: { type: "ip", value: "8.8.8.8" },
        organization: {
          key: "EXAMPLE",
          name: "Example ARIN Org",
          country: "US"
        },
        abuse: {
          handle: "ABUSE-ARIN",
          name: "ARIN Abuse",
          emails: ["abuse@example.com"],
          phones: ["+1-555-0000"],
          type: "Role"
        },
        admin_contacts: [],
        tech_contacts: [
          {
            handle: "TECH-ARIN",
            name: "ARIN Tech",
            emails: ["tech1@example.com", "tech2@example.com"],
            phones: ["+1-555-1000"],
            type: "Role"
          }
        ],
        noc_contacts: [
          {
            handle: "NOC-ARIN",
            name: "ARIN NOC",
            emails: ["noc@example.com"],
            phones: [],
            type: "Role"
          }
        ]
      }
    });
  });
});
