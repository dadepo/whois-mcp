import { describe, expect, it } from "vitest";

import { registeredToolNames } from "../src/register.js";

describe("registeredToolNames", () => {
  it("matches the current Python registration matrix", () => {
    expect(
      registeredToolNames({
        ripe: true,
        arin: true,
        apnic: true,
        afrinic: true,
        lacnic: true
      })
    ).toEqual([
      "ripe_whois_query",
      "ripe_expand_as_set",
      "ripe_validate_route_object",
      "ripe_contact_card",
      "arin_whois_query",
      "arin_validate_route_object",
      "arin_expand_as_set",
      "arin_contact_card",
      "apnic_whois_query",
      "apnic_contact_card",
      "afrinic_whois_query",
      "afrinic_contact_card",
      "lacnic_whois_query",
      "lacnic_contact_card"
    ]);
  });

  it("omits tools for disabled RIRs", () => {
    expect(
      registeredToolNames({
        ripe: false,
        arin: true,
        apnic: false,
        afrinic: false,
        lacnic: false
      })
    ).toEqual(["arin_whois_query", "arin_validate_route_object", "arin_expand_as_set", "arin_contact_card"]);
  });
});
