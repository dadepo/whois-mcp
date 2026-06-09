import { describe, expect, it } from "vitest";

import { RIRS } from "../src/config.js";
import { WhoisTimeoutError } from "../src/lib/whois-client.js";
import { handleWhoisQuery } from "../src/tools/whois.js";
import { fakeDeps } from "./helpers.js";

describe("WHOIS tools", () => {
  it("serializes flags and query to the TCP WHOIS client and returns the Python result shape", async () => {
    const deps = fakeDeps();
    deps.whoisClient.response = "route: 192.0.2.0/24\n";

    const result = await handleWhoisQuery(RIRS.ripe, { query: "AS64496", flags: ["-r"] }, deps);

    expect(result.ok).toBe(true);
    expect(result).toMatchObject({
      ok: true,
      data: {
        rpsl: "route: 192.0.2.0/24\n",
        server: "whois.ripe.net"
      }
    });
    expect(deps.whoisClient.calls[0]?.line).toBe("-r AS64496\r\n");
    expect(deps.whoisClient.calls[0]?.options).toEqual({
      chunkSize: 65536,
      readTimeoutReturnsPartial: false
    });
  });

  it("keeps non-RIPE read timeout behavior as partial success at the client option boundary", async () => {
    const deps = fakeDeps();
    await handleWhoisQuery(RIRS.apnic, { query: "AS4608" }, deps);
    expect(deps.whoisClient.calls[0]?.options).toEqual({
      chunkSize: 8192,
      readTimeoutReturnsPartial: true
    });
  });

  it("maps WHOIS timeout errors to timeout_error", async () => {
    const deps = fakeDeps();
    deps.whoisClient.response = new WhoisTimeoutError("connect");

    await expect(handleWhoisQuery(RIRS.ripe, { query: "AS64496" }, deps)).resolves.toEqual({
      ok: false,
      error: "timeout_error",
      detail: "Connection or read timeout"
    });
  });
});
