import { describe, expect, it } from "vitest";

import { envBool, envInt, envStr } from "../src/config.js";

describe("env helpers", () => {
  it("parses strings, integers, booleans, and fallbacks like the Python config", () => {
    process.env.TEST_WHOIS_STR = "value";
    process.env.TEST_WHOIS_INT = "42";
    process.env.TEST_WHOIS_BAD_INT = "nope";
    process.env.TEST_WHOIS_TRUE = "yes";
    process.env.TEST_WHOIS_FALSE = "off";

    expect(envStr("TEST_WHOIS_STR", "default")).toBe("value");
    expect(envStr("TEST_WHOIS_MISSING_STR", "default")).toBe("default");
    expect(envInt("TEST_WHOIS_INT", 10)).toBe(42);
    expect(envInt("TEST_WHOIS_BAD_INT", 10)).toBe(10);
    expect(envBool("TEST_WHOIS_TRUE", false)).toBe(true);
    expect(envBool("TEST_WHOIS_FALSE", true)).toBe(false);
    expect(envBool("TEST_WHOIS_MISSING_BOOL", true)).toBe(true);
  });
});
