import { describe, expect, it } from "vitest";

import { envBool, envInt, envIntWithFallback, envStr } from "../src/config.js";

describe("env helpers", () => {
  it("parses strings, integers, booleans, and fallbacks like the Python config", () => {
    process.env.TEST_CONFIG_STR = "value";
    process.env.TEST_CONFIG_INT = "42";
    process.env.TEST_CONFIG_BAD_INT = "nope";
    process.env.TEST_CONFIG_TRUE = "yes";
    process.env.TEST_CONFIG_FALSE = "off";
    process.env.TEST_CONFIG_LEGACY_INT = "7";

    expect(envStr("TEST_CONFIG_STR", "default")).toBe("value");
    expect(envStr("TEST_CONFIG_MISSING_STR", "default")).toBe("default");
    expect(envInt("TEST_CONFIG_INT", 10)).toBe(42);
    expect(envInt("TEST_CONFIG_BAD_INT", 10)).toBe(10);
    expect(envIntWithFallback("TEST_CONFIG_MISSING_INT", "TEST_CONFIG_LEGACY_INT", 10)).toBe(7);
    expect(envBool("TEST_CONFIG_TRUE", false)).toBe(true);
    expect(envBool("TEST_CONFIG_FALSE", true)).toBe(false);
    expect(envBool("TEST_CONFIG_MISSING_BOOL", true)).toBe(true);
  });
});
