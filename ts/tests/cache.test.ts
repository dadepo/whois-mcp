import { describe, expect, it, vi } from "vitest";

import { TTLCache } from "../src/cache.js";

describe("TTLCache", () => {
  it("returns cached values and evicts least recently used items", () => {
    const cache = new TTLCache<string, string>({ maxItems: 2, ttlSeconds: 60 });
    cache.set("a", "1");
    cache.set("b", "2");
    expect(cache.get("a")).toBe("1");

    cache.set("c", "3");

    expect(cache.get("b")).toBeUndefined();
    expect(cache.get("a")).toBe("1");
    expect(cache.get("c")).toBe("3");
  });

  it("expires values after the TTL", () => {
    vi.useFakeTimers();
    try {
      const cache = new TTLCache<string, string>({ maxItems: 2, ttlSeconds: 1 });
      cache.set("a", "1");
      vi.advanceTimersByTime(1001);
      expect(cache.get("a")).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
