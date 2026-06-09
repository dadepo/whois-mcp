export class TTLCache<K, V> {
  private readonly maxItems: number;
  private readonly ttlMs: number;
  private readonly data = new Map<K, { timestamp: number; value: V }>();

  constructor(options: { maxItems?: number; ttlSeconds?: number } = {}) {
    this.maxItems = options.maxItems ?? 512;
    this.ttlMs = (options.ttlSeconds ?? 60) * 1000;
  }

  get(key: K): V | undefined {
    const item = this.data.get(key);
    if (!item) {
      return undefined;
    }

    if (performance.now() - item.timestamp > this.ttlMs) {
      this.data.delete(key);
      return undefined;
    }

    this.data.delete(key);
    this.data.set(key, item);
    return item.value;
  }

  set(key: K, value: V): void {
    if (this.data.has(key)) {
      this.data.delete(key);
    }

    this.data.set(key, { timestamp: performance.now(), value });

    if (this.data.size > this.maxItems) {
      const firstKey = this.data.keys().next().value as K | undefined;
      if (firstKey !== undefined) {
        this.data.delete(firstKey);
      }
    }
  }

  clear(): void {
    this.data.clear();
  }

  has(key: K): boolean {
    return this.get(key) !== undefined;
  }

  get size(): number {
    return this.data.size;
  }
}
