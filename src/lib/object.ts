export function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function getPath(value: unknown, path: string[]): unknown {
  let cursor: unknown = value;
  for (const segment of path) {
    cursor = asRecord(cursor)[segment];
  }
  return cursor;
}

export function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

export function dollarString(value: unknown): string {
  return stringValue(asRecord(value)["$"]);
}

export function normalizeList<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) {
    return [];
  }

  return Array.isArray(value) ? value : [value];
}
