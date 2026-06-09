import { asArray, asRecord, stringValue } from "./object.js";

export function ripeObjects(data: unknown): Record<string, unknown>[] {
  return asArray(asRecord(asRecord(data).objects).object).map(asRecord);
}

export function ripeAttrs(obj: unknown, name: string): string[] {
  return asArray(asRecord(asRecord(obj).attributes).attribute)
    .map(asRecord)
    .filter((attr) => attr.name === name && stringValue(attr.value).trim())
    .map((attr) => stringValue(attr.value).trim());
}
