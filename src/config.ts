import dotenv from "dotenv";

dotenv.config({ path: ".env", quiet: true });

export function envStr(key: string, defaultValue: string): string {
  return process.env[key] ?? defaultValue;
}

export function envInt(key: string, defaultValue: number): number {
  const raw = process.env[key] ?? String(defaultValue);
  const parsed = Number.parseInt(raw, 10);
  return Number.isNaN(parsed) ? defaultValue : parsed;
}

export function envBool(key: string, defaultValue: boolean): boolean {
  const raw = (process.env[key] ?? "").toLowerCase().trim();
  if (!raw) {
    return defaultValue;
  }

  return ["true", "1", "yes", "on"].includes(raw);
}

export type RirId = "ripe" | "arin" | "apnic" | "afrinic" | "lacnic";

export interface WhoisEndpoint {
  server: string;
  port: number;
}

export interface RirConfig {
  id: RirId;
  label: string;
  supportEnv: string;
  enabled: boolean;
  whois: WhoisEndpoint;
  restBase?: string;
  rdapBase?: string;
}

export const SUPPORT_RIPE = envBool("SUPPORT_RIPE", true);
export const SUPPORT_ARIN = envBool("SUPPORT_ARIN", true);
export const SUPPORT_APNIC = envBool("SUPPORT_APNIC", true);
export const SUPPORT_AFRINIC = envBool("SUPPORT_AFRINIC", true);
export const SUPPORT_LACNIC = envBool("SUPPORT_LACNIC", true);

export const RIPE_WHOIS_SERVER = "whois.ripe.net";
export const RIPE_WHOIS_PORT = 43;
export const RIPE_REST_BASE = "https://rest.db.ripe.net";
export const RIPE_RDAP_BASE = "https://rdap.db.ripe.net";

export const ARIN_WHOIS_SERVER = "whois.arin.net";
export const ARIN_WHOIS_PORT = 43;
export const ARIN_REST_BASE = "https://whois.arin.net/rest";
export const ARIN_RDAP_BASE = "https://rdap.arin.net/registry";

export const APNIC_WHOIS_SERVER = "whois.apnic.net";
export const APNIC_WHOIS_PORT = 43;
export const APNIC_REST_BASE = "https://registry-api.apnic.net/v1";
export const APNIC_RDAP_BASE = "https://rdap.apnic.net";

export const AFRINIC_WHOIS_SERVER = "whois.afrinic.net";
export const AFRINIC_WHOIS_PORT = 43;
export const AFRINIC_RDAP_BASE = "https://rdap.afrinic.net/rdap";

export const LACNIC_WHOIS_SERVER = "whois.lacnic.net";
export const LACNIC_WHOIS_PORT = 43;
export const LACNIC_RDAP_BASE = "https://rdap.lacnic.net/rdap";

export const HTTP_TIMEOUT_SECONDS = envInt("HTTP_TIMEOUT_SECONDS", 10);
export const WHOIS_CONNECT_TIMEOUT_SECONDS = envInt("WHOIS_CONNECT_TIMEOUT_SECONDS", 5);
export const WHOIS_READ_TIMEOUT_SECONDS = envInt("WHOIS_READ_TIMEOUT_SECONDS", 5);
export const CACHE_TTL_SECONDS = envInt("CACHE_TTL_SECONDS", 60);
export const CACHE_MAX_ITEMS = envInt("CACHE_MAX_ITEMS", 512);
export const USER_AGENT = envStr("USER_AGENT", "inet-registry-mcp/1.0");

export const HTTP_HOST = envStr("HTTP_HOST", "127.0.0.1");
export const HTTP_PORT = envInt("HTTP_PORT", 8000);

export const RIRS: Record<RirId, RirConfig> = {
  ripe: {
    id: "ripe",
    label: "RIPE",
    supportEnv: "SUPPORT_RIPE",
    enabled: SUPPORT_RIPE,
    whois: { server: RIPE_WHOIS_SERVER, port: RIPE_WHOIS_PORT },
    restBase: RIPE_REST_BASE,
    rdapBase: RIPE_RDAP_BASE
  },
  arin: {
    id: "arin",
    label: "ARIN",
    supportEnv: "SUPPORT_ARIN",
    enabled: SUPPORT_ARIN,
    whois: { server: ARIN_WHOIS_SERVER, port: ARIN_WHOIS_PORT },
    restBase: ARIN_REST_BASE,
    rdapBase: ARIN_RDAP_BASE
  },
  apnic: {
    id: "apnic",
    label: "APNIC",
    supportEnv: "SUPPORT_APNIC",
    enabled: SUPPORT_APNIC,
    whois: { server: APNIC_WHOIS_SERVER, port: APNIC_WHOIS_PORT },
    restBase: APNIC_REST_BASE,
    rdapBase: APNIC_RDAP_BASE
  },
  afrinic: {
    id: "afrinic",
    label: "AfriNIC",
    supportEnv: "SUPPORT_AFRINIC",
    enabled: SUPPORT_AFRINIC,
    whois: { server: AFRINIC_WHOIS_SERVER, port: AFRINIC_WHOIS_PORT },
    rdapBase: AFRINIC_RDAP_BASE
  },
  lacnic: {
    id: "lacnic",
    label: "LACNIC",
    supportEnv: "SUPPORT_LACNIC",
    enabled: SUPPORT_LACNIC,
    whois: { server: LACNIC_WHOIS_SERVER, port: LACNIC_WHOIS_PORT },
    rdapBase: LACNIC_RDAP_BASE
  }
};
