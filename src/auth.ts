import type { RirId } from "./config.js";

export type WhoisMcpProfile = "production" | "test";
export type AuthCapability = "status" | "inventory" | "object_lookup" | "data_quality_audit";

export interface AuthEndpointSet {
  ripeDatabaseRestBase: string;
  arinRegRestBase: string;
  apnicRegistryBase: string;
  lacnicRegistrationBase: string;
}

export interface RirAuthProfile {
  rir: RirId;
  label: string;
  configured_credentials: string[];
  missing_credentials: string[];
  endpoints: Record<string, string>;
  capabilities: Record<AuthCapability, "available" | "missing_credentials" | "not_supported">;
}

export interface AuthConfig {
  profile: WhoisMcpProfile;
  rirs: Record<RirId, RirAuthProfile>;
}

export interface AuthEnv {
  [key: string]: string | undefined;
}

const profileAliases: Record<string, WhoisMcpProfile> = {
  prod: "production",
  production: "production",
  test: "test",
  testing: "test"
};

const defaultEndpoints: Record<WhoisMcpProfile, AuthEndpointSet> = {
  production: {
    ripeDatabaseRestBase: "https://rest.db.ripe.net/ripe",
    arinRegRestBase: "https://reg.arin.net/rest",
    apnicRegistryBase: "https://nir-api.apnic.net",
    lacnicRegistrationBase: ""
  },
  test: {
    ripeDatabaseRestBase: "https://rest-test.db.ripe.net/test",
    arinRegRestBase: "https://reg.ote.arin.net/rest",
    apnicRegistryBase: "https://registry-testbed.apnic.net/nir-api",
    lacnicRegistrationBase: ""
  }
};

export function parseWhoisMcpProfile(rawProfile: string | undefined = process.env.WHOIS_MCP_PROFILE): WhoisMcpProfile {
  const normalized = (rawProfile ?? "production").trim().toLowerCase();
  const profile = profileAliases[normalized];
  if (!profile) {
    throw new Error("WHOIS_MCP_PROFILE must be one of: production, prod, test, testing");
  }
  return profile;
}

export function authEndpoints(profile: WhoisMcpProfile, env: AuthEnv = process.env): AuthEndpointSet {
  const defaults = defaultEndpoints[profile];
  return {
    ripeDatabaseRestBase: endpointOverride(env.RIPE_DATABASE_REST_BASE, defaults.ripeDatabaseRestBase),
    arinRegRestBase: endpointOverride(env.ARIN_REG_REST_BASE, defaults.arinRegRestBase),
    apnicRegistryBase: endpointOverride(env.APNIC_REGISTRY_BASE, defaults.apnicRegistryBase),
    lacnicRegistrationBase: endpointOverride(env.LACNIC_REGISTRATION_BASE, defaults.lacnicRegistrationBase)
  };
}

export function readAuthConfig(env: AuthEnv = process.env): AuthConfig {
  const profile = parseWhoisMcpProfile(env.WHOIS_MCP_PROFILE);
  const endpoints = authEndpoints(profile, env);

  const ripeHasDatabaseKey = hasValue(env.RIPE_API_KEY);
  const arinHasApiKey = hasValue(env.ARIN_API_KEY);
  const apnicHasToken = hasValue(env.APNIC_ACCESS_TOKEN) || (hasValue(env.APNIC_CLIENT_ID) && hasValue(env.APNIC_CLIENT_SECRET));
  const lacnicHasToken = hasValue(env.LACNIC_ACCESS_TOKEN) || (hasValue(env.LACNIC_CLIENT_ID) && hasValue(env.LACNIC_CLIENT_SECRET));

  return {
    profile,
    rirs: {
      ripe: {
        rir: "ripe",
        label: "RIPE NCC",
        configured_credentials: ripeHasDatabaseKey ? ["RIPE_API_KEY"] : [],
        missing_credentials: ripeHasDatabaseKey ? [] : ["RIPE_API_KEY"],
        endpoints: {
          database_rest: endpoints.ripeDatabaseRestBase
        },
        capabilities: {
          status: "available",
          inventory: ripeHasDatabaseKey ? "available" : "missing_credentials",
          object_lookup: ripeHasDatabaseKey ? "available" : "missing_credentials",
          data_quality_audit: ripeHasDatabaseKey ? "available" : "missing_credentials"
        }
      },
      arin: {
        rir: "arin",
        label: "ARIN",
        configured_credentials: arinHasApiKey ? ["ARIN_API_KEY"] : [],
        missing_credentials: arinHasApiKey ? [] : ["ARIN_API_KEY"],
        endpoints: {
          registration_rest: endpoints.arinRegRestBase
        },
        capabilities: {
          status: "available",
          inventory: arinHasApiKey ? "available" : "missing_credentials",
          object_lookup: arinHasApiKey ? "available" : "missing_credentials",
          data_quality_audit: arinHasApiKey ? "available" : "missing_credentials"
        }
      },
      apnic: {
        rir: "apnic",
        label: "APNIC",
        configured_credentials: [
          ...(hasValue(env.APNIC_ACCESS_TOKEN) ? ["APNIC_ACCESS_TOKEN"] : []),
          ...(hasValue(env.APNIC_CLIENT_ID) ? ["APNIC_CLIENT_ID"] : []),
          ...(hasValue(env.APNIC_CLIENT_SECRET) ? ["APNIC_CLIENT_SECRET"] : [])
        ],
        missing_credentials: apnicHasToken ? [] : ["APNIC_ACCESS_TOKEN or APNIC_CLIENT_ID/APNIC_CLIENT_SECRET"],
        endpoints: {
          registry_api: endpoints.apnicRegistryBase
        },
        capabilities: {
          status: "available",
          inventory: "not_supported",
          object_lookup: "not_supported",
          data_quality_audit: "not_supported"
        }
      },
      afrinic: {
        rir: "afrinic",
        label: "AfriNIC",
        configured_credentials: [],
        missing_credentials: [],
        endpoints: {},
        capabilities: {
          status: "available",
          inventory: "not_supported",
          object_lookup: "not_supported",
          data_quality_audit: "not_supported"
        }
      },
      lacnic: {
        rir: "lacnic",
        label: "LACNIC",
        configured_credentials: [
          ...(hasValue(env.LACNIC_ACCESS_TOKEN) ? ["LACNIC_ACCESS_TOKEN"] : []),
          ...(hasValue(env.LACNIC_CLIENT_ID) ? ["LACNIC_CLIENT_ID"] : []),
          ...(hasValue(env.LACNIC_CLIENT_SECRET) ? ["LACNIC_CLIENT_SECRET"] : [])
        ],
        missing_credentials: lacnicHasToken ? [] : ["LACNIC_ACCESS_TOKEN or LACNIC_CLIENT_ID/LACNIC_CLIENT_SECRET"],
        endpoints: {
          registration_api: endpoints.lacnicRegistrationBase
        },
        capabilities: {
          status: "available",
          inventory: "not_supported",
          object_lookup: "not_supported",
          data_quality_audit: "not_supported"
        }
      }
    }
  };
}

export function envList(key: string, env: AuthEnv = process.env): string[] {
  return envStrFrom(env, key, "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

export function secretValue(key: string, env: AuthEnv = process.env): string | null {
  const value = envStrFrom(env, key, "").trim();
  return value ? value : null;
}

export function ripeAuthorizationHeader(env: AuthEnv = process.env): string | null {
  const value = secretValue("RIPE_API_KEY", env);
  if (!value) {
    return null;
  }
  return value.toLowerCase().startsWith("basic ") ? value : `Basic ${value}`;
}

export function arinUrlWithApiKey(baseUrl: string, env: AuthEnv = process.env): string | null {
  const apiKey = secretValue("ARIN_API_KEY", env);
  if (!apiKey) {
    return null;
  }

  const url = new URL(baseUrl);
  url.searchParams.set("apikey", apiKey);
  return url.toString();
}

export function redactUrlSecrets(url: string): string {
  const parsed = new URL(url);
  for (const key of ["apikey", "key"]) {
    if (parsed.searchParams.has(key)) {
      parsed.searchParams.set(key, "<redacted>");
    }
  }
  return parsed.toString();
}

function hasValue(value: string | undefined): boolean {
  return value !== undefined && value.trim() !== "";
}

function envStrFrom(env: AuthEnv, key: string, defaultValue: string): string {
  return env[key] ?? defaultValue;
}

function endpointOverride(value: string | undefined, defaultValue: string): string {
  const trimmed = value?.trim();
  return trimmed ? trimmed : defaultValue;
}
