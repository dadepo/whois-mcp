import { defaultHttpClient, type JsonHttpClient } from "./lib/http.js";
import { defaultWhoisClient, type WhoisClient } from "./lib/whois-client.js";

export interface ToolDependencies {
  httpClient: JsonHttpClient;
  whoisClient: WhoisClient;
}

export const defaultToolDependencies: ToolDependencies = {
  httpClient: defaultHttpClient,
  whoisClient: defaultWhoisClient
};
