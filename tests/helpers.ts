import type { ToolDependencies } from "../src/deps.js";
import type { WhoisEndpoint } from "../src/config.js";
import type { WhoisQueryOptions } from "../src/lib/whois-client.js";

export class FakeHttpClient {
  readonly calls: Array<{ url: string; headers?: Record<string, string> }> = [];
  private readonly responses = new Map<string, unknown | Error>();

  set(url: string, response: unknown | Error): void {
    this.responses.set(url, response);
  }

  async getJson(url: string, options: { notFoundValue?: unknown; headers?: Record<string, string> } = {}): Promise<unknown> {
    this.calls.push({ url, headers: options.headers });
    const response = this.responses.get(url);
    if (response instanceof Error) {
      throw response;
    }
    if (response !== undefined) {
      return response;
    }
    if ("notFoundValue" in options) {
      return options.notFoundValue;
    }
    throw new Error(`Unexpected URL: ${url}`);
  }
}

export class FakeWhoisClient {
  readonly calls: Array<{ endpoint: WhoisEndpoint; line: string; options: WhoisQueryOptions }> = [];
  response: string | Error = "WHOIS response";

  async query(endpoint: WhoisEndpoint, line: string, options: WhoisQueryOptions): Promise<string> {
    this.calls.push({ endpoint, line, options });
    if (this.response instanceof Error) {
      throw this.response;
    }
    return this.response;
  }
}

export function fakeDeps(): ToolDependencies & { httpClient: FakeHttpClient; whoisClient: FakeWhoisClient } {
  return {
    httpClient: new FakeHttpClient(),
    whoisClient: new FakeWhoisClient()
  };
}
