import { HTTP_TIMEOUT_SECONDS, USER_AGENT } from "../config.js";
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

export class HttpStatusError extends Error {
  readonly status: number;

  constructor(status: number, statusText: string, readonly url: string) {
    super(`HTTP ${status}: ${statusText}`);
    this.name = "HttpStatusError";
    this.status = status;
  }
}

export interface JsonHttpClient {
  getJson(url: string, options?: { notFoundValue?: unknown; headers?: Record<string, string> }): Promise<unknown>;
}

export class FetchJsonHttpClient implements JsonHttpClient {
  async getJson(
    url: string,
    options: { notFoundValue?: unknown; headers?: Record<string, string> } = {}
  ): Promise<unknown> {
    const response = await getText(url, {
      headers: {
        "User-Agent": USER_AGENT,
        ...(options.headers ?? {})
      },
      redirectsRemaining: 5
    });

    if (response.status === 404 && "notFoundValue" in options) {
      return options.notFoundValue;
    }

    if (response.status < 200 || response.status >= 300) {
      throw new HttpStatusError(response.status, response.statusText, url);
    }

    return JSON.parse(response.text) as unknown;
  }
}

interface TextResponse {
  status: number;
  statusText: string;
  text: string;
}

function getText(
  url: string,
  options: { headers: Record<string, string>; redirectsRemaining: number }
): Promise<TextResponse> {
  const parsedUrl = new URL(url);
  const client = parsedUrl.protocol === "http:" ? http : https;

  return new Promise((resolve, reject) => {
    const request = client.request(
      parsedUrl,
      {
        method: "GET",
        headers: options.headers,
        family: 4
      },
      (response) => {
        const status = response.statusCode ?? 0;
        const statusText = response.statusMessage ?? "";
        const location = response.headers.location;

        if (status >= 300 && status < 400 && location && options.redirectsRemaining > 0) {
          response.resume();
          const nextUrl = new URL(location, parsedUrl).toString();
          getText(nextUrl, {
            headers: options.headers,
            redirectsRemaining: options.redirectsRemaining - 1
          })
            .then(resolve)
            .catch(reject);
          return;
        }

        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            status,
            statusText,
            text: Buffer.concat(chunks).toString("utf8")
          });
        });
      }
    );

    request.setTimeout(HTTP_TIMEOUT_SECONDS * 1000, () => {
      request.destroy(new Error("HTTP request timed out"));
    });
    request.on("error", reject);
    request.end();
  });
}

export function errorDetail(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  if (typeof error === "object" && error !== null && "code" in error) {
    return String((error as { code: unknown }).code);
  }
  return String(error);
}

export const defaultHttpClient = new FetchJsonHttpClient();
