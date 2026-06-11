import net from "node:net";

import { PORT43_CONNECT_TIMEOUT_SECONDS, PORT43_READ_TIMEOUT_SECONDS } from "../config.js";
import type { WhoisEndpoint } from "../config.js";

export class WhoisTimeoutError extends Error {
  constructor(readonly phase: "connect" | "read") {
    super("Connection or read timeout");
    this.name = "WhoisTimeoutError";
  }
}

export interface WhoisQueryOptions {
  chunkSize: number;
  readTimeoutReturnsPartial: boolean;
}

export interface WhoisClient {
  query(endpoint: WhoisEndpoint, line: string, options: WhoisQueryOptions): Promise<string>;
}

export class NodeWhoisClient implements WhoisClient {
  async query(endpoint: WhoisEndpoint, line: string, options: WhoisQueryOptions): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({
        host: endpoint.server,
        port: endpoint.port,
        family: 4
      });
      const chunks: Buffer[] = [];
      let settled = false;
      let connectTimer: NodeJS.Timeout | undefined;
      let readTimer: NodeJS.Timeout | undefined;

      const cleanup = (): void => {
        if (connectTimer) {
          clearTimeout(connectTimer);
        }
        if (readTimer) {
          clearTimeout(readTimer);
        }
        socket.removeAllListeners();
        socket.destroy();
      };

      const settleResolve = (): void => {
        if (settled) {
          return;
        }
        settled = true;
        const text = Buffer.concat(chunks).toString("utf8");
        cleanup();
        resolve(text);
      };

      const settleReject = (error: Error): void => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(error);
      };

      const startReadTimer = (): void => {
        if (readTimer) {
          clearTimeout(readTimer);
        }
        readTimer = setTimeout(() => {
          if (options.readTimeoutReturnsPartial) {
            settleResolve();
          } else {
            settleReject(new WhoisTimeoutError("read"));
          }
        }, PORT43_READ_TIMEOUT_SECONDS * 1000);
      };

      connectTimer = setTimeout(() => {
        settleReject(new WhoisTimeoutError("connect"));
      }, PORT43_CONNECT_TIMEOUT_SECONDS * 1000);

      socket.on("connect", () => {
        if (connectTimer) {
          clearTimeout(connectTimer);
          connectTimer = undefined;
        }
        socket.write(line, "utf8");
        startReadTimer();
      });

      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk.subarray(0, options.chunkSize));
        startReadTimer();
      });

      socket.on("end", settleResolve);
      socket.on("close", settleResolve);
      socket.on("error", settleReject);
    });
  }
}

export const defaultWhoisClient = new NodeWhoisClient();
