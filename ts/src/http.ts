#!/usr/bin/env node
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

import { HTTP_HOST, HTTP_PORT } from "./config.js";
import { createWhoisMcpServer } from "./server.js";

const app = createMcpExpressApp();

app.post("/mcp", async (req, res) => {
  const server = createWhoisMcpServer();
  const transport = new StreamableHTTPServerTransport(
    {
      sessionIdGenerator: undefined
    } as unknown as ConstructorParameters<typeof StreamableHTTPServerTransport>[0]
  );

  try {
    await server.connect(transport as unknown as Transport);
    await transport.handleRequest(req, res, req.body);
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
  } catch (error) {
    console.error("Error handling MCP request:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error"
        },
        id: null
      });
    }
  }
});

app.get("/mcp", (_req, res) => {
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    })
  );
});

app.delete("/mcp", (_req, res) => {
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    })
  );
});

app.listen(HTTP_PORT, HTTP_HOST, (error?: Error) => {
  if (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }

  console.log(`Starting whois-mcp server on http://${HTTP_HOST}:${HTTP_PORT}`);
});
