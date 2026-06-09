#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { createWhoisMcpServer } from "./server.js";

async function main(): Promise<void> {
  const server = createWhoisMcpServer();
  await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  console.error("Server error:", error);
  process.exit(1);
});
