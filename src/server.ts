import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { defaultToolDependencies, type ToolDependencies } from "./deps.js";
import { registerTools } from "./register.js";

export function createInetRegistryMcpServer(deps: ToolDependencies = defaultToolDependencies): McpServer {
  const server = new McpServer(
    {
      name: "inet-registry-mcp",
      version: "0.1.0"
    },
    {
      capabilities: {
        logging: {}
      }
    }
  );

  registerTools(server, deps);
  return server;
}
