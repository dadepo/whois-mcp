#!/usr/bin/env node

console.error("Choose an MCP transport explicitly:");
console.error("  npm run dev:stdio  # run over stdin/stdout for MCP clients that launch the process");
console.error("  npm run dev:http   # run over HTTP at /mcp");
process.exit(1);
