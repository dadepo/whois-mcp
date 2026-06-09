#!/usr/bin/env node

const command = process.argv[2] === "start" ? "start" : "dev";

console.error("Choose an MCP transport explicitly:");
console.error(`  npm run ${command}:stdio  # run over stdin/stdout for MCP clients that launch the process`);
console.error(`  npm run ${command}:http   # run over HTTP at /mcp`);
process.exit(1);
