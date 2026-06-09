import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { RIRS, type RirId } from "./config.js";
import type { ToolDependencies } from "./deps.js";
import { registerArinAsSetTool } from "./tools/arin/as-set.js";
import { registerArinContactTool } from "./tools/arin/contact.js";
import { registerArinRouteTool } from "./tools/arin/route.js";
import { registerRdapContactTool } from "./tools/rdap-contact.js";
import { registerRipeAsSetTool } from "./tools/ripe/as-set.js";
import { registerRipeContactTool } from "./tools/ripe/contact.js";
import { registerRipeRouteTool } from "./tools/ripe/route.js";
import { registerWhoisTool } from "./tools/whois.js";

export function registeredToolNames(enabled: Partial<Record<RirId, boolean>> = {}): string[] {
  const isEnabled = (rir: RirId): boolean => enabled[rir] ?? RIRS[rir].enabled;
  const names: string[] = [];

  if (isEnabled("ripe")) {
    names.push("ripe_whois_query", "ripe_expand_as_set", "ripe_validate_route_object", "ripe_contact_card");
  }
  if (isEnabled("arin")) {
    names.push("arin_whois_query", "arin_validate_route_object", "arin_expand_as_set", "arin_contact_card");
  }
  if (isEnabled("apnic")) {
    names.push("apnic_whois_query", "apnic_contact_card");
  }
  if (isEnabled("afrinic")) {
    names.push("afrinic_whois_query", "afrinic_contact_card");
  }
  if (isEnabled("lacnic")) {
    names.push("lacnic_whois_query", "lacnic_contact_card");
  }

  return names;
}

export function registerTools(server: McpServer, deps: ToolDependencies): void {
  if (RIRS.ripe.enabled) {
    registerWhoisTool(server, RIRS.ripe, deps);
    registerRipeAsSetTool(server, deps);
    registerRipeRouteTool(server, deps);
    registerRipeContactTool(server, deps);
  }

  if (RIRS.arin.enabled) {
    registerWhoisTool(server, RIRS.arin, deps);
    registerArinRouteTool(server, deps);
    registerArinAsSetTool(server, deps);
    registerArinContactTool(server, deps);
  }

  for (const rirId of ["apnic", "afrinic", "lacnic"] as const) {
    const rir = RIRS[rirId];
    if (rir.enabled) {
      registerWhoisTool(server, rir, deps);
      registerRdapContactTool(server, rir, deps);
    }
  }
}
