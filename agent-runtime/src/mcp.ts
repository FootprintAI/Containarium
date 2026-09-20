import type { EngineConfig } from "./engine.js";

// McpServerSpec is one MCP server an engine should mount — engine-neutral, so
// Claude, Codex and Gemini all derive their config from the same list instead
// of each hand-building its own (which is how they would drift).
export interface McpServerSpec {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  // Claude `allowedTools` entries this server contributes. Explicit patterns,
  // never a blanket `mcp__<name>__*` for the platform MCP: the allow-list the
  // daemon seeded is the whole point.
  claudeAllow: string[];
}

export const PLATFORM_MCP_NAME = "containarium";

// mcpServerSpecs is agent-box always, plus the platform MCP when the seed asked
// for it. The platform MCP receives its URL, the PATH of the token file and its
// tool allow-list through env — never the token value.
export function mcpServerSpecs(cfg: EngineConfig): McpServerSpec[] {
  const specs: McpServerSpec[] = [
    {
      name: "agent-box",
      command: cfg.agentBoxCommand,
      args: cfg.agentBoxArgs,
      claudeAllow: ["mcp__agent-box__*"],
    },
  ];
  const p = cfg.platformMcp;
  if (p) {
    specs.push({
      name: PLATFORM_MCP_NAME,
      command: p.command,
      args: p.args,
      env: {
        CONTAINARIUM_SERVER_URL: p.serverUrl,
        CONTAINARIUM_JWT_TOKEN_FILE: p.tokenFile,
        CONTAINARIUM_MCP_TOOLS: p.tools,
      },
      claudeAllow: p.tools
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t !== "")
        .map((t) => `mcp__${PLATFORM_MCP_NAME}__${t}`),
    });
  }
  return specs;
}

// claudeMcpServers is the inline `mcpServers` option the Claude Agent SDK takes.
export function claudeMcpServers(
  specs: McpServerSpec[],
): Record<string, { command: string; args: string[]; env?: Record<string, string> }> {
  return Object.fromEntries(
    specs.map((s) => [s.name, { command: s.command, args: s.args, ...(s.env ? { env: s.env } : {}) }]),
  );
}

export function claudeAllowedTools(specs: McpServerSpec[]): string[] {
  return specs.flatMap((s) => s.claudeAllow);
}

// TOML basic strings share JSON's escaping for every character these values can
// hold, so JSON.stringify is a correct (and injection-safe) TOML encoder here.
const toml = (s: string): string => JSON.stringify(s);

// codexConfigToml renders ~/.codex/config.toml: the model, then one
// [mcp_servers.<name>] table (plus an .env table) per server.
export function codexConfigToml(cfg: EngineConfig): string {
  let out = "";
  if (cfg.model) out += `model = ${toml(cfg.model)}\n`;
  for (const s of mcpServerSpecs(cfg)) {
    out += `[mcp_servers.${s.name}]\ncommand = ${toml(s.command)}\nargs = [${s.args.map(toml).join(", ")}]\n`;
    if (s.env) {
      out += `[mcp_servers.${s.name}.env]\n`;
      for (const [k, v] of Object.entries(s.env)) out += `${k} = ${toml(v)}\n`;
    }
  }
  return out;
}
