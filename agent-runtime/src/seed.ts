import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// DEFAULT_SEED_DIR is where RunAgentSkill seeds the box (internal/server/
// agent_server.go buildAgentSeedScript): system_prompt.txt, token, input.json,
// agent-card.json.
export const DEFAULT_SEED_DIR = "/etc/containarium/agent";

// AgentCard mirrors the relevant fields of the seeded agent-card.json
// (grpc-gateway camelCase). Only output_schema_json is load-bearing for the
// runtime today; the rest is passed through for discovery.
export interface AgentCard {
  id?: string;
  name?: string;
  capabilities?: string[];
  inputSchemaJson?: string;
  outputSchemaJson?: string;
  [k: string]: unknown;
}

// PlatformMcpConfig mirrors <seed>/platform_mcp.json — the daemon's instruction
// to mount the platform MCP beside agent-box (design decision D4). The shape is
// pinned by fixtures/platform_mcp.json, which internal/server's tests also read.
export interface PlatformMcpConfig {
  command: string;
  args: string[];
  serverUrl: string;
  // Path to the run's platform JWT; the MCP server re-reads it per request, so
  // the token value never enters a process env or a config file.
  tokenFile: string;
  // CONTAINARIUM_MCP_TOOLS allow-list, e.g. "tracker_*". Never empty (see
  // parsePlatformMcp): an empty list means "every tool" to the MCP server.
  tools: string;
}

export interface Seed {
  systemPrompt: string;
  inputJson: string;
  agentCard: AgentCard | null;
  // Path to the scoped platform JWT (for the platform MCP). The runtime does
  // not read the token itself — an engine that mounts the platform MCP points
  // it at this file. Null if absent.
  tokenPath: string | null;
  // The platform MCP to mount as a second MCP server, or null when the daemon
  // did not seed one (the run is not bound to a tracker connection).
  platformMcp: PlatformMcpConfig | null;
}

function readIfPresent(dir: string, file: string): string {
  const p = join(dir, file);
  return existsSync(p) ? readFileSync(p, "utf8") : "";
}

function requireString(obj: Record<string, unknown>, field: string): string {
  const v = obj[field];
  if (typeof v !== "string" || v.trim() === "") {
    throw new Error(`platform_mcp.json: "${field}" must be a non-empty string`);
  }
  return v;
}

// parsePlatformMcp validates platform_mcp.json. It throws on anything malformed
// instead of degrading: a silently dropped file would leave the agent with no
// tracker tools and no signal why, and a lenient parse of `tools` could mount
// the entire tool catalog.
export function parsePlatformMcp(raw: string): PlatformMcpConfig {
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch (e) {
    throw new Error(`platform_mcp.json: not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    throw new Error("platform_mcp.json: must be a JSON object");
  }
  const o = obj as Record<string, unknown>;
  const args = o.args ?? [];
  if (!Array.isArray(args) || !args.every((a) => typeof a === "string")) {
    throw new Error('platform_mcp.json: "args" must be an array of strings');
  }
  return {
    command: requireString(o, "command"),
    args: args as string[],
    serverUrl: requireString(o, "server_url"),
    tokenFile: requireString(o, "token_file"),
    tools: requireString(o, "tools"),
  };
}

// loadSeed reads the seed directory the daemon populated at launch. Missing
// files degrade gracefully (empty prompt, "{}" input) so a partially-seeded
// box still runs rather than crashing.
export function loadSeed(dir: string = process.env.AGENT_SEED_DIR ?? DEFAULT_SEED_DIR): Seed {
  const systemPrompt = readIfPresent(dir, "system_prompt.txt").trim();
  const inputJson = readIfPresent(dir, "input.json").trim() || "{}";

  let agentCard: AgentCard | null = null;
  const cardRaw = readIfPresent(dir, "agent-card.json").trim();
  if (cardRaw) {
    try {
      agentCard = JSON.parse(cardRaw) as AgentCard;
    } catch {
      agentCard = null; // a malformed card is non-fatal; discovery just degrades
    }
  }

  const tokenFile = join(dir, "token");
  const tokenPath = existsSync(tokenFile) ? tokenFile : null;

  const mcpRaw = readIfPresent(dir, "platform_mcp.json").trim();
  const platformMcp = mcpRaw ? parsePlatformMcp(mcpRaw) : null;

  return { systemPrompt, inputJson, agentCard, tokenPath, platformMcp };
}
