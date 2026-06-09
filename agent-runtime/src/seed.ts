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

export interface Seed {
  systemPrompt: string;
  inputJson: string;
  agentCard: AgentCard | null;
  // Path to the scoped platform JWT (for the platform MCP). The runtime does
  // not read the token itself — an engine that mounts the platform MCP points
  // it at this file. Null if absent.
  tokenPath: string | null;
}

function readIfPresent(dir: string, file: string): string {
  const p = join(dir, file);
  return existsSync(p) ? readFileSync(p, "utf8") : "";
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

  return { systemPrompt, inputJson, agentCard, tokenPath };
}
