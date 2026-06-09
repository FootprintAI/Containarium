import { writeFileSync } from "node:fs";
import { join } from "node:path";

// Artifact is what the in-box loop writes back to the seed dir. The daemon
// reads artifact.json to populate RunAgentSkillResponse.artifact_json (and, for
// the A2A server, the AgentArtifact returned from /tasks).
export interface Artifact {
  // The agent's final output (JSON string, ideally matching the skill's
  // agent_card.output_schema_json).
  outputJson: string;
  // Which engine produced it (claude | codex) and the model used — for audit.
  engine: string;
  model: string;
  // Best-effort usage/cost metadata, engine-shaped.
  usage?: unknown;
  // Populated when the run failed.
  error?: string;
}

export const ARTIFACT_FILE = "artifact.json";

// writeArtifact writes the artifact next to the seed, mode 0600 (it may echo
// task content; keep it owner-only).
export function writeArtifact(dir: string, a: Artifact): void {
  writeFileSync(join(dir, ARTIFACT_FILE), JSON.stringify(a, null, 2), { mode: 0o600 });
}
