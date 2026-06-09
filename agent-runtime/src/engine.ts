// Engine is the pluggable in-box agent loop. Both the Claude Agent SDK and the
// OpenAI Codex SDK are wrapped behind this interface so the agent-runtime is
// harness-agnostic: a skill picks its engine, the rest of the runtime (seed
// loading, artifact writing, the A2A server in 4b) stays identical.
export interface EngineConfig {
  // Model id. Engine-specific: Claude → claude-opus-4-8; Codex → an OpenAI
  // model. Empty means "use the engine's own default".
  model: string;
  // The skill's persona, from system_prompt.txt.
  systemPrompt: string;
  // The in-box agent-box MCP server (the engine's tool surface): the command
  // to spawn over stdio and its args.
  agentBoxCommand: string;
  agentBoxArgs: string[];
  // Hard cap on agentic turns (tool-use round trips).
  maxTurns: number;
}

export interface EngineResult {
  // The agent's final output text/JSON.
  outputJson: string;
  // Engine-shaped usage/cost, if available.
  usage?: unknown;
}

export interface Engine {
  readonly name: string;
  run(task: string, cfg: EngineConfig): Promise<EngineResult>;
}
