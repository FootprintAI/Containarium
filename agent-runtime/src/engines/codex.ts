import { Codex } from "@openai/codex-sdk";
import type { Engine, EngineConfig, EngineResult } from "../engine.js";

// CodexEngine drives the in-box loop with the OpenAI Codex SDK. Like the Claude
// engine it mounts agent-box as its tool surface — but Codex wires MCP servers
// and the model through its own config (~/.codex/config.toml), which the
// runtime writes before this engine runs (see writeCodexConfig in index.ts).
// Auth: the Codex SDK reads its key from the environment (CODEX_API_KEY /
// OPENAI_API_KEY), seeded via secrets.
//
// The Codex SDK has no separate system-prompt field, so the skill's persona is
// prepended to the task. Verified against @openai/codex-sdk: Codex.startThread
// → thread.run(prompt) → turn.finalResponse.
export class CodexEngine implements Engine {
  readonly name = "codex";

  async run(task: string, cfg: EngineConfig): Promise<EngineResult> {
    const codex = new Codex();

    const thread = codex.startThread({
      workingDirectory: process.cwd(),
      skipGitRepoCheck: true,
    });

    const prompt = cfg.systemPrompt
      ? `${cfg.systemPrompt}\n\n---\nTask:\n${task}`
      : task;

    const turn = await thread.run(prompt);
    const out = (turn as { finalResponse?: string }).finalResponse ?? "";
    return { outputJson: out.trim() };
  }
}
