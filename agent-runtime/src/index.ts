import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { startA2AServer } from "./a2a.js";
import { writeArtifact } from "./artifact.js";
import type { Engine, EngineConfig } from "./engine.js";
import { ClaudeEngine } from "./engines/claude.js";
import { CodexEngine } from "./engines/codex.js";
import { pollConfigFromEnv, runPollLoop } from "./poll.js";
import { DEFAULT_SEED_DIR, loadSeed } from "./seed.js";

// The in-box loop entrypoint (Phase 4a). Reads the seed the daemon planted,
// runs one task to completion through the selected engine (Claude Agent SDK or
// OpenAI Codex SDK) — both mounting agent-box as their MCP tool surface — and
// writes artifact.json back for the daemon to return.
//
// Engine selection: CONTAINARIUM_AGENT_ENGINE (claude | codex), default claude.
// (A later phase moves this onto the skill manifest as an `engine` field.)

const seedDir = process.env.AGENT_SEED_DIR ?? DEFAULT_SEED_DIR;
const engineName = (process.env.CONTAINARIUM_AGENT_ENGINE ?? "claude").toLowerCase();
const agentBoxCommand = process.env.AGENT_BOX_BIN ?? "agent-box";
const maxTurns = Number(process.env.CONTAINARIUM_AGENT_MAX_TURNS ?? "12");

// Model default is engine-specific. Claude → claude-opus-4-8 (per the Claude
// API guidance). Codex → empty, i.e. let Codex use its own configured default
// (we don't hard-code an OpenAI model id). Override either with
// CONTAINARIUM_AGENT_MODEL.
const model = process.env.CONTAINARIUM_AGENT_MODEL ?? (engineName === "claude" ? "claude-opus-4-8" : "");

function pickEngine(name: string): Engine {
  switch (name) {
    case "claude":
      return new ClaudeEngine();
    case "codex":
      return new CodexEngine();
    default:
      throw new Error(`unknown engine ${name} (want: claude | codex)`);
  }
}

// writeCodexConfig registers agent-box as an MCP server (and the model, if set)
// in ~/.codex/config.toml, which the Codex CLI the SDK drives reads. The Claude
// engine takes its MCP config inline, so this is Codex-only.
function writeCodexConfig(cfg: EngineConfig): void {
  const dir = join(homedir(), ".codex");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const argsToml = cfg.agentBoxArgs.map((a) => `"${a}"`).join(", ");
  let toml = "";
  if (cfg.model) toml += `model = "${cfg.model}"\n`;
  toml += `[mcp_servers.agent-box]\ncommand = "${cfg.agentBoxCommand}"\nargs = [${argsToml}]\n`;
  writeFileSync(join(dir, "config.toml"), toml);
}

// mode: "run" (one-shot — read input.json, run once, write artifact.json; the
// 4a path `agent run` uses), "serve" (start the A2A server so peers/crews can
// delegate tasks; the 4b path SendAgentTask reaches), or "poll" (pull-queue
// worker: lease → run → complete in a loop, outbound-only; prototype). Default
// "run".
const mode = (process.env.CONTAINARIUM_AGENT_MODE ?? "run").toLowerCase();

async function main(): Promise<void> {
  const seed = loadSeed(seedDir);
  const engine = pickEngine(engineName);
  const cfg: EngineConfig = {
    model,
    systemPrompt: seed.systemPrompt,
    agentBoxCommand,
    agentBoxArgs: [],
    maxTurns,
  };

  if (engine.name === "codex") writeCodexConfig(cfg);

  if (mode === "serve") {
    // Long-running: serve /agent-card + /tasks until the box stops.
    startA2AServer(seed, engine, cfg);
    return;
  }

  if (mode === "poll") {
    // Long-running pull-queue worker: lease → run → complete, outbound-only.
    // The seed's system prompt is the worker's persona; the leased task's
    // input_json is the per-run input.
    await runPollLoop(pollConfigFromEnv(), engine, cfg);
    return;
  }

  try {
    const res = await engine.run(seed.inputJson, cfg);
    writeArtifact(seedDir, { outputJson: res.outputJson, engine: engine.name, model, usage: res.usage });
    process.stdout.write(`agent-runtime: ${engine.name} run complete\n`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    writeArtifact(seedDir, { outputJson: "", engine: engine.name, model, error: msg });
    process.stderr.write(`agent-runtime: ${engine.name} run failed: ${msg}\n`);
    process.exitCode = 1;
  }
}

void main();
