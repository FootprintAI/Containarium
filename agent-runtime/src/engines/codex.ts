import { Codex, type Thread, type ThreadItem } from "@openai/codex-sdk";
import type { Engine, EngineConfig, EngineResult } from "../engine.js";
import type { JournalSink } from "../journal.js";

// CodexThreadFactory starts the Codex thread a run streams; a seam for tests.
export type CodexThreadFactory = () => Pick<Thread, "runStreamed">;

// CodexEngine drives the in-box loop with the OpenAI Codex SDK. Like the Claude
// engine it mounts agent-box as its tool surface — but Codex wires MCP servers
// and the model through its own config (~/.codex/config.toml), which the
// runtime writes before this engine runs (see writeCodexConfig in index.ts).
// Auth: the Codex SDK reads its key from the environment (CODEX_API_KEY /
// OPENAI_API_KEY), seeded via secrets.
//
// The Codex SDK has no separate system-prompt field, so the skill's persona is
// prepended to the task. The turn is streamed (thread.runStreamed) rather than
// awaited (thread.run) so each completed item is journaled as it lands
// (#2095); the result is the same thread.run() computes: the last agent
// message is the final response, turn.failed throws.
//
// Output schema (#2002): the skill's agent_card.output_schema_json is passed
// as the turn's outputSchema — the SDK's native mechanism (codex exec
// --output-schema), which shapes the final agent message provider-side. The
// runtime does not re-validate the message locally; conformance is the
// provider's, as with the Claude engine's structured output.
export class CodexEngine implements Engine {
  readonly name = "codex";

  constructor(
    private readonly startThread: CodexThreadFactory = () =>
      new Codex().startThread({ workingDirectory: process.cwd(), skipGitRepoCheck: true }),
  ) {}

  async run(task: string, cfg: EngineConfig, journal: JournalSink): Promise<EngineResult> {
    const thread = this.startThread();

    const prompt = cfg.systemPrompt
      ? `${cfg.systemPrompt}\n\n---\nTask:\n${task}`
      : task;

    const { events } = await thread.runStreamed(prompt, cfg.outputSchema ? { outputSchema: cfg.outputSchema } : undefined);
    let finalResponse = "";
    let usage: unknown;
    for await (const event of events) {
      if (event.type === "item.completed") {
        if (event.item.type === "agent_message") finalResponse = event.item.text;
        journalCodexItem(event.item, journal);
      } else if (event.type === "turn.completed") {
        usage = event.usage;
      } else if (event.type === "turn.failed") {
        throw new Error(event.error.message);
      } else if (event.type === "error") {
        journal.append({ kind: "error", text: event.message });
      }
    }
    return { outputJson: finalResponse.trim(), usage };
  }
}

// journalCodexItem maps one completed Codex item to journal lines. MCP tool
// names use the Claude engine's mcp__<server>__<tool> form so a renderer sees
// one naming scheme across engines. Reasoning, web-search and todo-list items
// are not journaled.
function journalCodexItem(item: ThreadItem, journal: JournalSink): void {
  switch (item.type) {
    case "agent_message":
      if (item.text) journal.append({ kind: "assistant", text: item.text });
      return;
    case "command_execution":
      journal.append({ kind: "tool_use", tool: "shell", input: item.command });
      journal.append({ kind: "tool_result", tool: "shell", text: item.aggregated_output });
      return;
    case "mcp_tool_call": {
      const tool = `mcp__${item.server}__${item.tool}`;
      journal.append({ kind: "tool_use", tool, input: JSON.stringify(item.arguments ?? {}) });
      const text = item.error
        ? item.error.message
        : (item.result?.content ?? []).map((b) => (b.type === "text" ? b.text : `[${b.type}]`)).join("\n");
      journal.append({ kind: "tool_result", tool, text });
      return;
    }
    case "file_change":
      journal.append({ kind: "tool_use", tool: "file_change", input: item.changes.map((c) => `${c.kind} ${c.path}`).join("\n") });
      journal.append({ kind: "tool_result", tool: "file_change", text: item.status });
      return;
    case "error":
      journal.append({ kind: "error", text: item.message });
      return;
    default:
      return;
  }
}
