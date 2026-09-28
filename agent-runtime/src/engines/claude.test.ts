import type { SDKMessage } from "@anthropic-ai/claude-agent-sdk";
import { describe, expect, it } from "vitest";
import type { EngineConfig } from "../engine.js";
import { CaptureJournal } from "../testing/capture.js";
import { ClaudeEngine, type ClaudeQuery } from "./claude.js";

const cfg: EngineConfig = { model: "", systemPrompt: "", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 3 };

// Only the fields the engine reads; the SDK's full message types carry ids and
// usage the journal never looks at.
function fakeQuery(messages: unknown[]): ClaudeQuery {
  return async function* () {
    for (const m of messages) yield m as SDKMessage;
  };
}

const assistant = (...content: unknown[]) => ({ type: "assistant", message: { content } });
const user = (...content: unknown[]) => ({ type: "user", message: { role: "user", content } });

describe("ClaudeEngine journal", () => {
  it("journals assistant text, tool_use and tool_result one line each, in order", async () => {
    const j = new CaptureJournal();
    const engine = new ClaudeEngine(
      fakeQuery([
        { type: "system", subtype: "init" },
        assistant({ type: "text", text: "Looking." }),
        assistant({ type: "tool_use", id: "tu1", name: "mcp__agent-box__shell", input: { cmd: "ls" } }),
        user({ type: "tool_result", tool_use_id: "tu1", content: [{ type: "text", text: "README.md" }] }),
        assistant({ type: "text", text: '{"files":1}' }),
        { type: "result", subtype: "success", is_error: false, result: "", usage: { output_tokens: 3 } },
      ]),
    );
    const res = await engine.run("task", cfg, j);
    expect(j.entries).toEqual([
      { kind: "assistant", text: "Looking." },
      { kind: "tool_use", tool: "mcp__agent-box__shell", input: '{"cmd":"ls"}' },
      { kind: "tool_result", tool: "mcp__agent-box__shell", text: "README.md" },
      { kind: "assistant", text: '{"files":1}' },
    ]);
    expect(res.outputJson).toBe('Looking.{"files":1}');
    expect(res.usage).toEqual({ output_tokens: 3 });
  });

  it("journals a string tool_result and an unknown tool id", async () => {
    const j = new CaptureJournal();
    const engine = new ClaudeEngine(
      fakeQuery([user({ type: "tool_result", tool_use_id: "nope", content: "plain" }), { type: "result", subtype: "success", is_error: false }]),
    );
    await engine.run("task", cfg, j);
    expect(j.entries).toEqual([{ kind: "tool_result", tool: "unknown", text: "plain" }]);
  });

  it("journals an error result", async () => {
    const j = new CaptureJournal();
    const engine = new ClaudeEngine(
      fakeQuery([{ type: "result", subtype: "error_max_turns", is_error: true, errors: ["hit the turn cap"] }]),
    );
    await engine.run("task", cfg, j);
    expect(j.entries).toEqual([{ kind: "error", text: "error_max_turns: hit the turn cap" }]);
  });
});
