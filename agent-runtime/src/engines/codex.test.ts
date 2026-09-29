import type { ThreadEvent } from "@openai/codex-sdk";
import { describe, expect, it } from "vitest";
import type { EngineConfig } from "../engine.js";
import { CaptureJournal } from "../testing/capture.js";
import { CodexEngine } from "./codex.js";

const cfg: EngineConfig = { model: "", systemPrompt: "persona", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 3 };

function fakeThread(events: ThreadEvent[], seen?: string[], seenOptions?: unknown[]) {
  return () => ({
    async runStreamed(input: string, turnOptions?: unknown) {
      seen?.push(input);
      seenOptions?.push(turnOptions);
      return {
        events: (async function* () {
          for (const e of events) yield e;
        })(),
      };
    },
  });
}

describe("CodexEngine journal", () => {
  it("journals assistant, tool_use and tool_result one line each, in order", async () => {
    const j = new CaptureJournal();
    const seen: string[] = [];
    const engine = new CodexEngine(
      fakeThread(
        [
          { type: "thread.started", thread_id: "th" },
          { type: "turn.started" },
          { type: "item.started", item: { id: "0", type: "agent_message", text: "" } },
          { type: "item.completed", item: { id: "1", type: "agent_message", text: "Looking." } },
          {
            type: "item.completed",
            item: {
              id: "2", type: "mcp_tool_call", server: "agent-box", tool: "shell", arguments: { cmd: "ls" }, status: "completed",
              result: { content: [{ type: "text", text: "README.md" }], structured_content: null },
            },
          },
          { type: "item.completed", item: { id: "3", type: "command_execution", command: "cat x", aggregated_output: "x!", exit_code: 0, status: "completed" } },
          { type: "item.completed", item: { id: "4", type: "agent_message", text: '{"files":1}' } },
          { type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 2, reasoning_output_tokens: 0 } },
        ],
        seen,
      ),
    );
    const res = await engine.run("task", cfg, j);
    expect(j.entries).toEqual([
      { kind: "assistant", text: "Looking." },
      { kind: "tool_use", tool: "mcp__agent-box__shell", input: '{"cmd":"ls"}' },
      { kind: "tool_result", tool: "mcp__agent-box__shell", text: "README.md" },
      { kind: "tool_use", tool: "shell", input: "cat x" },
      { kind: "tool_result", tool: "shell", text: "x!" },
      { kind: "assistant", text: '{"files":1}' },
    ]);
    expect(res.outputJson).toBe('{"files":1}');
    expect(seen[0]).toContain("persona");
  });

  it("journals a failed MCP call's error as its tool_result and error items as errors", async () => {
    const j = new CaptureJournal();
    const engine = new CodexEngine(
      fakeThread([
        { type: "item.completed", item: { id: "1", type: "mcp_tool_call", server: "s", tool: "t", arguments: {}, status: "failed", error: { message: "denied" } } },
        { type: "item.completed", item: { id: "2", type: "error", message: "soft failure" } },
        { type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0, reasoning_output_tokens: 0 } },
      ]),
    );
    await engine.run("task", cfg, j);
    expect(j.entries).toEqual([
      { kind: "tool_use", tool: "mcp__s__t", input: "{}" },
      { kind: "tool_result", tool: "mcp__s__t", text: "denied" },
      { kind: "error", text: "soft failure" },
    ]);
  });

  it("throws on turn.failed, like thread.run()", async () => {
    const engine = new CodexEngine(fakeThread([{ type: "turn.failed", error: { message: "quota" } }]));
    await expect(engine.run("task", cfg, new CaptureJournal())).rejects.toThrow("quota");
  });
});

// #2002: the Codex SDK's native schema mechanism is the turn's outputSchema
// (codex exec --output-schema); the skill's agent_card.output_schema_json is
// handed to it so the final agent message is shaped by the provider, not by
// prose.
describe("CodexEngine output schema", () => {
  const schema = { type: "object", properties: { files: { type: "array" } }, required: ["files"] };
  const done: ThreadEvent[] = [
    { type: "item.completed", item: { id: "1", type: "agent_message", text: '{"files":[]}' } },
    { type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0, reasoning_output_tokens: 0 } },
  ];

  it("passes the schema to the turn as outputSchema", async () => {
    const seenOptions: unknown[] = [];
    const engine = new CodexEngine(fakeThread(done, undefined, seenOptions));
    const res = await engine.run("task", { ...cfg, outputSchema: schema }, new CaptureJournal());
    expect(seenOptions).toEqual([{ outputSchema: schema }]);
    expect(res.outputJson).toBe('{"files":[]}');
  });

  it("passes no turn options when the skill declares no schema", async () => {
    const seenOptions: unknown[] = [];
    await new CodexEngine(fakeThread(done, undefined, seenOptions)).run("task", cfg, new CaptureJournal());
    expect(seenOptions).toEqual([undefined]);
  });
});
