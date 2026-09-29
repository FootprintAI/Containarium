import type { SDKMessage } from "@anthropic-ai/claude-agent-sdk";
import { describe, expect, it } from "vitest";
import type { EngineConfig } from "../engine.js";
import { CaptureJournal } from "../testing/capture.js";
import { ClaudeEngine, type ClaudeQuery } from "./claude.js";

const cfg: EngineConfig = { model: "", systemPrompt: "", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 3 };

// Only the fields the engine reads; the SDK's full message types carry ids and
// usage the journal never looks at. `seen` captures each query() params
// object, for tests that assert what the engine asked the SDK for.
function fakeQuery(messages: unknown[], seen?: Parameters<ClaudeQuery>[0][]): ClaudeQuery {
  return async function* (params) {
    seen?.push(params);
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

// #2002: a skill's agent_card.output_schema_json is enforced by the SDK's
// structured-output mechanism (outputFormat json_schema — the SDK validates the
// final output against the schema and re-prompts on mismatch), not requested in
// prose. The artifact is the SDK-validated structured_output; a run that never
// produced one is rejected rather than returning whatever text the model wrote.
describe("ClaudeEngine output schema", () => {
  const schema = {
    type: "object",
    properties: { files: { type: "array" }, summary: { type: "string" } },
    required: ["files", "summary"],
  };
  const schemaCfg: EngineConfig = { ...cfg, outputSchema: schema };
  const structured = { files: [{ path: "README.md", content: "# hi\n" }], summary: "added a heading" };
  const success = (extra: Record<string, unknown> = {}) => ({ type: "result", subtype: "success", is_error: false, result: "", ...extra });

  it("passes the schema to the SDK as a json_schema outputFormat", async () => {
    const seen: Parameters<ClaudeQuery>[0][] = [];
    const engine = new ClaudeEngine(fakeQuery([success({ structured_output: structured })], seen));
    await engine.run("task", schemaCfg, new CaptureJournal());
    expect(seen[0]?.options?.outputFormat).toEqual({ type: "json_schema", schema });
  });

  it("sends no outputFormat when the skill declares no schema", async () => {
    const seen: Parameters<ClaudeQuery>[0][] = [];
    const engine = new ClaudeEngine(fakeQuery([success()], seen));
    await engine.run("task", cfg, new CaptureJournal());
    expect(seen[0]?.options?.outputFormat).toBeUndefined();
  });

  it("returns the SDK-validated structured_output as the artifact, not the assistant prose", async () => {
    const j = new CaptureJournal();
    // The exact failure from the issue: a fabricated tool call written as prose.
    const prose = 'print(default_api.write_file(path = file_path, content = modified_content))';
    const engine = new ClaudeEngine(fakeQuery([assistant({ type: "text", text: prose }), success({ structured_output: structured, usage: { output_tokens: 9 } })]));
    const res = await engine.run("task", schemaCfg, j);
    expect(JSON.parse(res.outputJson)).toEqual(structured);
    expect(res.usage).toEqual({ output_tokens: 9 });
    // The prose is still journaled — it is what the model said — it just never
    // becomes the artifact.
    expect(j.entries).toEqual([{ kind: "assistant", text: prose }]);
  });

  it("rejects a run whose output never conformed (SDK retries exhausted)", async () => {
    const j = new CaptureJournal();
    const engine = new ClaudeEngine(
      fakeQuery([
        assistant({ type: "text", text: "not json" }),
        { type: "result", subtype: "error_max_structured_output_retries", is_error: true, errors: ["output did not match the schema"] },
      ]),
    );
    await expect(engine.run("task", schemaCfg, j)).rejects.toThrow(/error_max_structured_output_retries.*did not match/);
    expect(j.entries).toEqual([
      { kind: "assistant", text: "not json" },
      { kind: "error", text: "error_max_structured_output_retries: output did not match the schema" },
    ]);
  });

  it("rejects any other error result too when a schema is declared, instead of returning prose", async () => {
    const engine = new ClaudeEngine(fakeQuery([assistant({ type: "text", text: "half done" }), { type: "result", subtype: "error_max_turns", is_error: true, errors: [] }]));
    await expect(engine.run("task", schemaCfg, new CaptureJournal())).rejects.toThrow(/error_max_turns/);
  });

  it("rejects a success result that carries no structured_output when a schema is declared", async () => {
    // The SDK docs call this out: subtype success with no structured_output is a
    // failure to treat as such, not text to pass along.
    const engine = new ClaudeEngine(fakeQuery([assistant({ type: "text", text: '{"files":1}' }), success()]));
    await expect(engine.run("task", schemaCfg, new CaptureJournal())).rejects.toThrow(/no structured output/);
  });

  it("rejects a run that ends without any result message when a schema is declared", async () => {
    const engine = new ClaudeEngine(fakeQuery([assistant({ type: "text", text: "..." })]));
    await expect(engine.run("task", schemaCfg, new CaptureJournal())).rejects.toThrow(/no structured output/);
  });
});
