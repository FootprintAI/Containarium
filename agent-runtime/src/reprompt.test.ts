import { describe, expect, it } from "vitest";
import type { Engine, EngineConfig, EngineResult } from "./engine.js";
import type { JournalSink } from "./journal.js";
import { FINAL_JSON_REPROMPT, isFileChangingTool, runWithFinalJsonReprompt } from "./reprompt.js";
import { CaptureJournal } from "./testing/capture.js";

const cfg: EngineConfig = { model: "", systemPrompt: "", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 1 };

// scriptedEngine plays one first turn and, if the engine supports follow-ups,
// one reply per follow-up from `replies` (#2513 item 2). `prompts` records
// each follow-up prompt it was sent.
function scriptedEngine(
  first: (j: JournalSink) => string,
  replies: string[] | undefined,
  prompts: string[] = [],
): Engine {
  const reply = async (prompt: string, j: JournalSink): Promise<EngineResult> => {
    prompts.push(prompt);
    const out = replies?.shift() ?? "";
    if (out) j.append({ kind: "assistant", text: out });
    return { outputJson: out, ...(replies ? { followUp: reply } : {}) };
  };
  return {
    name: "scripted",
    async run(_task, _cfg, journal) {
      return { outputJson: first(journal), ...(replies ? { followUp: reply } : {}) };
    },
  };
}

const editsFile = (tool: string) => (j: JournalSink) => {
  j.append({ kind: "tool_use", tool, input: '{"path":"text/slug.go"}' });
  j.append({ kind: "tool_result", tool, text: "bytes_written: 649" });
  return "";
};

describe("isFileChangingTool", () => {
  it.each([
    ["write_file", true],
    ["move_file", true],
    ["delete_file", true],
    ["mcp__agent-box__write_file", true],
    ["mcp__agent-box__delete_file", true],
    ["file_change", true],
    ["read_file", false],
    ["list_directory", false],
    ["shell_exec", false],
    ["mcp__agent-box__read_file", false],
    ["mcp__platform__tracker_comment", false],
    ["rewrite_file", false],
  ])("%s -> %s", (tool, want) => {
    expect(isFileChangingTool(tool)).toBe(want);
  });
});

describe("runWithFinalJsonReprompt (#2513 item 2)", () => {
  it("re-prompts once when the run changed files but returned no final message, and returns the reply", async () => {
    const j = new CaptureJournal();
    const prompts: string[] = [];
    const res = await runWithFinalJsonReprompt(
      scriptedEngine(editsFile("mcp__agent-box__write_file"), ['{"files":["text/slug.go"]}'], prompts),
      "task",
      cfg,
      j,
    );
    expect(res.outputJson).toBe('{"files":["text/slug.go"]}');
    expect(prompts).toEqual([FINAL_JSON_REPROMPT]);
    expect(j.entries).toContainEqual({
      kind: "status",
      text: "run changed files but returned no final message: re-prompting once for the final JSON",
    });
  });

  it("fails the run with the reason when the re-prompt also returns nothing, without asking twice", async () => {
    const j = new CaptureJournal();
    const prompts: string[] = [];
    await expect(
      runWithFinalJsonReprompt(scriptedEngine(editsFile("write_file"), ["", '{"late":true}'], prompts), "task", cfg, j),
    ).rejects.toThrow(/changed files but returned no final JSON, even after one re-prompt/);
    expect(prompts).toHaveLength(1);
  });

  it("does not re-prompt a run that changed no files", async () => {
    const j = new CaptureJournal();
    const prompts: string[] = [];
    const res = await runWithFinalJsonReprompt(
      scriptedEngine(editsFile("read_file"), ['{"x":1}'], prompts),
      "task",
      cfg,
      j,
    );
    expect(res.outputJson).toBe("");
    expect(prompts).toEqual([]);
  });

  it("does not re-prompt a run that returned a final message", async () => {
    const prompts: string[] = [];
    const res = await runWithFinalJsonReprompt(
      scriptedEngine((j) => (editsFile("write_file")(j), '{"files":[]}'), ['{"x":1}'], prompts),
      "task",
      cfg,
      new CaptureJournal(),
    );
    expect(res.outputJson).toBe('{"files":[]}');
    expect(prompts).toEqual([]);
  });

  it("treats a whitespace-only final message as none", async () => {
    const prompts: string[] = [];
    const res = await runWithFinalJsonReprompt(
      scriptedEngine((j) => (editsFile("file_change")(j), "  \n"), ['{"ok":true}'], prompts),
      "task",
      cfg,
      new CaptureJournal(),
    );
    expect(res.outputJson).toBe('{"ok":true}');
    expect(prompts).toHaveLength(1);
  });

  it("leaves the result alone when the engine cannot continue the conversation", async () => {
    const res = await runWithFinalJsonReprompt(scriptedEngine(editsFile("write_file"), undefined), "task", cfg, new CaptureJournal());
    expect(res.outputJson).toBe("");
  });

  it("journals the run's own rows through to the caller's journal", async () => {
    const j = new CaptureJournal();
    await runWithFinalJsonReprompt(scriptedEngine(editsFile("write_file"), ['{"a":1}']), "task", cfg, j);
    expect(j.entries[0]).toEqual({ kind: "tool_use", tool: "write_file", input: '{"path":"text/slug.go"}' });
    expect(j.entries.at(-1)).toEqual({ kind: "assistant", text: '{"a":1}' });
  });
});
