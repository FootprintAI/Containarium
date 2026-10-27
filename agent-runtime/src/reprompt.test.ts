import { describe, expect, it } from "vitest";
import type { Engine, EngineConfig, EngineResult } from "./engine.js";
import type { JournalSink } from "./journal.js";
import { FINAL_JSON_REPROMPT, isFileChangingTool, isFileChangingToolUse, runWithFinalJsonReprompt } from "./reprompt.js";
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
    // #3107 item 5: only agent-box's tools count under the mcp__ prefix.
    ["mcp__other__write_file", false],
    ["mcp__containarium__delete_file", false],
    ["mcp__agent-box-evil__write_file", false],
    ["mcp__agent-box__", false],
    ["mcp__platform__tracker_comment", false],
    ["rewrite_file", false],
  ])("%s -> %s", (tool, want) => {
    expect(isFileChangingTool(tool)).toBe(want);
  });
});

describe("isFileChangingToolUse (#3107 item 1)", () => {
  const sh = (command: string) => JSON.stringify({ command });
  it("counts a shell_exec / Codex shell command that writes a file", () => {
    expect(isFileChangingToolUse("mcp__agent-box__shell_exec", sh("echo hi > a.txt"))).toBe(true);
    expect(isFileChangingToolUse("shell_exec", sh("sed -i s/a/b/ f.go"))).toBe(true);
    expect(isFileChangingToolUse("shell", "bash -lc 'rm old.go'")).toBe(true);
  });
  it("does not count a shell command that only reads, or one it cannot parse", () => {
    expect(isFileChangingToolUse("mcp__agent-box__shell_exec", sh("cat f.go | grep x"))).toBe(false);
    expect(isFileChangingToolUse("shell", "ls -la")).toBe(false);
    expect(isFileChangingToolUse("shell_exec", "not json > a.txt")).toBe(false);
    expect(isFileChangingToolUse("shell_exec", JSON.stringify({ command: 5 }))).toBe(false);
  });
  it("does not treat another server's shell_exec as a shell", () => {
    expect(isFileChangingToolUse("mcp__other__shell_exec", sh("rm -rf x"))).toBe(false);
  });
  it("still counts the file tools whatever the input", () => {
    expect(isFileChangingToolUse("write_file", "{}")).toBe(true);
  });
});

describe("runWithFinalJsonReprompt (#2513 item 2)", () => {
  it("re-prompts a run that edited only through the shell (#3107)", async () => {
    const prompts: string[] = [];
    const shellEdit = (j: JournalSink) => {
      j.append({ kind: "tool_use", tool: "mcp__agent-box__shell_exec", input: JSON.stringify({ command: "echo x > out.txt" }) });
      return "";
    };
    const res = await runWithFinalJsonReprompt(scriptedEngine(shellEdit, ['{"ok":1}'], prompts), "task", cfg, new CaptureJournal());
    expect(res.outputJson).toBe('{"ok":1}');
    expect(prompts).toHaveLength(1);
  });

  it("does not re-prompt a run whose shell calls only read (#3107)", async () => {
    const prompts: string[] = [];
    const shellRead = (j: JournalSink) => {
      j.append({ kind: "tool_use", tool: "shell", input: "bash -lc 'git status'" });
      return "";
    };
    await runWithFinalJsonReprompt(scriptedEngine(shellRead, ['{"ok":1}'], prompts), "task", cfg, new CaptureJournal());
    expect(prompts).toEqual([]);
  });

  it("does not re-prompt a run whose only write_file came from another MCP server (#3107 item 5)", async () => {
    const prompts: string[] = [];
    await runWithFinalJsonReprompt(scriptedEngine(editsFile("mcp__other__write_file"), ['{"ok":1}'], prompts), "task", cfg, new CaptureJournal());
    expect(prompts).toEqual([]);
  });

  it("sums both turns' usage into the returned result (#3107 item 2)", async () => {
    const engine: Engine = {
      name: "scripted",
      async run(_t, _c, j) {
        editsFile("write_file")(j);
        return {
          outputJson: "",
          usage: { input_tokens: 10, output_tokens: 3 },
          followUp: async () => ({ outputJson: '{"a":1}', usage: { input_tokens: 5, output_tokens: 2 } }),
        };
      },
    };
    const res = await runWithFinalJsonReprompt(engine, "task", cfg, new CaptureJournal());
    expect(res.usage).toEqual({ input_tokens: 15, output_tokens: 5 });
  });

  it("accepts a non-JSON reply as final: non-empty is the whole test (#3107 item 6)", async () => {
    const res = await runWithFinalJsonReprompt(
      scriptedEngine(editsFile("write_file"), ["Sorry, I changed text/slug.go."]),
      "task",
      cfg,
      new CaptureJournal(),
    );
    expect(res.outputJson).toBe("Sorry, I changed text/slug.go.");
  });

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
