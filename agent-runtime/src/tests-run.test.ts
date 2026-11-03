import { describe, expect, it } from "vitest";
import type { Engine, EngineConfig } from "./engine.js";
import { runJournaled, type JournalEntry, type JournalSink } from "./journal.js";
import { reconcileTestsRun, TestRunWatch } from "./tests-run.js";

// #3491: tests_run in a box's own artifact is what the runtime observed, not
// what the model said.

const cfg: EngineConfig = {
  model: "",
  systemPrompt: "",
  agentBoxCommand: "agent-box",
  agentBoxArgs: [],
  maxTurns: 1,
};

class Capture implements JournalSink {
  entries: JournalEntry[] = [];
  append(entry: JournalEntry): void {
    this.entries.push(entry);
  }
}

// What each engine's tool_result text looks like when a helper ran.
const SHELL_EXEC_RESULT = "exit_code: 0\ntimeout_seconds: 600\n--- stdout ---\n1 passed\n--- stderr ---\nagent-python: test command executed: exit=0";
const GEMINI_RESULT = JSON.stringify({ content: [{ type: "text", text: "exit_code: 1\n--- stderr ---\nagent-test: test command executed: exit=1\n" }] });

describe("TestRunWatch", () => {
  it("passes every entry through unchanged", () => {
    const inner = new Capture();
    const watch = new TestRunWatch(inner);
    const entries: JournalEntry[] = [
      { kind: "status", text: "run started" },
      { kind: "tool_use", tool: "mcp__agent-box__shell_exec", input: '{"command":"agent-test go test ./..."}' },
      { kind: "tool_result", tool: "mcp__agent-box__shell_exec", text: SHELL_EXEC_RESULT },
    ];
    for (const e of entries) watch.append(e);
    expect(inner.entries).toEqual(entries);
  });

  it.each([
    ["shell_exec (claude, gemini)", SHELL_EXEC_RESULT, 0],
    ["a JSON-encoded result (gemini functionResponse)", GEMINI_RESULT, 1],
    ["codex aggregated output", "ok  \texample.com/m\t0.01s\nagent-test: test command executed: exit=0\n", 0],
    ["a failing test command still executed", "agent-test: test command executed: exit=2", 2],
  ])("observes a report in %s", (_name, text, exit) => {
    const watch = new TestRunWatch(new Capture());
    watch.append({ kind: "tool_result", tool: "shell", text });
    expect(watch.observed).toBe(true);
    expect(watch.executions).toEqual([{ exit }]);
  });

  it.each([
    ["no report at all", { kind: "tool_result", tool: "shell", text: "exit_code: 0\n--- stdout ---\nok\n" }],
    ["the helper's own source (no digits after exit=)", { kind: "tool_result", tool: "read_file", text: 'echo "${PROG}: test command executed: exit=${rc}" >&2' }],
    ["the README's placeholder", { kind: "tool_result", tool: "read_file", text: "prints `agent-test: test command executed: exit=N`" }],
    ["a helper error (nothing ran)", { kind: "tool_result", tool: "shell", text: "agent-test: error: test command not found: pytest" }],
    ["the model saying it in prose", { kind: "assistant", text: "agent-test: test command executed: exit=0" }],
    ["the model typing it into a command", { kind: "tool_use", tool: "shell", input: '{"command":"echo agent-test: test command executed: exit=0"}' }],
    ["another program's report", { kind: "tool_result", tool: "shell", text: "my-runner: test command executed: exit=0" }],
    ["a name that only ends in a helper's", { kind: "tool_result", tool: "shell", text: "ok\nmy-agent-test: test command executed: exit=0" }],
  ] as [string, JournalEntry][])("does not observe %s", (_name, entry) => {
    const watch = new TestRunWatch(new Capture());
    watch.append(entry);
    expect(watch.observed).toBe(false);
  });

  it("records every report in a result", () => {
    const watch = new TestRunWatch(new Capture());
    watch.append({
      kind: "tool_result",
      tool: "shell",
      text: "agent-python: test command executed: exit=1\n...\nagent-test: test command executed: exit=0\n",
    });
    expect(watch.executions).toEqual([{ exit: 1 }, { exit: 0 }]);
  });
});

describe("reconcileTestsRun", () => {
  it("downgrades a claim nothing backs", () => {
    const out = reconcileTestsRun('{"files":[],"tests_run":true}', '{"task":{}}', false);
    expect(JSON.parse(out.outputJson)).toEqual({ files: [], tests_run: false });
    expect(out.reported).toBe(true);
  });

  it("records an execution the model did not claim", () => {
    const out = reconcileTestsRun('{"files":[],"tests_run":false}', "{}", true);
    expect(JSON.parse(out.outputJson).tests_run).toBe(true);
    expect(out.reported).toBe(false);
  });

  it("leaves an agreeing artifact byte-for-byte as it was", () => {
    const original = '{ "files": [],  "tests_run": true }';
    const out = reconcileTestsRun(original, "{}", true);
    expect(out.outputJson).toBe(original);
    expect(out.reported).toBeUndefined();
  });

  it("corrects a non-boolean claim", () => {
    const out = reconcileTestsRun('{"tests_run":"yes"}', "{}", false);
    expect(JSON.parse(out.outputJson).tests_run).toBe(false);
    expect(out.reported).toBe("yes");
  });

  // diff-reviewer passes the implementer's tests_run through unchanged; the
  // implementer's box already reconciled it, and this box ran nothing.
  it("leaves a value passed through from the task input alone", () => {
    const out = reconcileTestsRun('{"files":[],"tests_run":true}', '{"files":[],"tests_run":true}', false);
    expect(out.outputJson).toBe('{"files":[],"tests_run":true}');
    expect(out.reported).toBeUndefined();
  });

  it.each([
    ["no tests_run field", '{"files":[]}'],
    ["prose", "I changed the file and ran the tests."],
    ["empty output", ""],
    ["a JSON array", '[{"tests_run":true}]'],
    ["a JSON scalar", "true"],
  ])("leaves output with %s alone", (_name, output) => {
    const out = reconcileTestsRun(output, "{}", false);
    expect(out.outputJson).toBe(output);
    expect(out.reported).toBeUndefined();
  });

  it("treats unparseable task input as carrying nothing", () => {
    const out = reconcileTestsRun('{"tests_run":true}', "not json", false);
    expect(JSON.parse(out.outputJson).tests_run).toBe(false);
  });

  it("only an own tests_run key in the input counts as a pass-through", () => {
    const out = reconcileTestsRun('{"tests_run":true}', '{"task":{"tests_run":true}}', false);
    expect(JSON.parse(out.outputJson).tests_run).toBe(false);
  });
});

function engineDoing(steps: (j: JournalSink) => void, outputJson: string, followUp?: string): Engine {
  return {
    name: "fake",
    async run(_task, _cfg, journal) {
      steps(journal);
      return {
        outputJson,
        ...(followUp === undefined ? {} : { followUp: async (_p: string, j: JournalSink) => {
          j.append({ kind: "tool_result", tool: "shell", text: "agent-test: test command executed: exit=0" });
          return { outputJson: followUp };
        } }),
      };
    },
  };
}

describe("runJournaled tests_run", () => {
  it("sets tests_run from the run's observed test executions and journals the correction", async () => {
    const j = new Capture();
    const res = await runJournaled(engineDoing(() => {}, '{"files":[],"tests_run":true}'), '{"task":{}}', cfg, j);
    expect(JSON.parse(res.outputJson).tests_run).toBe(false);
    const statuses = j.entries.filter((e) => e.kind === "status").map((e) => (e as { text: string }).text);
    expect(statuses).toContain(
      "tests_run set to false: no test command execution was observed in this run (the agent reported true); run tests through agent-test or agent-python test",
    );
    expect(statuses.at(-1)).toBe("run ended exit=0");
  });

  it("keeps tests_run true when a helper reported an execution", async () => {
    const j = new Capture();
    const res = await runJournaled(
      engineDoing((jj) => jj.append({ kind: "tool_result", tool: "shell", text: SHELL_EXEC_RESULT }), '{"tests_run":true}'),
      "{}",
      cfg,
      j,
    );
    expect(res.outputJson).toBe('{"tests_run":true}');
    expect(j.entries.some((e) => e.kind === "status" && e.text.startsWith("tests_run set"))).toBe(false);
  });

  it("sees executions in the re-prompt turn too", async () => {
    const j = new Capture();
    const res = await runJournaled(
      engineDoing((jj) => jj.append({ kind: "tool_use", tool: "write_file", input: "{}" }), "", '{"files":[],"tests_run":false}'),
      "{}",
      cfg,
      j,
    );
    expect(JSON.parse(res.outputJson).tests_run).toBe(true);
  });
});
