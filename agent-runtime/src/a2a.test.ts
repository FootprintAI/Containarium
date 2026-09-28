import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runTask } from "./a2a.js";
import type { Engine, EngineConfig } from "./engine.js";
import { serveJournals } from "./journal.js";

const cfg: EngineConfig = { model: "", systemPrompt: "", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 1 };
const engine: Engine = {
  name: "fake",
  async run(task, _cfg, journal) {
    journal.append({ kind: "tool_use", tool: "shell", input: task });
    return { outputJson: "{}" };
  },
};

describe("runTask (serve mode)", () => {
  it("journals a task under the run_id it carries (protojson camelCase or snake_case)", async () => {
    const root = mkdtempSync(join(tmpdir(), "journal-"));
    const journals = serveJournals({ root, skillId: "hello-agent", secrets: [], warn: () => {} });
    const a = await runTask({ id: "t1", inputJson: '{"q":1}', runId: "run-9" }, engine, cfg, journals);
    const b = await runTask({ id: "t2", input_json: '{"q":2}', run_id: "run-9" }, engine, cfg, journals);
    expect(a.state).toBe("AGENT_TASK_STATE_COMPLETED");
    expect(b.state).toBe("AGENT_TASK_STATE_COMPLETED");
    const lines = readFileSync(join(root, "run-9", "hello-agent.jsonl"), "utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as { seq: number; kind: string });
    expect(lines.map((l) => [l.seq, l.kind])).toEqual([
      [1, "status"], [2, "tool_use"], [3, "status"],
      [4, "status"], [5, "tool_use"], [6, "status"],
    ]);
  });

  it("fails the task, not the server, on a run_id that would escape the journal root", async () => {
    const journals = serveJournals({ root: mkdtempSync(join(tmpdir(), "journal-")), skillId: "s", secrets: [], warn: () => {} });
    const art = await runTask({ id: "t", inputJson: "{}", runId: "../../etc" }, engine, cfg, journals);
    expect(art.state).toBe("AGENT_TASK_STATE_FAILED");
    expect(art.error).toMatch(/run id/);
  });

  it("still runs a task without a journal factory (poll mode)", async () => {
    const art = await runTask({ id: "t", inputJson: "{}" }, engine, cfg);
    expect(art.state).toBe("AGENT_TASK_STATE_COMPLETED");
  });
});
