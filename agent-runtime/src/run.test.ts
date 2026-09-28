import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Engine, EngineConfig } from "./engine.js";
import { runOnce } from "./run.js";

const cfg: EngineConfig = { model: "", systemPrompt: "", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 1 };

function dirs(): { seedDir: string; root: string } {
  return { seedDir: mkdtempSync(join(tmpdir(), "seed-")), root: mkdtempSync(join(tmpdir(), "journal-")) };
}

const okEngine: Engine = {
  name: "fake",
  async run(_task, _cfg, journal) {
    journal.append({ kind: "assistant", text: "hello" });
    return { outputJson: '{"ok":true}' };
  },
};

function artifact(seedDir: string): { outputJson: string; error?: string } {
  return JSON.parse(readFileSync(join(seedDir, "artifact.json"), "utf8")) as { outputJson: string; error?: string };
}

describe("runOnce (run mode)", () => {
  it("journals the run under <root>/<CONTAINARIUM_RUN_ID>/<CONTAINARIUM_SKILL_ID>.jsonl", async () => {
    const { seedDir, root } = dirs();
    const code = await runOnce({
      env: { CONTAINARIUM_RUN_ID: "run-1", CONTAINARIUM_SKILL_ID: "hello-agent" },
      seedDir, inputJson: "{}", tokenPath: null, engine: okEngine, cfg, model: "m", journalRoot: root,
    });
    expect(code).toBe(0);
    expect(artifact(seedDir).outputJson).toBe('{"ok":true}');
    const lines = readFileSync(join(root, "run-1", "hello-agent.jsonl"), "utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as { seq: number; kind: string; text: string });
    expect(lines.map((l) => [l.seq, l.kind, l.text])).toEqual([
      [1, "status", "run started"],
      [2, "assistant", "hello"],
      [3, "status", "run ended exit=0"],
    ]);
  });

  it("ends the journal exit=1 and writes the error artifact when the engine fails", async () => {
    const { seedDir, root } = dirs();
    const failing: Engine = { name: "fake", run: async () => { throw new Error("boom"); } };
    const code = await runOnce({
      env: { CONTAINARIUM_RUN_ID: "run-2", CONTAINARIUM_SKILL_ID: "s" },
      seedDir, inputJson: "{}", tokenPath: null, engine: failing, cfg, model: "m", journalRoot: root,
    });
    expect(code).toBe(1);
    expect(artifact(seedDir).error).toBe("boom");
    expect(readFileSync(join(root, "run-2", "s.jsonl"), "utf8")).toContain('"text":"run ended exit=1"');
  });

  it.each([
    ["CONTAINARIUM_RUN_ID missing", { CONTAINARIUM_SKILL_ID: "s" }, /CONTAINARIUM_RUN_ID/],
    ["CONTAINARIUM_RUN_ID empty", { CONTAINARIUM_RUN_ID: "", CONTAINARIUM_SKILL_ID: "s" }, /CONTAINARIUM_RUN_ID/],
    ["CONTAINARIUM_SKILL_ID missing", { CONTAINARIUM_RUN_ID: "run-3" }, /CONTAINARIUM_SKILL_ID/],
    ["CONTAINARIUM_RUN_ID unsafe", { CONTAINARIUM_RUN_ID: "../x", CONTAINARIUM_SKILL_ID: "s" }, /run id/],
  ])("hard-fails without running the engine when %s", async (_name, env, want) => {
    const { seedDir, root } = dirs();
    let ran = false;
    const spy: Engine = { name: "fake", run: async () => { ran = true; return { outputJson: "{}" }; } };
    const code = await runOnce({ env, seedDir, inputJson: "{}", tokenPath: null, engine: spy, cfg, model: "m", journalRoot: root });
    expect(code).not.toBe(0);
    expect(ran).toBe(false);
    expect(artifact(seedDir).error).toMatch(want);
    expect(existsSync(join(root, "run-3"))).toBe(false);
  });
});
