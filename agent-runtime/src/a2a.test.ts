import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createA2AServer, runTask, type A2AServerOptions } from "./a2a.js";
import type { Engine, EngineConfig } from "./engine.js";
import { serveJournals } from "./journal.js";
import type { Seed } from "./seed.js";

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

// POST /tasks is a daemon-only endpoint (#2125, decision D1 in
// docs/architecture/execution-scoped-authorization.md). The daemon presents the
// per-box secret it derived for THIS box; anyone else — including a peer box
// that can reach port 8674 — is refused before the body is parsed, before the
// engine runs, and before any journal line exists.
const BOX_SECRET = "2a4f6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a";

const seed: Seed = {
  systemPrompt: "",
  inputJson: "{}",
  agentCard: { name: "hello-agent" },
  tokenPath: null,
  platformMcp: null,
  outputSchema: null,
};

interface Harness {
  url: string;
  journalRoot: string;
  engineCalls: () => number;
  close: () => Promise<void>;
}

const openHarnesses: Harness[] = [];

function startHarness(expectedToken: string): Promise<Harness> {
  let calls = 0;
  const countingEngine: Engine = {
    name: "counting",
    async run(task, _c, journal) {
      calls++;
      journal.append({ kind: "tool_use", tool: "shell", input: task });
      return { outputJson: '{"ok":true}' };
    },
  };
  const journalRoot = mkdtempSync(join(tmpdir(), "journal-a2a-"));
  const opts: A2AServerOptions = {
    seed,
    engine: countingEngine,
    cfg,
    journals: serveJournals({ root: journalRoot, skillId: "hello-agent", secrets: [], warn: () => {} }),
    expectedToken,
    warn: () => {},
  };
  const server = createA2AServer(opts);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      const h: Harness = {
        url: `http://127.0.0.1:${port}`,
        journalRoot,
        engineCalls: () => calls,
        close: () => new Promise((done) => { server.close(() => { done(); }); }),
      };
      openHarnesses.push(h);
      resolve(h);
    });
  });
}

afterEach(async () => {
  await Promise.all(openHarnesses.splice(0).map((h) => h.close()));
});

function postTask(url: string, headers: Record<string, string>, runId = "run-victim"): Promise<Response> {
  return fetch(`${url}/tasks`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ id: "t1", inputJson: '{"q":"hi"}', runId }),
  });
}

describe("POST /tasks authentication (#2125)", () => {
  it("accepts a task carrying the box's own secret (the daemon's crew hop)", async () => {
    const h = await startHarness(BOX_SECRET);
    const res = await postTask(h.url, { authorization: `Bearer ${BOX_SECRET}` }, "run-9");
    expect(res.status).toBe(200);
    const art = (await res.json()) as { state: string; outputJson: string };
    expect(art.state).toBe("AGENT_TASK_STATE_COMPLETED");
    expect(art.outputJson).toBe('{"ok":true}');
    expect(h.engineCalls()).toBe(1);
    expect(existsSync(join(h.journalRoot, "run-9", "hello-agent.jsonl"))).toBe(true);
  });

  it("accepts a lowercase bearer scheme (RFC 7235: the scheme is case-insensitive)", async () => {
    const h = await startHarness(BOX_SECRET);
    const res = await postTask(h.url, { authorization: `bearer ${BOX_SECRET}` }, "run-9");
    expect(res.status).toBe(200);
    expect(h.engineCalls()).toBe(1);
  });

  const refusals: { name: string; headers: Record<string, string>; want: number; seeded?: string }[] = [
    { name: "a peer box's own secret (a differing credential)", headers: { authorization: "Bearer 9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0" }, want: 403 },
    { name: "a token of the right length but one byte off", headers: { authorization: `Bearer ${BOX_SECRET.slice(0, -1)}b` }, want: 403 },
    { name: "a prefix of the real secret", headers: { authorization: `Bearer ${BOX_SECRET.slice(0, 16)}` }, want: 403 },
    { name: "no Authorization header at all", headers: {}, want: 401 },
    { name: "an empty Authorization header", headers: { authorization: "" }, want: 401 },
    { name: "a bare Bearer with no token", headers: { authorization: "Bearer" }, want: 401 },
    { name: "a Bearer with an empty token", headers: { authorization: "Bearer " }, want: 401 },
    { name: "a non-Bearer scheme", headers: { authorization: `Basic ${BOX_SECRET}` }, want: 401 },
    { name: "the secret with no scheme", headers: { authorization: BOX_SECRET }, want: 401 },
    // Fail closed: a box the daemon never seeded a secret to serves nothing,
    // rather than accepting everything.
    { name: "any credential when the box was seeded no secret", headers: { authorization: `Bearer ${BOX_SECRET}` }, want: 401, seeded: "" },
  ];

  for (const c of refusals) {
    it(`refuses ${c.name} with ${c.want}, before the engine or the journal`, async () => {
      const h = await startHarness(c.seeded ?? BOX_SECRET);
      const res = await postTask(h.url, c.headers);
      expect(res.status).toBe(c.want);
      const art = (await res.json()) as { state: string; error: string };
      expect(art.state).toBe("AGENT_TASK_STATE_FAILED");
      expect(art.error).not.toBe("");
      // The refusal is the whole point: no engine invocation, and NO journal
      // line under the run_id the caller named (#2125's acceptance criterion).
      expect(h.engineCalls()).toBe(0);
      expect(readdirSync(h.journalRoot)).toEqual([]);
    });
  }

  it("never echoes the expected secret in a refusal", async () => {
    const h = await startHarness(BOX_SECRET);
    const res = await postTask(h.url, { authorization: "Bearer nope" });
    expect(await res.text()).not.toContain(BOX_SECRET);
  });

  it("serves the agent card unauthenticated (discovery, no engine, no journal)", async () => {
    const h = await startHarness(BOX_SECRET);
    const res = await fetch(`${h.url}/agent-card`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ name: "hello-agent" });
    expect(h.engineCalls()).toBe(0);
    expect(readdirSync(h.journalRoot)).toEqual([]);
  });

  it("still 404s an unknown path for an authenticated caller", async () => {
    const h = await startHarness(BOX_SECRET);
    const res = await fetch(`${h.url}/nope`, { headers: { authorization: `Bearer ${BOX_SECRET}` } });
    expect(res.status).toBe(404);
  });
});
