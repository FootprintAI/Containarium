import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import {
  CredentialAuthenticationError,
  trackClaudeCredentialState,
} from "./credential-state.js";
import { stateCommand, type Observation } from "./credential-state-cli.js";
import type { Engine, EngineConfig } from "./engine.js";
import { CaptureJournal } from "./testing/capture.js";
const cfg: EngineConfig = {
  model: "",
  systemPrompt: "",
  agentBoxCommand: "fake",
  agentBoxArgs: [],
  maxTurns: 1,
};
const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
});
function fixture() {
  const home = mkdtempSync(join(tmpdir(), "auth-episodes-"));
  homes.push(home);
  mkdirSync(join(home, ".claude"));
  writeFileSync(
    join(home, ".claude", ".credentials.json"),
    '{"accessToken":"FAKE_ONLY","expiresAt":9999999999999}',
  );
  writeFileSync(
    join(home, ".claude", "settings.json"),
    '{"ANTHROPIC_API_KEY":"FAKE_ONLY"}',
  );
  return home;
}
const snapshot = (h: string) => stateCommand(h, ["snapshot"]) as Observation;
const begin = (h: string) =>
  (stateCommand(h, ["begin"]) as { generation: number }).generation;
const finish = (h: string, g: number, source: string, outcome: string) =>
  stateCommand(h, ["finish", String(g), source, outcome]);
describe("durable credential episodes", () => {
  it("retains failure/recovery/failure until acknowledgement and deduplicates repeated failures", async () => {
    const home = fixture();
    let failed = true;
    const engine: Engine = {
      name: "claude",
      async run() {
        if (failed) throw new CredentialAuthenticationError("oauth");
        return {
          outputJson: "ok",
          authenticationSucceeded: true,
          authenticationSource: "oauth",
        };
      },
    };
    const run = () =>
      trackClaudeCredentialState(engine, home).run(
        "task",
        cfg,
        new CaptureJournal(),
      );
    await expect(run()).rejects.toThrow("authentication failed");
    await expect(run()).rejects.toThrow();
    const first = snapshot(home).pending[0].id;
    expect(snapshot(home).pending).toHaveLength(1);
    failed = false;
    await run();
    expect(snapshot(home).active).toBe(false);
    expect(snapshot(home).pending[0].id).toBe(first);
    failed = true;
    await expect(run()).rejects.toThrow();
    expect(snapshot(home).pending).toHaveLength(2);
    expect(snapshot(home).pending[1].afterRecovery).toBe(true);
    stateCommand(home, ["ack", first]);
    expect(snapshot(home).pending).toHaveLength(1);
    const last = snapshot(home).pending[0].id;
    stateCommand(home, ["ack", last]);
    expect(snapshot(home).active).toBe(true);
    expect(snapshot(home).pending).toEqual([]);
    await expect(run()).rejects.toThrow();
    expect(snapshot(home).pending).toEqual([]);
    const statePath = join(
      home,
      ".local",
      "state",
      "containarium",
      "claude-auth-state.json",
    );
    expect(statSync(statePath).mode & 0o777).toBe(0o600);
    expect(readFileSync(statePath, "utf8")).not.toContain("FAKE_ONLY");
  });
  it("an old overlapping success cannot recover a newer failure", async () => {
    const home = fixture();
    let resolve!: (v: {
      outputJson: string;
      authenticationSucceeded: boolean;
      authenticationSource: "oauth";
    }) => void;
    const old = trackClaudeCredentialState(
      {
        name: "claude",
        run: () =>
          new Promise((r) => {
            resolve = r;
          }),
      },
      home,
    ).run("old", cfg, new CaptureJournal());
    await expect(
      trackClaudeCredentialState(
        {
          name: "claude",
          async run() {
            throw new CredentialAuthenticationError("oauth");
          },
        },
        home,
      ).run("new", cfg, new CaptureJournal()),
    ).rejects.toThrow();
    resolve({
      outputJson: "ok",
      authenticationSucceeded: true,
      authenticationSource: "oauth",
    });
    await old;
    expect(snapshot(home).active).toBe(true);
    expect(snapshot(home).pending).toHaveLength(1);
  });
  it("neither API keys nor unknown sources affect OAuth failure/recovery with coexisting files", () => {
    const home = fixture();
    finish(home, begin(home), "oauth", "failure");
    for (const source of ["key", "unknown"]) {
      finish(home, begin(home), source, "success");
      finish(home, begin(home), source, "failure");
    }
    expect(snapshot(home).active).toBe(true);
    expect(snapshot(home).pending).toHaveLength(1);
    finish(home, begin(home), "oauth", "other");
    expect(snapshot(home).active).toBe(true);
    finish(home, begin(home), "oauth", "success");
    expect(snapshot(home).active).toBe(false);
    expect(snapshot(home).pending).toHaveLength(1);
  });
  it("allocates generations safely in separate concurrent processes and survives restart/ack boundaries", async () => {
    const home = fixture();
    const cli = fileURLToPath(
      new URL("../dist/credential-state-cli.js", import.meta.url),
    );
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        promisify(execFile)(process.execPath, [cli, "begin"], {
          env: { HOME: home, PATH: process.env.PATH },
        }),
      ),
    );
    const generations = results
      .map((r) => (JSON.parse(r.stdout) as { generation: number }).generation)
      .sort((a, b) => a - b);
    expect(generations).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    finish(home, 8, "oauth", "failure");
    finish(home, 1, "oauth", "success");
    expect(snapshot(home).active).toBe(true);
    const id = snapshot(home).pending[0].id;
    expect(snapshot(home).pending[0].id).toBe(id); // every command is a new process
    stateCommand(home, ["ack", id]);
    stateCommand(home, ["ack", id]);
    expect(snapshot(home).pending).toEqual([]);
    expect(snapshot(home).active).toBe(true);
  });
  it("does not touch other engines or credential values", () => {
    const home = fixture();
    const engine: Engine = {
      name: "codex",
      async run() {
        return { outputJson: "ok" };
      },
    };
    expect(trackClaudeCredentialState(engine, home)).toBe(engine);
    expect(existsSync(join(home, ".local"))).toBe(false);
  });
});
it("preserves late failure evidence without undoing a newer successful run", () => {
  const home = fixture(),
    older = begin(home),
    newer = begin(home);
  finish(home, newer, "oauth", "success");
  finish(home, older, "oauth", "failure");
  expect(snapshot(home).active).toBe(false);
  expect(snapshot(home).pending).toHaveLength(1);
  finish(home, older, "oauth", "failure");
  expect(snapshot(home).pending).toHaveLength(1);
});

it("supports installed launchers pointing through a versioned-directory symlink", async () => {
  const home = fixture();
  const link = join(home, "state-helper.js");
  symlinkSync(
    fileURLToPath(new URL("../dist/credential-state-cli.js", import.meta.url)),
    link,
  );
  const result = await promisify(execFile)(
    process.execPath,
    [link, "snapshot"],
    { env: { HOME: home, PATH: process.env.PATH } },
  );
  expect(JSON.parse(result.stdout)).toEqual({
    version: 1,
    active: false,
    pending: [],
  });
});
