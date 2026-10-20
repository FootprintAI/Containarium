import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CredentialAuthenticationError, trackClaudeCredentialState } from "./credential-state.js";
import type { Engine, EngineConfig } from "./engine.js";
import { CaptureJournal } from "./testing/capture.js";

const cfg: EngineConfig = { model: "", systemPrompt: "", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 1 };
const homes: string[] = [];
afterEach(() => { for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true }); });
function fixture(signIn = true) {
  const home = mkdtempSync(join(tmpdir(), "credential-state-")); homes.push(home);
  const credential = join(home, ".claude", ".credentials.json");
  if (signIn) {
    mkdirSync(join(home, ".claude"));
    writeFileSync(credential, '{"accessToken":"FAKE_NEVER_READ","refreshToken":"FAKE_NEVER_READ"}', { mode: 0o600 });
  }
  return { home, credential, marker: join(home, ".local", "state", "containarium", "claude-auth-failed") };
}

describe("credential run state", () => {
  it("persists an empty private failure marker, keeps it on repeated/unrelated failures, and removes it on recovery", async () => {
    const { home, marker, credential } = fixture();
    let failure: unknown = new CredentialAuthenticationError();
    let authenticationSucceeded = true;
    const engine: Engine = { name: "claude", async run() { if (failure) throw failure; return { outputJson: "ok", authenticationSucceeded }; } };
    const run = () => trackClaudeCredentialState(engine, home).run("task", cfg, new CaptureJournal());
    await expect(run()).rejects.toThrow("authentication failed");
    expect(readFileSync(marker, "utf8")).toBe("");
    expect(statSync(marker).mode & 0o777).toBe(0o600);
    expect(statSync(join(home, ".local", "state", "containarium")).mode & 0o777).toBe(0o700);
    // A new wrapper models a new runtime process; no in-memory state is needed.
    await expect(run()).rejects.toThrow("authentication failed");
    failure = new Error("unrelated timeout");
    await expect(run()).rejects.toThrow("unrelated timeout");
    expect(existsSync(marker)).toBe(true);
    failure = null;
    authenticationSucceeded = false;
    await expect(run()).resolves.toEqual({ outputJson: "ok", authenticationSucceeded: false });
    expect(existsSync(marker)).toBe(true);
    authenticationSucceeded = true;
    await expect(run()).resolves.toEqual({ outputJson: "ok", authenticationSucceeded: true });
    expect(existsSync(marker)).toBe(false);
    expect(readFileSync(credential, "utf8")).toBe('{"accessToken":"FAKE_NEVER_READ","refreshToken":"FAKE_NEVER_READ"}');
  });

  it.each([401, 403, 429, 500])("only typed authentication status 401 records failure, not %s otherwise", async status => {
    const { home, marker } = fixture();
    const engine: Engine = { name: "claude", async run() { throw { status, message: "FAKE_PROVIDER_BODY_NEVER_ECHO" }; } };
    const result = trackClaudeCredentialState(engine, home).run("task", cfg, new CaptureJournal());
    if (status === 401) await expect(result).rejects.toThrow("coding-engine authentication failed");
    else await expect(result).rejects.toEqual({ status, message: "FAKE_PROVIDER_BODY_NEVER_ECHO" });
    expect(existsSync(marker)).toBe(status === 401);
  });

  it("does not infer failure from task output or error text", async () => {
    const { home, marker } = fixture();
    const engine: Engine = { name: "claude", async run() { throw new Error("authentication_failed 401"); } };
    await expect(trackClaudeCredentialState(engine, home).run("task", cfg, new CaptureJournal())).rejects.toThrow("401");
    expect(existsSync(marker)).toBe(false);
  });

  it("leaves API-key and other-engine state unchanged", async () => {
    const { home, marker } = fixture(false);
    const engine: Engine = { name: "claude", async run() { throw new CredentialAuthenticationError(); } };
    await expect(trackClaudeCredentialState(engine, home).run("task", cfg, new CaptureJournal())).rejects.toThrow();
    expect(existsSync(marker)).toBe(false);
    const codex = { ...engine, name: "codex" };
    expect(trackClaudeCredentialState(codex, home)).toBe(codex);
  });
});
