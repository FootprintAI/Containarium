import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Engine } from "./engine.js";

// A categorical failure, never the provider's error body or credential value.
export class CredentialAuthenticationError extends Error {
  constructor() { super("coding-engine authentication failed"); }
}

function authenticationFailure(e: unknown): boolean {
  if (e instanceof CredentialAuthenticationError) return true;
  if (typeof e !== "object" || e === null) return false;
  // Provider SDKs expose 401 as a typed status. Never infer authentication
  // failure from task output, arbitrary error text, 403 permissions or 429.
  return "status" in e && e.status === 401;
}

// Applied at runtime assembly so run, serve and poll all record the same
// outcome. An empty owner-only marker persists across daemon/runtime restarts.
// Only file existence is checked; sign-in/secret values are never read.
export function trackClaudeCredentialState(engine: Engine, home: string): Engine {
  if (engine.name !== "claude") return engine;
  const credential = join(home, ".claude", ".credentials.json");
  const marker = join(home, ".local", "state", "containarium", "claude-auth-failed");
  const record = (failed: boolean): void => {
    try {
      if (failed) {
        if (!existsSync(credential)) return; // API-key path is unchanged.
        mkdirSync(dirname(marker), { recursive: true, mode: 0o700 });
        if (!existsSync(marker)) writeFileSync(marker, "", { mode: 0o600, flag: "wx" });
      } else {
        rmSync(marker, { force: true });
      }
    } catch {
      // State I/O must not change the task outcome or leak error/credential data.
      process.stderr.write("agent-runtime: could not persist credential run state\n");
    }
  };
  return {
    name: engine.name,
    async run(task, cfg, journal) {
      try {
        const result = await engine.run(task, cfg, journal);
        if (result.authenticationSucceeded === true) record(false);
        return result;
      } catch (e) {
        if (authenticationFailure(e)) {
          record(true);
          throw new CredentialAuthenticationError();
        }
        throw e; // Ordinary failures do not recover a failed sign-in.
      }
    },
  };
}
