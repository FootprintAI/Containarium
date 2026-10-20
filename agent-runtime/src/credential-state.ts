import type { Engine } from "./engine.js";
import { stateCommand } from "./credential-state-cli.js";
export type AuthenticationSource = "oauth" | "key" | "unknown";
export class CredentialAuthenticationError extends Error {
  constructor(readonly source: AuthenticationSource = "unknown") {
    super("coding-engine authentication failed");
  }
}
export type CredentialStateCommand = (home: string, args: string[]) => unknown;
// Success updates health, never unacknowledged failure episodes. Source is
// supplied by the SDK/launch metadata, never inferred from a credential file.
export function trackClaudeCredentialState(
  engine: Engine,
  home: string,
  command: CredentialStateCommand = stateCommand,
): Engine {
  if (engine.name !== "claude") return engine;
  return {
    name: engine.name,
    async run(task, cfg, journal) {
      let generation: number | undefined;
      try {
        generation = (command(home, ["begin"]) as { generation: number })
          .generation;
      } catch {
        process.stderr.write("agent-runtime: credential state unavailable\n");
      }
      const finish = (source: AuthenticationSource, outcome: string): void => {
        if (generation === undefined) return;
        try {
          command(home, ["finish", String(generation), source, outcome]);
        } catch {
          process.stderr.write(
            "agent-runtime: could not persist credential run state\n",
          );
        }
      };
      try {
        const result = await engine.run(task, cfg, journal);
        finish(
          result.authenticationSource ?? "unknown",
          result.authenticationSucceeded === true ? "success" : "other",
        );
        return result;
      } catch (e) {
        if (e instanceof CredentialAuthenticationError)
          finish(e.source, "failure");
        throw e;
      }
    },
  };
}
