import { writeArtifact } from "./artifact.js";
import type { Engine, EngineConfig } from "./engine.js";
import { FileJournal, JOURNAL_ROOT, journalSecrets, runJournaled } from "./journal.js";

export interface RunOnceOptions {
  env: Readonly<Record<string, string | undefined>>;
  seedDir: string;
  inputJson: string;
  // The seeded platform JWT, redacted from the journal.
  tokenPath: string | null;
  engine: Engine;
  cfg: EngineConfig;
  model: string;
  journalRoot?: string;
}

// runOnce is run mode: journal the run, run the task once, write
// artifact.json, and return the process exit code. The daemon exports
// CONTAINARIUM_RUN_ID and CONTAINARIUM_SKILL_ID in the exec prefix; without
// them there is no journal path, and that is a hard failure (exit 2, the
// reason in artifact.json and on stderr) rather than a silent run with no
// journal.
export async function runOnce(o: RunOnceOptions): Promise<number> {
  const { engine, model } = o;
  let journal: FileJournal;
  try {
    const runId = o.env.CONTAINARIUM_RUN_ID;
    const skillId = o.env.CONTAINARIUM_SKILL_ID;
    if (!runId) throw new Error("CONTAINARIUM_RUN_ID is not set; run mode needs it to journal the run");
    if (!skillId) throw new Error("CONTAINARIUM_SKILL_ID is not set; run mode needs it to journal the run");
    journal = FileJournal.open({
      root: o.journalRoot ?? JOURNAL_ROOT,
      runId,
      skillId,
      secrets: journalSecrets(o.env, o.tokenPath),
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    writeArtifact(o.seedDir, { outputJson: "", engine: engine.name, model, error: msg });
    process.stderr.write(`agent-runtime: ${msg}\n`);
    return 2;
  }

  try {
    const res = await runJournaled(engine, o.inputJson, o.cfg, journal);
    writeArtifact(o.seedDir, { outputJson: res.outputJson, engine: engine.name, model, usage: res.usage });
    process.stdout.write(`agent-runtime: ${engine.name} run complete\n`);
    return 0;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    writeArtifact(o.seedDir, { outputJson: "", engine: engine.name, model, error: msg });
    process.stderr.write(`agent-runtime: ${engine.name} run failed: ${msg}\n`);
    return 1;
  }
}
