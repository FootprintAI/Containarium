import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Engine, EngineConfig, EngineResult } from "./engine.js";
import type { JournalEvent } from "./journal.schema.js";

// The per-run journal (#2095): an append-only JSON-lines file per run per
// member box at /var/log/agent-runtime/runs/<run_id>/<skill_id>.jsonl, written
// from each engine's message loop so a client can tail what the agent is
// doing by byte offset while it runs. The line format is journal.schema.ts.
// /var/log/agent-runtime.log is untouched: it stays the process log.

export const JOURNAL_ROOT = "/var/log/agent-runtime/runs";

// MAX_FIELD_BYTES caps tool_use.input and tool_result.text (UTF-8 bytes,
// including the truncation marker).
export const MAX_FIELD_BYTES = 2048;
const TRUNCATION_MARKER = "…";

export const REDACTED = "[REDACTED]";
// Secrets shorter than this are ignored: redacting a one-character value
// would shred every line without protecting anything real.
const MIN_SECRET_LENGTH = 8;

// JournalEntry is what an engine appends; the journal assigns seq and t.
export type JournalEntry = JournalEvent extends infer E ? (E extends JournalEvent ? Omit<E, "seq" | "t"> : never) : never;

export interface JournalSink {
  append(entry: JournalEntry): void;
}

// NULL_JOURNAL discards everything: for paths that are not journaled (poll
// mode, a serve-mode task with no run_id).
export const NULL_JOURNAL: JournalSink = { append: () => {} };

// Same shape the daemon enforces on run ids (resolveRunID); skill ids share
// it. Both become path segments, so nothing that could leave the root.
const ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

function checkId(what: string, id: string): void {
  if (!ID_PATTERN.test(id) || id === "." || id === "..") {
    throw new Error(`journal: invalid ${what} ${JSON.stringify(id)} (want 1-128 of [A-Za-z0-9._-])`);
  }
}

// journalPath is <root>/<run_id>/<skill_id>.jsonl. It throws on an id that is
// not a single safe path segment.
export function journalPath(root: string, runId: string, skillId: string): string {
  checkId("run id", runId);
  checkId("skill id", skillId);
  return join(root, runId, `${skillId}.jsonl`);
}

export function redact(s: string, secrets: readonly string[]): string {
  let out = s;
  for (const secret of secrets) {
    if (out.includes(secret)) out = out.split(secret).join(REDACTED);
  }
  return out;
}

// truncateBytes cuts s to at most max UTF-8 bytes (marker included) without
// splitting a code point.
export function truncateBytes(s: string, max: number): string {
  if (Buffer.byteLength(s, "utf8") <= max) return s;
  const budget = max - Buffer.byteLength(TRUNCATION_MARKER, "utf8");
  let bytes = 0;
  let end = 0;
  for (const ch of s) {
    const n = Buffer.byteLength(ch, "utf8");
    if (bytes + n > budget) break;
    bytes += n;
    end += ch.length;
  }
  return s.slice(0, end) + TRUNCATION_MARKER;
}

// sanitize redacts every string field, then truncates the capped ones.
// Redacting first means a secret straddling the cut cannot leave a prefix.
function sanitize(entry: JournalEntry, secrets: readonly string[]): JournalEntry {
  switch (entry.kind) {
    case "tool_use":
      return { kind: "tool_use", tool: redact(entry.tool, secrets), input: truncateBytes(redact(entry.input, secrets), MAX_FIELD_BYTES) };
    case "tool_result":
      return { kind: "tool_result", tool: redact(entry.tool, secrets), text: truncateBytes(redact(entry.text, secrets), MAX_FIELD_BYTES) };
    case "status":
    case "assistant":
    case "error":
      return { kind: entry.kind, text: redact(entry.text, secrets) };
  }
}

export interface FileJournalOptions {
  root?: string;
  runId: string;
  skillId: string;
  // Literal values that must never appear in a line (see journalSecrets).
  secrets: readonly string[];
  now?: () => Date;
}

// FileJournal appends sanitized events to one journal file. Appends are
// synchronous so lines land in call order and seq is strictly increasing.
export class FileJournal implements JournalSink {
  readonly path: string;
  private seq: number;
  private readonly secrets: readonly string[];
  private readonly now: () => Date;

  private constructor(path: string, seq: number, secrets: readonly string[], now: () => Date) {
    this.path = path;
    this.seq = seq;
    this.secrets = secrets;
    this.now = now;
  }

  // open creates the run directory and resumes seq from any lines already in
  // the file, so a second task of the same run on the same box (or a
  // restarted runtime) keeps seq monotonic within the file.
  static open(opts: FileJournalOptions): FileJournal {
    const path = journalPath(opts.root ?? JOURNAL_ROOT, opts.runId, opts.skillId);
    mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
    let seq = 0;
    if (existsSync(path)) {
      for (const c of readFileSync(path, "utf8")) if (c === "\n") seq++;
    }
    const secrets = opts.secrets.filter((s) => s.length >= MIN_SECRET_LENGTH);
    return new FileJournal(path, seq, secrets, opts.now ?? (() => new Date()));
  }

  append(entry: JournalEntry): void {
    const event = { seq: ++this.seq, t: this.now().toISOString(), ...sanitize(entry, this.secrets) } as JournalEvent;
    try {
      appendFileSync(this.path, JSON.stringify(event) + "\n", { mode: 0o600 });
    } catch (e) {
      // A full disk must not kill the agent mid-run; the process log says why
      // the journal stopped.
      process.stderr.write(`agent-runtime: journal append to ${this.path} failed: ${e instanceof Error ? e.message : String(e)}\n`);
    }
  }
}

const defaultWarn = (m: string): void => {
  process.stderr.write(`agent-runtime: ${m}\n`);
};

// openJournal opens a run's journal under the one policy the runtime applies
// to journal I/O: a journal never kills a run. An id that is not a safe path
// segment still throws (that is a bad request, not an I/O fault); a directory
// or file that cannot be created or read degrades to NULL_JOURNAL with a
// warning on the process log, the same as an append that fails mid-run.
export function openJournal(opts: FileJournalOptions, warn: (msg: string) => void = defaultWarn): JournalSink {
  journalPath(opts.root ?? JOURNAL_ROOT, opts.runId, opts.skillId);
  try {
    return FileJournal.open(opts);
  } catch (e) {
    warn(`journal for run ${opts.runId} could not be opened; not journaled: ${e instanceof Error ? e.message : String(e)}`);
    return NULL_JOURNAL;
  }
}

// The env vars that carry a credential into the box: the model-gateway token
// under each provider's name (the daemon's gatewayProviderEnvs), the provider
// keys a direct-mode box is seeded with, and the per-box A2A credential the
// daemon authenticates to this box's /tasks with (#2125) — which a journal
// served back by TailRunLog must not carry out of the box.
const SECRET_ENV_VARS = [
  "CONTAINARIUM_A2A_TOKEN",
  "CONTAINARIUM_GATEWAY_TOKEN",
  "ANTHROPIC_AUTH_TOKEN",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "CODEX_API_KEY",
] as const;

// journalSecrets lists the literal credential values this runtime holds: the
// seeded gateway token / provider keys from the environment and the seeded
// platform JWT. The git credential a run fetches its repo with is used by
// the daemon for that one fetch and never persisted in the box, so the
// runtime holds no value of it to redact.
export function journalSecrets(env: Readonly<Record<string, string | undefined>>, tokenPath: string | null): string[] {
  const out = new Set<string>();
  for (const name of SECRET_ENV_VARS) {
    const v = env[name]?.trim();
    if (v) out.add(v);
  }
  if (tokenPath && existsSync(tokenPath)) {
    const v = readFileSync(tokenPath, "utf8").trim();
    if (v) out.add(v);
  }
  return [...out];
}

// runJournaled runs one task through the engine bracketed by status lines:
// "run started", then whatever the engine journals, then "run ended exit=N"
// (0 on success; on failure the error is journaled first, exit=1, and the
// error is rethrown).
export async function runJournaled(engine: Engine, task: string, cfg: EngineConfig, journal: JournalSink): Promise<EngineResult> {
  journal.append({ kind: "status", text: "run started" });
  try {
    const res = await engine.run(task, cfg, journal);
    journal.append({ kind: "status", text: "run ended exit=0" });
    return res;
  } catch (e) {
    journal.append({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    journal.append({ kind: "status", text: "run ended exit=1" });
    throw e;
  }
}

export interface ServeJournalOptions {
  root?: string;
  // CONTAINARIUM_SKILL_ID, exported by the daemon when it starts serve mode.
  skillId: string | undefined;
  secrets: readonly string[];
  warn?: (msg: string) => void;
}

// serveJournals returns the per-task journal lookup for serve mode: each A2A
// task names its run (AgentTask.run_id), the box's skill id names the file.
// Tasks of the same run share one FileJournal so seq stays monotonic. A task
// with no run_id (a direct SendAgentTask outside a tracked run), a box
// started without a skill id, or a journal that cannot be opened is not
// journaled; the process log says so. An unsafe run_id throws, which fails
// that task.
export function serveJournals(opts: ServeJournalOptions): (runId: string | undefined) => JournalSink {
  const warn = opts.warn ?? defaultWarn;
  const open = new Map<string, JournalSink>();
  return (runId) => {
    if (!runId) {
      warn("task has no run_id; not journaled");
      return NULL_JOURNAL;
    }
    if (!opts.skillId) {
      warn("CONTAINARIUM_SKILL_ID is not set; task not journaled");
      return NULL_JOURNAL;
    }
    const path = journalPath(opts.root ?? JOURNAL_ROOT, runId, opts.skillId);
    const cached = open.get(path);
    if (cached) return cached;
    const j = openJournal({ root: opts.root, runId, skillId: opts.skillId, secrets: opts.secrets }, warn);
    // Only a journal that opened is kept: a later task of the run retries.
    if (j !== NULL_JOURNAL) open.set(path, j);
    return j;
  };
}
