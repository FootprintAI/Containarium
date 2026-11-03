import type { JournalEntry, JournalSink } from "./journal.js";

// tests_run (#3491): a skill artifact's "did this box execute a test command"
// field is set by the runtime from what it observed during the run, not taken
// from the model's own report.
//
// What counts as observed: the box's test runners, agent-test and
// `agent-python test` (agent-runtime/helpers), print
//   <helper>: test command executed: exit=N
// on stderr once the command has run, and that line comes back to the engine
// in a tool result (shell_exec's stderr section, or Codex's aggregated
// command output). A helper error ("test command not found", no venv) prints
// no such line, because nothing ran. The test's own pass/fail does not matter:
// a failing suite still executed.
//
// This is a guard against a mistaken self-report, not an attestation. Anything
// in the box, the model included, can print that line; the platform's own
// evidence that tests ran and passed is the Proof Pack (docs/PROOF-PACK.md),
// which never reads tests_run.

// The report line, at the start of a line in the raw text or after an escaped
// newline in JSON-encoded text (the Gemini engine journals a function
// response as JSON). Digits are required, so the helpers' own source
// ("exit=${rc}") and documentation ("exit=N") never match.
const REPORT = /(?:^|\n|\\n)(?:agent-test|agent-python): test command executed: exit=(-?\d+)/g;

export interface TestExecution {
  exit: number;
}

// TestRunWatch passes every entry through to the journal and records each
// test-command execution reported in a tool result.
export class TestRunWatch implements JournalSink {
  readonly executions: TestExecution[] = [];
  constructor(private readonly journal: JournalSink) {}

  get observed(): boolean {
    return this.executions.length > 0;
  }

  append(entry: JournalEntry): void {
    if (entry.kind === "tool_result") {
      for (const m of entry.text.matchAll(REPORT)) this.executions.push({ exit: Number(m[1]) });
    }
    this.journal.append(entry);
  }
}

export interface Reconciled {
  outputJson: string;
  // The value the agent reported, when the runtime replaced it; absent when
  // the output was left as it was.
  reported?: unknown;
}

function asObject(json: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(json);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// reconcileTestsRun sets the output's top-level tests_run to observed. It
// leaves the output alone when it is not a JSON object with a tests_run key,
// when tests_run already equals observed (the original bytes are kept), and
// when the task input itself carries a top-level tests_run: that is a value
// passed through from a peer (diff-reviewer relays the implementer's), whose
// own box already reconciled it, not a claim about this box.
export function reconcileTestsRun(outputJson: string, inputJson: string, observed: boolean): Reconciled {
  const out = asObject(outputJson);
  if (!out || !Object.hasOwn(out, "tests_run")) return { outputJson };
  const input = asObject(inputJson);
  if (input && Object.hasOwn(input, "tests_run")) return { outputJson };
  const reported = out.tests_run;
  if (reported === observed) return { outputJson };
  return { outputJson: JSON.stringify({ ...out, tests_run: observed }), reported };
}

// correctionText is the journal status line for a replaced tests_run.
export function correctionText(observed: boolean, executions: number, reported: unknown): string {
  return observed
    ? `tests_run set to true: ${executions} test command execution(s) observed in this run (the agent reported ${JSON.stringify(reported)})`
    : `tests_run set to false: no test command execution was observed in this run (the agent reported ${JSON.stringify(reported)}); run tests through agent-test or agent-python test`;
}
