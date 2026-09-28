import { z } from "zod";

// The run journal's line format (#2095): one JSON object per line in
// /var/log/agent-runtime/runs/<run_id>/<skill_id>.jsonl. Exported as a zod
// schema so anything that renders a journal parses it rather than casting.
// Objects are strict: a field the runtime never writes is a malformed line.

const seq = z.number().int().positive();
const t = z.iso.datetime();

export const StatusEventSchema = z.strictObject({ seq, t, kind: z.literal("status"), text: z.string() });
export const AssistantEventSchema = z.strictObject({ seq, t, kind: z.literal("assistant"), text: z.string() });
export const ToolUseEventSchema = z.strictObject({ seq, t, kind: z.literal("tool_use"), tool: z.string(), input: z.string() });
export const ToolResultEventSchema = z.strictObject({ seq, t, kind: z.literal("tool_result"), tool: z.string(), text: z.string() });
export const ErrorEventSchema = z.strictObject({ seq, t, kind: z.literal("error"), text: z.string() });

export const JournalEventSchema = z.discriminatedUnion("kind", [
  StatusEventSchema,
  AssistantEventSchema,
  ToolUseEventSchema,
  ToolResultEventSchema,
  ErrorEventSchema,
]);

export type JournalEvent = z.infer<typeof JournalEventSchema>;
export type JournalKind = JournalEvent["kind"];

// parseJournalLine parses and validates one journal line; it throws on
// anything that is not a well-formed event.
export function parseJournalLine(line: string): JournalEvent {
  return JournalEventSchema.parse(JSON.parse(line));
}

// JOURNAL_FIXTURE_LINES is one line of every kind, exactly as the runtime
// writes them, for downstream renderers' tests. fixtures/journal.jsonl holds
// the same lines for consumers outside this package.
export const JOURNAL_FIXTURE_LINES: readonly string[] = [
  '{"seq":1,"t":"2026-09-28T10:00:00.000Z","kind":"status","text":"run started"}',
  '{"seq":2,"t":"2026-09-28T10:00:01.000Z","kind":"assistant","text":"I will list the repository first."}',
  '{"seq":3,"t":"2026-09-28T10:00:02.000Z","kind":"tool_use","tool":"mcp__agent-box__shell","input":"{\\"command\\":\\"ls\\"}"}',
  '{"seq":4,"t":"2026-09-28T10:00:03.000Z","kind":"tool_result","tool":"mcp__agent-box__shell","text":"README.md\\nsrc\\n"}',
  '{"seq":5,"t":"2026-09-28T10:00:04.000Z","kind":"error","text":"error_max_turns: reached the turn limit"}',
  '{"seq":6,"t":"2026-09-28T10:00:05.000Z","kind":"status","text":"run ended exit=1"}',
];
