import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Engine, EngineConfig } from "./engine.js";
import {
  FileJournal,
  JOURNAL_ROOT,
  MAX_FIELD_BYTES,
  REDACTED,
  journalPath,
  journalSecrets,
  runJournaled,
  serveJournals,
  type JournalEntry,
  type JournalSink,
} from "./journal.js";
import { JOURNAL_FIXTURE_LINES, JournalEventSchema, parseJournalLine } from "./journal.schema.js";

const cfg: EngineConfig = { model: "", systemPrompt: "", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 1 };

function tmpRoot(): string {
  return mkdtempSync(join(tmpdir(), "journal-"));
}

function readLines(path: string): unknown[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l !== "")
    .map((l) => JSON.parse(l) as unknown);
}

function fixedClock(): () => Date {
  let ms = Date.parse("2026-09-28T10:00:00.000Z");
  return () => new Date((ms += 1000));
}

describe("journalPath", () => {
  it("is <root>/<run_id>/<skill_id>.jsonl under /var/log/agent-runtime/runs", () => {
    expect(JOURNAL_ROOT).toBe("/var/log/agent-runtime/runs");
    expect(journalPath(JOURNAL_ROOT, "run-1", "hello-agent")).toBe("/var/log/agent-runtime/runs/run-1/hello-agent.jsonl");
  });

  it.each([
    ["run id with a slash", "../etc", "hello-agent"],
    ["dot-dot run id", "..", "hello-agent"],
    ["empty run id", "", "hello-agent"],
    ["skill id with a slash", "run-1", "a/b"],
    ["empty skill id", "run-1", ""],
  ])("rejects %s", (_name, runId, skillId) => {
    expect(() => journalPath("/r", runId, skillId)).toThrow();
  });
});

describe("FileJournal", () => {
  it("appends one typed line per event with seq monotonic from 1 and an ISO timestamp", () => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "run-1", skillId: "hello-agent", secrets: [], now: fixedClock() });
    j.append({ kind: "status", text: "run started" });
    j.append({ kind: "assistant", text: "hi" });
    j.append({ kind: "tool_use", tool: "shell", input: '{"cmd":"ls"}' });
    j.append({ kind: "tool_result", tool: "shell", text: "a b" });
    j.append({ kind: "error", text: "boom" });
    j.append({ kind: "status", text: "run ended exit=1" });

    const lines = readLines(join(root, "run-1", "hello-agent.jsonl"));
    expect(lines).toEqual([
      { seq: 1, t: "2026-09-28T10:00:01.000Z", kind: "status", text: "run started" },
      { seq: 2, t: "2026-09-28T10:00:02.000Z", kind: "assistant", text: "hi" },
      { seq: 3, t: "2026-09-28T10:00:03.000Z", kind: "tool_use", tool: "shell", input: '{"cmd":"ls"}' },
      { seq: 4, t: "2026-09-28T10:00:04.000Z", kind: "tool_result", tool: "shell", text: "a b" },
      { seq: 5, t: "2026-09-28T10:00:05.000Z", kind: "error", text: "boom" },
      { seq: 6, t: "2026-09-28T10:00:06.000Z", kind: "status", text: "run ended exit=1" },
    ]);
    for (const l of lines) expect(JournalEventSchema.parse(l)).toEqual(l);
  });

  it("is owner-only (it can echo task content)", () => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: [] });
    j.append({ kind: "status", text: "run started" });
    expect(statSync(j.path).mode & 0o777).toBe(0o600);
  });

  it("resumes seq when the file already has lines, so seq stays monotonic per file", () => {
    const root = tmpRoot();
    const a = FileJournal.open({ root, runId: "r", skillId: "s", secrets: [] });
    a.append({ kind: "status", text: "run started" });
    a.append({ kind: "status", text: "run ended exit=0" });
    const b = FileJournal.open({ root, runId: "r", skillId: "s", secrets: [] });
    b.append({ kind: "status", text: "run started" });
    expect(readLines(a.path).map((l) => (l as { seq: number }).seq)).toEqual([1, 2, 3]);
  });

  it("truncates tool_use.input and tool_result.text at 2 KiB", () => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: [] });
    const big = "x".repeat(5000);
    const multibyte = "é".repeat(3000); // 2 bytes each: 6000 bytes
    j.append({ kind: "tool_use", tool: "shell", input: big });
    j.append({ kind: "tool_result", tool: "shell", text: big });
    j.append({ kind: "tool_result", tool: "shell", text: multibyte });
    j.append({ kind: "tool_use", tool: "shell", input: "x".repeat(MAX_FIELD_BYTES) }); // exactly at the cap
    const [use, result, mb, exact] = readLines(j.path) as Array<{ input?: string; text?: string }>;
    for (const v of [use!.input!, result!.text!, mb!.text!]) {
      expect(Buffer.byteLength(v, "utf8")).toBeLessThanOrEqual(MAX_FIELD_BYTES);
      expect(v.endsWith("…")).toBe(true);
    }
    expect(mb!.text!.includes("�")).toBe(false); // never splits a code point
    expect(exact!.input).toBe("x".repeat(MAX_FIELD_BYTES));
  });

  it("does not truncate assistant, status or error text", () => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: [] });
    const big = "y".repeat(5000);
    j.append({ kind: "assistant", text: big });
    j.append({ kind: "error", text: big });
    for (const l of readLines(j.path) as Array<{ text: string }>) expect(l.text).toBe(big);
  });

  // Secrets × event kinds: the seeded gateway token, the platform JWT and a
  // git credential never appear in any journal line, in any field.
  const secrets = {
    "gateway token": "gw.eyJhbGciOiJIUzI1NiJ9.gatewaytokenpayload.sig",
    "platform JWT": "eyJhbGciOiJSUzI1NiJ9.platformjwtpayload.signature",
    "git credential": "ghp_0123456789abcdefghijABCDEFGHIJ012345",
  } as const;
  const kinds: Array<[string, (s: string) => JournalEntry]> = [
    ["status", (s) => ({ kind: "status", text: `run started ${s}` })],
    ["assistant", (s) => ({ kind: "assistant", text: `token is ${s}.` })],
    ["tool_use input", (s) => ({ kind: "tool_use", tool: "shell", input: JSON.stringify({ cmd: `curl -H 'Authorization: Bearer ${s}'` }) })],
    ["tool_use tool", (s) => ({ kind: "tool_use", tool: s, input: "{}" })],
    ["tool_result", (s) => ({ kind: "tool_result", tool: "shell", text: `GATEWAY=${s}\n` })],
    ["tool_result past the cap", (s) => ({ kind: "tool_result", tool: "shell", text: "z".repeat(MAX_FIELD_BYTES - 10) + s })],
    ["error", (s) => ({ kind: "error", text: `401 for ${s}` })],
  ];
  const cases = Object.entries(secrets).flatMap(([secretName, secret]) =>
    kinds.map(([kind, make]) => [secretName, kind, secret, make] as const),
  );
  it.each(cases)("redacts the %s from %s", (_secretName, _kind, secret, make) => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: Object.values(secrets) });
    j.append(make(secret));
    const raw = readFileSync(j.path, "utf8");
    expect(raw).not.toContain(secret);
    expect(JournalEventSchema.parse(JSON.parse(raw))).toBeTruthy();
  });

  // Redaction must run before truncation: truncating first would cut the
  // secret at the cap, leave its first bytes in the line, and the remaining
  // fragment would no longer match the secret to redact.
  it.each(Object.entries(secrets))("redacts the %s before truncating, leaving no byte of it at the cut", (_name, secret) => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: Object.values(secrets) });
    const pad = "z".repeat(MAX_FIELD_BYTES - REDACTED.length);
    j.append({ kind: "tool_result", tool: "shell", text: pad + secret });
    j.append({ kind: "tool_use", tool: "shell", input: pad + secret });
    const [result, use] = readLines(j.path) as Array<{ text?: string; input?: string }>;
    expect(result!.text).toBe(pad + REDACTED);
    expect(use!.input).toBe(pad + REDACTED);
    expect(readFileSync(j.path, "utf8")).not.toContain(secret.slice(0, 4));
  });

  it("redacts every occurrence and marks it", () => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: ["s3cr3t-value-1234"] });
    j.append({ kind: "assistant", text: "a s3cr3t-value-1234 b s3cr3t-value-1234" });
    expect(readLines(j.path)[0]).toMatchObject({ text: `a ${REDACTED} b ${REDACTED}` });
  });

  it("ignores empty and trivially short secrets instead of redacting everything", () => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: ["", "x"] });
    j.append({ kind: "assistant", text: "xyz" });
    expect(readLines(j.path)[0]).toMatchObject({ text: "xyz" });
  });
});

describe("journalSecrets", () => {
  it("collects the gateway token vars, provider keys and the seeded platform JWT", () => {
    const dir = tmpRoot();
    const tokenPath = join(dir, "token");
    writeFileSync(tokenPath, "platform-jwt-value-abc\n");
    const got = journalSecrets(
      {
        CONTAINARIUM_GATEWAY_TOKEN: "gw-gemini-token-1",
        ANTHROPIC_AUTH_TOKEN: "gw-anthropic-token-1",
        OPENAI_API_KEY: "gw-openai-token-1",
        ANTHROPIC_API_KEY: "direct-anthropic-key",
        GEMINI_API_KEY: "direct-gemini-key",
        GOOGLE_API_KEY: "direct-google-key",
        CODEX_API_KEY: "direct-codex-key",
        PATH: "/usr/bin",
      },
      tokenPath,
    );
    expect(new Set(got)).toEqual(
      new Set([
        "gw-gemini-token-1",
        "gw-anthropic-token-1",
        "gw-openai-token-1",
        "direct-anthropic-key",
        "direct-gemini-key",
        "direct-google-key",
        "direct-codex-key",
        "platform-jwt-value-abc",
      ]),
    );
  });

  it("tolerates a missing token file", () => {
    expect(journalSecrets({}, null)).toEqual([]);
    expect(journalSecrets({}, "/nonexistent/token")).toEqual([]);
  });
});

function fakeEngine(run: (task: string, j: JournalSink) => Promise<string>): Engine {
  return {
    name: "fake",
    async run(task, _cfg, journal) {
      return { outputJson: await run(task, journal) };
    },
  };
}

describe("runJournaled", () => {
  it("brackets a successful run with status lines around the engine's events", async () => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: [] });
    const res = await runJournaled(
      fakeEngine(async (_t, jj) => {
        jj.append({ kind: "assistant", text: "done" });
        return "{}";
      }),
      "{}",
      cfg,
      j,
    );
    expect(res.outputJson).toBe("{}");
    expect(readLines(j.path).map((l) => (l as { kind: string; text?: string }).text ?? l)).toEqual([
      "run started",
      "done",
      "run ended exit=0",
    ]);
  });

  it("journals the error and exit=1 on failure, then rethrows", async () => {
    const root = tmpRoot();
    const j = FileJournal.open({ root, runId: "r", skillId: "s", secrets: [] });
    await expect(
      runJournaled(
        fakeEngine(async () => {
          throw new Error("model unreachable");
        }),
        "{}",
        cfg,
        j,
      ),
    ).rejects.toThrow("model unreachable");
    expect(readLines(j.path)).toMatchObject([
      { seq: 1, kind: "status", text: "run started" },
      { seq: 2, kind: "error", text: "model unreachable" },
      { seq: 3, kind: "status", text: "run ended exit=1" },
    ]);
  });
});

describe("serveJournals", () => {
  it("opens <root>/<task run_id>/<skill_id>.jsonl and reuses it for the same run", () => {
    const root = tmpRoot();
    const errs: string[] = [];
    const journals = serveJournals({ root, skillId: "hello-agent", secrets: [], warn: (m) => errs.push(m) });
    const a = journals("run-7");
    a.append({ kind: "status", text: "run started" });
    const b = journals("run-7");
    b.append({ kind: "status", text: "run started" });
    expect(readLines(join(root, "run-7", "hello-agent.jsonl")).map((l) => (l as { seq: number }).seq)).toEqual([1, 2]);
    expect(errs).toEqual([]);
  });

  it("does not journal (and says so on the process log) when the task has no run_id", () => {
    const root = tmpRoot();
    const errs: string[] = [];
    const journals = serveJournals({ root, skillId: "hello-agent", secrets: [], warn: (m) => errs.push(m) });
    journals(undefined).append({ kind: "status", text: "run started" });
    journals("").append({ kind: "status", text: "run started" });
    expect(errs).toHaveLength(2);
    expect(errs[0]).toMatch(/run_id/);
    expect(existsSync(join(root, "hello-agent.jsonl"))).toBe(false);
  });

  it("does not journal when the box was launched without a skill id", () => {
    const root = tmpRoot();
    const errs: string[] = [];
    const journals = serveJournals({ root, skillId: undefined, secrets: [], warn: (m) => errs.push(m) });
    journals("run-1").append({ kind: "status", text: "run started" });
    expect(errs[0]).toMatch(/CONTAINARIUM_SKILL_ID/);
    expect(existsSync(join(root, "run-1"))).toBe(false);
  });

  it("degrades to no journal, with a warning, when the journal directory cannot be created", () => {
    const blocker = join(tmpRoot(), "not-a-dir");
    writeFileSync(blocker, "");
    const errs: string[] = [];
    const journals = serveJournals({ root: join(blocker, "runs"), skillId: "s", secrets: [], warn: (m) => errs.push(m) });
    expect(() => journals("run-1").append({ kind: "status", text: "run started" })).not.toThrow();
    expect(errs).toHaveLength(1);
    expect(errs[0]).toMatch(/not journaled/);
  });

  it("rejects a run_id that would escape the journal root", () => {
    const journals = serveJournals({ root: tmpRoot(), skillId: "s", secrets: [], warn: () => {} });
    expect(() => journals("../../etc")).toThrow();
  });
});

describe("journal.schema", () => {
  it("round-trips every event kind through the exported fixture lines", () => {
    const kinds = new Set<string>();
    for (const line of JOURNAL_FIXTURE_LINES) {
      const ev = parseJournalLine(line);
      kinds.add(ev.kind);
      expect(JSON.stringify(ev)).toBe(line);
    }
    expect(kinds).toEqual(new Set(["status", "assistant", "tool_use", "tool_result", "error"]));
  });

  it("matches the shared fixtures/journal.jsonl file", () => {
    const file = readFileSync(new URL("../fixtures/journal.jsonl", import.meta.url), "utf8");
    expect(file.trimEnd().split("\n")).toEqual([...JOURNAL_FIXTURE_LINES]);
  });

  it.each([
    ["unknown kind", { seq: 1, t: "2026-09-28T10:00:00.000Z", kind: "thought", text: "x" }],
    ["missing tool", { seq: 1, t: "2026-09-28T10:00:00.000Z", kind: "tool_use", input: "{}" }],
    ["non-integer seq", { seq: 1.5, t: "2026-09-28T10:00:00.000Z", kind: "status", text: "x" }],
    ["bad timestamp", { seq: 1, t: "yesterday", kind: "status", text: "x" }],
    ["extra field", { seq: 1, t: "2026-09-28T10:00:00.000Z", kind: "status", text: "x", secret: "y" }],
  ])("rejects a line with %s", (_name, line) => {
    expect(() => parseJournalLine(JSON.stringify(line))).toThrow();
  });
});
