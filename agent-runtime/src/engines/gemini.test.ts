import type { GenerateContentResponse } from "@google/genai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { EngineConfig } from "../engine.js";
import { CaptureJournal } from "../testing/capture.js";
import { GeminiEngine, geminiFollowUp, journalGeminiResponse } from "./gemini.js";

// The Gemini engine makes one generateContent call with automatic function
// calling; the SDK returns the tool-use turns as automaticFunctionCallingHistory
// alongside the final text. That history is the engine's event stream.
function fakeResponse(r: { history: unknown[]; text: string }): Pick<GenerateContentResponse, "automaticFunctionCallingHistory" | "text"> {
  return { automaticFunctionCallingHistory: r.history as GenerateContentResponse["automaticFunctionCallingHistory"], text: r.text };
}

describe("GeminiEngine journal", () => {
  it("journals assistant, tool_use and tool_result one line each, in order", () => {
    const j = new CaptureJournal();
    journalGeminiResponse(
      fakeResponse({
        history: [
          { role: "user", parts: [{ text: "the task" }] },
          { role: "model", parts: [{ text: "Looking." }, { functionCall: { name: "shell", args: { cmd: "ls" } } }] },
          { role: "user", parts: [{ functionResponse: { name: "shell", response: { content: [{ type: "text", text: "README.md" }] } } }] },
          { role: "model", parts: [{ text: "hmm", thought: true }] },
        ],
        text: '{"files":1}',
      }),
      j,
    );
    expect(j.entries).toEqual([
      { kind: "assistant", text: "Looking." },
      { kind: "tool_use", tool: "shell", input: '{"cmd":"ls"}' },
      { kind: "tool_result", tool: "shell", text: '{"content":[{"type":"text","text":"README.md"}]}' },
      { kind: "assistant", text: '{"files":1}' },
    ]);
  });

  it("journals only the missing final message when there was no tool use and no text", () => {
    const j = new CaptureJournal();
    journalGeminiResponse(fakeResponse({ history: [], text: "" }), j);
    expect(j.entries).toEqual([{ kind: "status", text: "model ended without a final message: finish_reason=unknown" }]);
  });

  // #2513: a run that edited files and then stopped with no final JSON left no
  // trace of why. The journal now says how the turn ended.
  describe("how the turn ended (#2513)", () => {
    const withEnding = (text: string, extra: Record<string, unknown>) =>
      ({ ...fakeResponse({ history: [], text }), ...extra }) as Parameters<typeof journalGeminiResponse>[0];

    it("names a STOP with no final text", () => {
      const j = new CaptureJournal();
      journalGeminiResponse(withEnding("", { candidates: [{ finishReason: "STOP" }] }), j);
      expect(j.entries).toEqual([{ kind: "status", text: "model ended without a final message: finish_reason=STOP" }]);
    });

    it("names MAX_TOKENS, the finish message and a prompt block", () => {
      const j = new CaptureJournal();
      journalGeminiResponse(
        withEnding("", { candidates: [{ finishReason: "MAX_TOKENS", finishMessage: "limit hit" }], promptFeedback: { blockReason: "SAFETY" } }),
        j,
      );
      expect(j.entries).toEqual([
        { kind: "status", text: 'model ended without a final message: finish_reason=MAX_TOKENS finish_message="limit hit" block_reason=SAFETY' },
      ]);
    });

    it("stays quiet for a normal STOP with a final message", () => {
      const j = new CaptureJournal();
      journalGeminiResponse(withEnding('{"ok":1}', { candidates: [{ finishReason: "STOP" }] }), j);
      expect(j.entries).toEqual([{ kind: "assistant", text: '{"ok":1}' }]);
    });

    it("flags a final message cut off by MAX_TOKENS", () => {
      const j = new CaptureJournal();
      journalGeminiResponse(withEnding('{"ok":', { candidates: [{ finishReason: "MAX_TOKENS" }] }), j);
      expect(j.entries).toEqual([
        { kind: "assistant", text: '{"ok":' },
        { kind: "status", text: "model ended abnormally after its final message: finish_reason=MAX_TOKENS" },
      ]);
    });

    it("bounds the finish message", () => {
      const j = new CaptureJournal();
      journalGeminiResponse(withEnding("", { candidates: [{ finishReason: "OTHER", finishMessage: "x".repeat(1000) }] }), j);
      const row = JSON.stringify(j.entries[0]);
      expect(row).toContain("x".repeat(200));
      expect(row).not.toContain("x".repeat(201));
    });
  });
});

// #2002: the Gemini API only accepts a response schema alongside function
// calling on Gemini 3 preview models, not on this engine's default; the schema
// is therefore prompt-only here. That gap must be visible in the run journal,
// not silent. The engine journals it before it needs any credential, so the
// notice can be asserted without network.
describe("GeminiEngine output schema (prompt-only gap)", () => {
  const credentialEnv = ["GEMINI_API_KEY", "GOOGLE_API_KEY", "CONTAINARIUM_MODEL_GATEWAY_URL", "CONTAINARIUM_GATEWAY_TOKEN"] as const;
  const saved: Partial<Record<(typeof credentialEnv)[number], string | undefined>> = {};
  beforeEach(() => {
    for (const k of credentialEnv) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const k of credentialEnv) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  const cfg: EngineConfig = { model: "", systemPrompt: "", agentBoxCommand: "agent-box", agentBoxArgs: [], maxTurns: 1 };

  it("journals that a declared schema is not enforced by this engine", async () => {
    const j = new CaptureJournal();
    await expect(new GeminiEngine().run("task", { ...cfg, outputSchema: { type: "object" } }, j)).rejects.toThrow(/GEMINI_API_KEY/);
    expect(j.entries).toEqual([{ kind: "status", text: expect.stringMatching(/output schema.*not enforced.*gemini/i) }]);
  });

  it("journals nothing about schemas when none is declared", async () => {
    const j = new CaptureJournal();
    await expect(new GeminiEngine().run("task", cfg, j)).rejects.toThrow(/GEMINI_API_KEY/);
    expect(j.entries).toEqual([]);
  });
});

// #2513 item 2: the follow-up replays the conversation the automatic function
// calling loop had (its history starts with the task), plus the model's last
// turn, then asks — with no tools mounted, so the answer is text.
describe("geminiFollowUp", () => {
  const callContent = { role: "model", parts: [{ functionCall: { name: "write_file", args: { path: "text/slug.go" } } }] };
  const resultContent = { role: "user", parts: [{ functionResponse: { name: "write_file", response: { bytes_written: 649 } } }] };
  const taskContent = { role: "user", parts: [{ text: "task" }] };

  function fakeGenerate(reply: string, seen: unknown[]) {
    return async (params: unknown) => {
      seen.push(params);
      return { text: reply, candidates: [{ finishReason: "STOP", content: { role: "model", parts: [{ text: reply }] } }] } as unknown as GenerateContentResponse;
    };
  }

  it("replays the history and asks once with no tools, returning the trimmed reply", async () => {
    const seen: unknown[] = [];
    const followUp = geminiFollowUp(fakeGenerate(' {"files":["text/slug.go"]}\n', seen), { model: "m", systemPrompt: "persona", task: "task" }, {
      automaticFunctionCallingHistory: [taskContent, callContent, resultContent],
      candidates: [{ finishReason: "STOP" as never, content: { role: "model", parts: [] } }],
    });
    const j = new CaptureJournal();
    const res = await followUp("give me the JSON", j);
    expect(res.outputJson).toBe('{"files":["text/slug.go"]}');
    expect(seen).toEqual([
      {
        model: "m",
        contents: [taskContent, callContent, resultContent, { role: "user", parts: [{ text: "give me the JSON" }] }],
        config: { systemInstruction: "persona" },
      },
    ]);
    expect(j.entries).toEqual([{ kind: "assistant", text: ' {"files":["text/slug.go"]}\n' }]);
  });

  it("starts from the task when there was no tool loop, keeps the model's last text, drops a dangling call", async () => {
    const seen: unknown[] = [];
    await geminiFollowUp(fakeGenerate("{}", seen), { model: "m", systemPrompt: "", task: "task" }, {
      candidates: [{ content: { role: "model", parts: [{ text: "Done." }, { functionCall: { name: "shell_exec", args: {} } }] } }],
    })("ask", new CaptureJournal());
    expect((seen[0] as { contents: unknown }).contents).toEqual([
      taskContent,
      { role: "model", parts: [{ text: "Done." }] },
      { role: "user", parts: [{ text: "ask" }] },
    ]);
    expect((seen[0] as { config: unknown }).config).toEqual({});
  });
});
