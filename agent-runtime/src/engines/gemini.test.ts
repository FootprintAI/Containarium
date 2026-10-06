import type { GenerateContentResponse } from "@google/genai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { EngineConfig } from "../engine.js";
import { CaptureJournal } from "../testing/capture.js";
import { GeminiEngine, journalGeminiResponse } from "./gemini.js";

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

  it("journals nothing extra when there was no tool use and no text", () => {
    const j = new CaptureJournal();
    journalGeminiResponse(fakeResponse({ history: [], text: "" }), j);
    expect(j.entries).toEqual([]);
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
