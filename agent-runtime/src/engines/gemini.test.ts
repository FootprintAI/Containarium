import type { GenerateContentResponse } from "@google/genai";
import { describe, expect, it } from "vitest";
import { CaptureJournal } from "../testing/capture.js";
import { journalGeminiResponse } from "./gemini.js";

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
