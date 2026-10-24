// How an engine's turn ended, rendered as the journal's status row (#2513).
// The Gemini engine writes the same row from its own finish reason
// (describeGeminiEnding); this is the shape the other engines share, so a
// journal reader greps one prefix whichever engine ran.

// FINAL_MESSAGE_PREVIEW_CHARS bounds the final-message preview on the row.
// The full text is already its own assistant row; the preview only puts the
// start of it beside the stop reason.
export const FINAL_MESSAGE_PREVIEW_CHARS = 200;

// EndingField is one `name=value` on the row. Values come from the SDK's
// enumerated stop/terminal reasons and result subtypes, never model output.
export interface EndingField {
  readonly name: string;
  readonly value: string;
}

export interface RunEnding {
  // The model's final message (after its last tool call); empty if none.
  readonly finalMessage: string;
  // Whether the engine had the output it was asked for: a final message, or
  // the structured output when a schema was declared.
  readonly hasFinalOutput: boolean;
  // Whether the turn ended any way but the ordinary one.
  readonly abnormal: boolean;
  readonly fields: readonly EndingField[];
}

// describeRunEnding returns the status row's text, or undefined for the
// unremarkable case: the final output is there and the ending was ordinary.
export function describeRunEnding(ending: RunEnding): string | undefined {
  if (ending.hasFinalOutput && !ending.abnormal) return undefined;
  const parts = ending.fields.map((f) => `${f.name}=${f.value}`);
  const final = ending.finalMessage;
  if (final.trim()) {
    parts.push(`final_message=${JSON.stringify(final.slice(0, FINAL_MESSAGE_PREVIEW_CHARS))}`);
    if (final.length > FINAL_MESSAGE_PREVIEW_CHARS) parts.push(`final_message_chars=${final.length}`);
  }
  return ending.hasFinalOutput || final.trim()
    ? `model ended abnormally after its final message: ${parts.join(" ")}`
    : `model ended without a final message: ${parts.join(" ")}`;
}
