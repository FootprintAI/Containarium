// Re-prompt once for a missing final message (#2513 item 2).
//
// A skill's contract asks for one final JSON object. A run that edited files
// and then ended its turn without a final message used to fail outright, with
// its work on disk. The maintainer decision (2026-10-25): ask the agent once,
// in the same conversation, for its final JSON. If it still returns none, the
// run fails with that reason. The runtime never builds a result from the
// changed files itself: a synthesised summary would claim things the agent
// never said.
import type { Engine, EngineConfig, EngineResult } from "./engine.js";
import type { JournalEntry, JournalSink } from "./journal.js";

// FINAL_JSON_REPROMPT is the one follow-up message the agent gets.
export const FINAL_JSON_REPROMPT =
  "You changed files but ended your turn without a final message. " +
  "Reply now with only the final JSON object your instructions ask for, with no tool calls and no other text. " +
  "Report only what you actually did.";

// The tools that change files: agent-box's write/move/delete (bare under
// Gemini, mcp__agent-box__<tool> under Claude and Codex) and Codex's native
// file_change item. A change made through shell_exec is not seen here, so a
// run that edits only through the shell is not re-prompted.
const FILE_CHANGING_TOOLS: ReadonlySet<string> = new Set(["write_file", "move_file", "delete_file", "file_change"]);

// isFileChangingTool reports whether a journaled tool name changes files.
export function isFileChangingTool(tool: string): boolean {
  const bare = tool.startsWith("mcp__") ? tool.slice(tool.indexOf("__", "mcp__".length) + 2) : tool;
  return FILE_CHANGING_TOOLS.has(bare);
}

// FileChangeWatch passes every entry through to the journal and notes whether
// any of them was a file-changing tool call.
class FileChangeWatch implements JournalSink {
  changedFiles = false;
  constructor(private readonly journal: JournalSink) {}
  append(entry: JournalEntry): void {
    if (entry.kind === "tool_use" && isFileChangingTool(entry.tool)) this.changedFiles = true;
    this.journal.append(entry);
  }
}

// runWithFinalJsonReprompt runs the task once. When the run changed files and
// returned no final message, and the engine can continue the conversation, it
// sends FINAL_JSON_REPROMPT once and returns that turn's result, or throws if
// the reply is empty too. Any other result is returned as it is: a run that
// changed no files and returned nothing still fails in the daemon, as before.
export async function runWithFinalJsonReprompt(
  engine: Engine,
  task: string,
  cfg: EngineConfig,
  journal: JournalSink,
): Promise<EngineResult> {
  const watch = new FileChangeWatch(journal);
  const res = await engine.run(task, cfg, watch);
  if (res.outputJson.trim() !== "" || !watch.changedFiles || !res.followUp) return res;
  journal.append({
    kind: "status",
    text: "run changed files but returned no final message: re-prompting once for the final JSON",
  });
  const reply = await res.followUp(FINAL_JSON_REPROMPT, journal);
  if (reply.outputJson.trim() === "") {
    throw new Error(
      "the agent changed files but returned no final JSON, even after one re-prompt for it; see the run journal for the tool calls it made",
    );
  }
  return reply;
}
