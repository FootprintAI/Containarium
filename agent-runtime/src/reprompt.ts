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
import { AGENT_BOX_MCP_NAME } from "./mcp.js";
import { shellCommandWritesFiles } from "./shell-edit.js";
import { sumUsage } from "./usage.js";

// FINAL_JSON_REPROMPT is the one follow-up message the agent gets.
export const FINAL_JSON_REPROMPT =
  "You changed files but ended your turn without a final message. " +
  "Reply now with only the final JSON object your instructions ask for, with no tool calls and no other text. " +
  "Report only what you actually did.";

// The tools that change files: agent-box's write/move/delete (bare under
// Gemini, mcp__agent-box__<tool> under Claude and Codex) and Codex's native
// file_change item. A tool of any other MCP server is not counted, whatever it
// is called. A shell command counts when shellCommandWritesFiles says it
// writes (shell-edit.ts; #3107).
const FILE_CHANGING_TOOLS: ReadonlySet<string> = new Set(["write_file", "move_file", "delete_file", "file_change"]);
const SHELL_TOOLS: ReadonlySet<string> = new Set(["shell_exec", "shell"]);
const AGENT_BOX_PREFIX = `mcp__${AGENT_BOX_MCP_NAME}__`;

// agentBoxToolName is the tool's bare name when it is agent-box's (or an
// engine-native tool journaled bare), or undefined for another server's tool.
function agentBoxToolName(tool: string): string | undefined {
  if (tool.startsWith(AGENT_BOX_PREFIX)) return tool.slice(AGENT_BOX_PREFIX.length);
  return tool.startsWith("mcp__") ? undefined : tool;
}

// isFileChangingTool reports whether a journaled tool name changes files.
export function isFileChangingTool(tool: string): boolean {
  const bare = agentBoxToolName(tool);
  return bare !== undefined && FILE_CHANGING_TOOLS.has(bare);
}

// isFileChangingToolUse is isFileChangingTool plus the shell tools, whose
// input says whether the command writes. shell_exec's input is the journaled
// JSON arguments; Codex's shell input is the raw command.
export function isFileChangingToolUse(tool: string, input: string): boolean {
  if (isFileChangingTool(tool)) return true;
  const bare = agentBoxToolName(tool);
  if (bare === undefined || !SHELL_TOOLS.has(bare)) return false;
  return shellCommandWritesFiles(bare === "shell" ? input : shellExecCommand(input));
}

function shellExecCommand(input: string): string {
  try {
    const args: unknown = JSON.parse(input);
    if (typeof args === "object" && args !== null && "command" in args && typeof args.command === "string") return args.command;
  } catch {
    // Not JSON: not a call we can read.
  }
  return "";
}

// FileChangeWatch passes every entry through to the journal and notes whether
// any of them was a file-changing tool call.
class FileChangeWatch implements JournalSink {
  changedFiles = false;
  constructor(private readonly journal: JournalSink) {}
  append(entry: JournalEntry): void {
    if (entry.kind === "tool_use" && isFileChangingToolUse(entry.tool, entry.input)) this.changedFiles = true;
    this.journal.append(entry);
  }
}

// runWithFinalJsonReprompt runs the task once. When the run changed files and
// returned no final message, and the engine can continue the conversation, it
// sends FINAL_JSON_REPROMPT once and returns that turn's result, or throws if
// the reply is empty too. The returned result is the reply with both turns'
// usage summed (#3107).
//
// What counts as a final message (#3107 item 6): any non-blank text, for the
// first turn and the reply alike. The runtime does not parse it. A schema-bound
// run is enforced provider-side and never reaches here (Claude offers no
// followUp for it; Codex's outputSchema shapes the reply), and a free-form
// skill's output is text the daemon stores as it is, so requiring JSON here
// would fail runs the daemon accepts. A prose reply therefore ends the run
// without a second ask; the prompt asks for JSON, and the daemon is the judge
// of what it can parse. Any other result is returned as it is: a run that
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
  return { ...reply, usage: sumUsage(res.usage, reply.usage) };
}
