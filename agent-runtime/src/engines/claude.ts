import { query, type SDKMessage } from "@anthropic-ai/claude-agent-sdk";
import type { Engine, EngineConfig, EngineResult } from "../engine.js";
import type { JournalSink } from "../journal.js";
import { claudeAllowedTools, claudeMcpServers, mcpServerSpecs } from "../mcp.js";

// ClaudeQuery is the shape of the Agent SDK's query(), injectable for tests.
export type ClaudeQuery = (params: Parameters<typeof query>[0]) => AsyncIterable<SDKMessage>;

// ClaudeEngine drives the in-box loop with the Claude Agent SDK (the harness
// that powers Claude Code). It mounts the in-box agent-box binary as an MCP
// server, so agent-box's tools (shell/files/process) are the agent's tool
// surface. Auth: ANTHROPIC_API_KEY from the environment (seeded via secrets).
//
// permissionMode "dontAsk" runs fully non-interactive (deny anything not
// allow-listed, never prompt); allowedTools scopes the agent to agent-box's
// MCP tools (prefix `mcp__<server>__`) and, when the seed carries a
// platform_mcp.json (#1922 D4), exactly the platform tools the daemon
// allow-listed — never the whole platform catalog.
//
// Journal (#2095): every assistant text block, tool_use block and tool_result
// block the query() iterator yields is appended as it arrives; an error
// result is journaled as an error.
export class ClaudeEngine implements Engine {
  readonly name = "claude";

  // queryFn is the Agent SDK's query(); a seam for tests.
  constructor(private readonly queryFn: ClaudeQuery = query) {}

  async run(task: string, cfg: EngineConfig, journal: JournalSink): Promise<EngineResult> {
    let text = "";
    let usage: unknown;
    // tool_use id -> tool name, so a tool_result line can name its tool.
    const toolNames = new Map<string, string>();

    const specs = mcpServerSpecs(cfg);
    const options = {
      model: cfg.model || "claude-opus-4-8",
      systemPrompt: cfg.systemPrompt,
      maxTurns: cfg.maxTurns,
      permissionMode: "dontAsk",
      allowedTools: claudeAllowedTools(specs),
      mcpServers: claudeMcpServers(specs),
    } as Parameters<typeof query>[0]["options"];

    for await (const m of this.queryFn({ prompt: task, options })) {
      if (m.type === "assistant") {
        for (const block of m.message.content ?? []) {
          if (block.type === "text" && block.text) {
            text += block.text;
            journal.append({ kind: "assistant", text: block.text });
          } else if (block.type === "tool_use") {
            toolNames.set(block.id, block.name);
            journal.append({ kind: "tool_use", tool: block.name, input: JSON.stringify(block.input ?? {}) });
          }
        }
      } else if (m.type === "user") {
        const content = m.message.content;
        if (typeof content === "string") continue;
        for (const block of content ?? []) {
          if (block.type !== "tool_result") continue;
          journal.append({
            kind: "tool_result",
            tool: toolNames.get(block.tool_use_id) ?? "unknown",
            text: toolResultText(block.content),
          });
        }
      } else if (m.type === "result") {
        usage = m.usage;
        if (m.subtype !== "success") {
          const detail = (m.errors ?? []).join("; ");
          journal.append({ kind: "error", text: detail ? `${m.subtype}: ${detail}` : m.subtype });
        }
        break;
      }
    }

    return { outputJson: text.trim(), usage };
  }
}

// toolResultText flattens a tool_result's content to text: text blocks
// verbatim, anything else (an image, a document) as a [type] placeholder.
function toolResultText(content: string | ReadonlyArray<{ type: string; text?: string }> | undefined): string {
  if (content === undefined) return "";
  if (typeof content === "string") return content;
  return content.map((b) => (b.type === "text" && typeof b.text === "string" ? b.text : `[${b.type}]`)).join("\n");
}
