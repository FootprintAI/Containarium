import { query } from "@anthropic-ai/claude-agent-sdk";
import type { Engine, EngineConfig, EngineResult } from "../engine.js";

// ClaudeEngine drives the in-box loop with the Claude Agent SDK (the harness
// that powers Claude Code). It mounts the in-box agent-box binary as an MCP
// server, so agent-box's tools (shell/files/process) are the agent's tool
// surface. Auth: ANTHROPIC_API_KEY from the environment (seeded via secrets).
//
// permissionMode "dontAsk" runs fully non-interactive (deny anything not
// allow-listed, never prompt); allowedTools scopes the agent to agent-box's
// MCP tools (prefix `mcp__<server>__`).
export class ClaudeEngine implements Engine {
  readonly name = "claude";

  async run(task: string, cfg: EngineConfig): Promise<EngineResult> {
    let text = "";
    let usage: unknown;

    const options = {
      model: cfg.model || "claude-opus-4-8",
      systemPrompt: cfg.systemPrompt,
      maxTurns: cfg.maxTurns,
      permissionMode: "dontAsk",
      allowedTools: ["mcp__agent-box__*"],
      mcpServers: {
        "agent-box": {
          command: cfg.agentBoxCommand,
          args: cfg.agentBoxArgs,
        },
      },
    } as Parameters<typeof query>[0]["options"];

    for await (const message of query({ prompt: task, options })) {
      const m = message as { type: string; message?: { content?: Array<{ type: string; text?: string }> }; usage?: unknown };
      if (m.type === "assistant" && m.message?.content) {
        for (const block of m.message.content) {
          if (block.type === "text" && block.text) text += block.text;
        }
      }
      if (m.type === "result") {
        usage = m.usage;
        break;
      }
    }

    return { outputJson: text.trim(), usage };
  }
}
