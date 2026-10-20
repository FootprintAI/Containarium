import {
  CredentialAuthenticationError,
  type AuthenticationSource,
} from "../credential-state.js";
import { query, type SDKMessage } from "@anthropic-ai/claude-agent-sdk";
import type { Engine, EngineConfig, EngineResult } from "../engine.js";
import type { JournalSink } from "../journal.js";
import {
  claudeAllowedTools,
  claudeMcpServers,
  mcpServerSpecs,
} from "../mcp.js";

// ClaudeQuery is the shape of the Agent SDK's query(), injectable for tests.
export type ClaudeQuery = (
  params: Parameters<typeof query>[0],
) => AsyncIterable<SDKMessage>;

type ClaudeResult = Extract<SDKMessage, { type: "result" }>;

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
// Output schema (#2002): when the skill's agent_card declares an
// output_schema_json, it is passed as the SDK's `outputFormat` (json_schema).
// The SDK validates the agent's final output against the schema and
// re-prompts on mismatch; the artifact is the resulting `structured_output`,
// never the assistant's prose. A run that ends without one — validation
// retries exhausted (error_max_structured_output_retries), any other error
// result, or a "success" that carries no structured_output (the SDK documents
// that case as a failure too) — is rejected by throwing, so the daemon gets
// an error artifact instead of a schema-violating one. Without a declared
// schema the artifact is the concatenated assistant text, as before.
//
// Journal (#2095): every assistant text block, tool_use block and tool_result
// block the query() iterator yields is appended as it arrives; an error
// result is journaled as an error.
export class ClaudeEngine implements Engine {
  readonly name = "claude";

  // queryFn is the Agent SDK's query(); a seam for tests.
  constructor(private readonly queryFn: ClaudeQuery = query) {}

  async run(
    task: string,
    cfg: EngineConfig,
    journal: JournalSink,
  ): Promise<EngineResult> {
    let source: AuthenticationSource = cfg.authenticationSource ?? "unknown";
    let externalProvider = false;
    let text = "";
    let usage: unknown;
    let result: ClaudeResult | undefined;
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
      ...(cfg.outputSchema
        ? { outputFormat: { type: "json_schema", schema: cfg.outputSchema } }
        : {}),
    } as Parameters<typeof query>[0]["options"];

    let dispose: (() => void) | undefined;
    try {
      const stream = this.queryFn({ prompt: task, options });
      if ("close" in stream && typeof stream.close === "function") {
        const close = stream.close;
        dispose = () => {
          close.call(stream);
        };
      }
      // SDK account info is nonsecret provenance and is available before model
      // inference. Do not inspect email/account identifiers or credential values.
      if ("accountInfo" in stream && typeof stream.accountInfo === "function") {
        try {
          const info = (await stream.accountInfo()) as {
            apiKeySource?: string;
            apiProvider?: string;
          };
          externalProvider = Boolean(
            info.apiProvider && info.apiProvider !== "firstParty",
          );
          source = externalProvider
            ? "key"
            : info.apiKeySource === "oauth"
              ? "oauth"
              : ["user", "project", "org", "temporary"].includes(
                    info.apiKeySource ?? "",
                  )
                ? "key"
                : source;
        } catch (e) {
          if (
            typeof e === "object" &&
            e !== null &&
            "status" in e &&
            e.status === 401
          )
            throw new CredentialAuthenticationError(source);
          // Optional metadata lookup failures must not break a valid run.
          // The authoritative init message may still identify its source.
        }
      }
      for await (const m of stream) {
        if (m.type === "system" && m.subtype === "init") {
          source = externalProvider
            ? "key"
            : m.apiKeySource === "oauth"
              ? "oauth"
              : ["user", "project", "org", "temporary"].includes(m.apiKeySource)
                ? "key"
                : "unknown";
        }
        if (m.type === "assistant") {
          if (m.error === "authentication_failed")
            throw new CredentialAuthenticationError(source);
          for (const block of m.message.content ?? []) {
            if (block.type === "text" && block.text) {
              text += block.text;
              journal.append({ kind: "assistant", text: block.text });
            } else if (block.type === "tool_use") {
              toolNames.set(block.id, block.name);
              journal.append({
                kind: "tool_use",
                tool: block.name,
                input: JSON.stringify(block.input ?? {}),
              });
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
          if ("api_error_status" in m && m.api_error_status === 401)
            throw new CredentialAuthenticationError(source);
          usage = m.usage;
          result = m;
          if (m.subtype !== "success") {
            journal.append({ kind: "error", text: resultErrorText(m) });
          }
          break;
        }
      }
    } catch (e) {
      if (e instanceof CredentialAuthenticationError) throw e;
      if (
        typeof e === "object" &&
        e !== null &&
        "status" in e &&
        e.status === 401
      )
        throw new CredentialAuthenticationError(source);
      throw e;
    } finally {
      try {
        dispose?.();
      } catch {
        process.stderr.write("agent-runtime: SDK cleanup unavailable\n");
      }
    }
    const authenticated =
      result?.subtype === "success" && result.is_error === false;
    if (cfg.outputSchema) {
      return {
        outputJson: JSON.stringify(structuredOutput(result)),
        usage,
        authenticationSucceeded: authenticated,
        authenticationSource: source,
      };
    }
    return {
      outputJson: text.trim(),
      usage,
      authenticationSucceeded: authenticated,
      authenticationSource: source,
    };
  }
}

// structuredOutput is the SDK-validated output of a schema-bound run, or
// throws naming why there is none.
function structuredOutput(result: ClaudeResult | undefined): unknown {
  const want = "no structured output matching agent_card.output_schema_json";
  if (result === undefined)
    throw new Error(`claude: run ended without a result message — ${want}`);
  if (result.subtype !== "success")
    throw new Error(`claude: ${resultErrorText(result)} — ${want}`);
  if (result.structured_output === undefined)
    throw new Error(`claude: run ended with ${want}`);
  return result.structured_output;
}

// resultErrorText renders an error result as "<subtype>: <errors>" (or just
// the subtype), the journal's error line for it.
function resultErrorText(result: ClaudeResult): string {
  const detail = "errors" in result ? (result.errors ?? []).join("; ") : "";
  return detail ? `${result.subtype}: ${detail}` : result.subtype;
}

// toolResultText flattens a tool_result's content to text: text blocks
// verbatim, anything else (an image, a document) as a [type] placeholder.
function toolResultText(
  content: string | ReadonlyArray<{ type: string; text?: string }> | undefined,
): string {
  if (content === undefined) return "";
  if (typeof content === "string") return content;
  return content
    .map((b) =>
      b.type === "text" && typeof b.text === "string" ? b.text : `[${b.type}]`,
    )
    .join("\n");
}
