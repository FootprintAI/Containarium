import { GoogleGenAI, mcpToTool } from "@google/genai";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Engine, EngineConfig, EngineResult } from "../engine.js";
import { mcpServerSpecs } from "../mcp.js";

// GeminiEngine drives the in-box loop with the Google Gen AI SDK (@google/genai).
// Like the Claude and Codex engines it mounts the in-box agent-box binary as its
// tool surface — here over MCP: agent-box is spawned as an MCP stdio server and
// handed to the SDK via mcpToTool(), and the SDK's automatic function calling runs
// the tool-use loop (capped at cfg.maxTurns remote calls). Auth: GEMINI_API_KEY
// (or GOOGLE_API_KEY) from the environment, seeded via secrets.
//
// Default model: gemini-2.5-flash — a cheap, fast model. That low cost is the
// reason this engine exists: a budget-friendly way to exercise the agent
// mechanism end-to-end without burning frontier-model spend on every test run.
export class GeminiEngine implements Engine {
  readonly name = "gemini";

  async run(task: string, cfg: EngineConfig): Promise<EngineResult> {
    // Gateway mode: CONTAINARIUM_MODEL_GATEWAY_URL + CONTAINARIUM_GATEWAY_TOKEN
    // route calls through the platform's model-gateway so the real Gemini key
    // never lives in the box. Direct mode: GEMINI_API_KEY / GOOGLE_API_KEY hits
    // the provider directly (OSS / self-hosted use case).
    const gatewayUrl = process.env.CONTAINARIUM_MODEL_GATEWAY_URL;
    const gatewayToken = process.env.CONTAINARIUM_GATEWAY_TOKEN;
    const useGateway = !!(gatewayUrl && gatewayToken);

    const apiKey = useGateway
      ? gatewayToken!
      : (process.env.GEMINI_API_KEY ?? process.env.GOOGLE_API_KEY);
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY (or GOOGLE_API_KEY) is not set — for hosted use, set CONTAINARIUM_MODEL_GATEWAY_URL + CONTAINARIUM_GATEWAY_TOKEN");
    }

    // Spawn each MCP server as a stdio child — agent-box always, plus the
    // platform MCP when the seed carries one (#1922 D4) — the same tool
    // surface the other engines mount, exposed to Gemini through MCP clients.
    const mcpClients: Client[] = [];
    try {
      for (const spec of mcpServerSpecs(cfg)) {
        const client = new Client({ name: "agent-runtime", version: "0.1.0" });
        mcpClients.push(client);
        await client.connect(
          new StdioClientTransport({ command: spec.command, args: spec.args, ...(spec.env ? { env: spec.env } : {}) }),
        );
      }
      // When routing through the gateway the SDK sends x-goog-api-key (the
      // gateway token) to `<gatewayUrl>/v1/model/gemini/<upstream-path>`.
      // The gateway verifies the token, injects the real Gemini key, and
      // proxies to generativelanguage.googleapis.com — so the key never leaves
      // the gateway process.
      const ai = new GoogleGenAI({
        apiKey,
        ...(useGateway ? { httpOptions: { baseUrl: `${gatewayUrl}/v1/model/gemini` } } : {}),
      });
      const response = await ai.models.generateContent({
        model: cfg.model || "gemini-2.5-flash",
        contents: task,
        config: {
          ...(cfg.systemPrompt ? { systemInstruction: cfg.systemPrompt } : {}),
          // mcpToTool is variadic over clients but typed as a tuple TS cannot infer
          // from an array; agent-box is always present, so it is never empty.
          tools: [mcpToTool(...(mcpClients as unknown as Parameters<typeof mcpToTool>))],
          // Cap the agentic tool-use loop the same way the other engines bound
          // maxTurns; automatic function calling executes agent-box tool calls.
          automaticFunctionCalling: { maximumRemoteCalls: cfg.maxTurns },
        },
      });
      return { outputJson: (response.text ?? "").trim(), usage: response.usageMetadata };
    } finally {
      await Promise.allSettled(mcpClients.map((c) => c.close()));
    }
  }
}
