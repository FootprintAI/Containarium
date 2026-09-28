import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Engine, EngineConfig } from "./engine.js";
import { NULL_JOURNAL, runJournaled, type JournalSink } from "./journal.js";
import type { Seed } from "./seed.js";

// A2A_PORT is the port the daemon resolves for a peer's in-box A2A server
// (resolvePeerA2A in internal/server/agent_server.go uses :8674).
export const A2A_PORT = 8674;

// Wire shapes match the proto (containarium/v1/agent.proto) as serialized by
// protojson, which the daemon's sendA2ATask uses: lowerCamelCase fields, enum
// values as their proto name strings.
interface AgentTaskWire {
  id?: string;
  inputJson?: string;
  input_json?: string; // protojson accepts snake_case on input too
  // The run the task belongs to; names its journal (#2095).
  runId?: string;
  run_id?: string;
}

// TaskJournals resolves a task's run_id to the journal it is written to.
export type TaskJournals = (runId: string | undefined) => JournalSink;
interface AgentArtifactWire {
  taskId: string;
  outputJson: string;
  state: "AGENT_TASK_STATE_COMPLETED" | "AGENT_TASK_STATE_FAILED";
  error: string;
}

// runTask runs one delegated A2A task through the engine and shapes the
// artifact. Pure (engine + cfg injected) — the HTTP layer just adapts to it.
// journals maps the task's run_id to its journal; without it (poll mode) the
// task is not journaled.
export async function runTask(task: AgentTaskWire, engine: Engine, cfg: EngineConfig, journals?: TaskJournals): Promise<AgentArtifactWire> {
  const taskId = task.id ?? "";
  const input = task.inputJson ?? task.input_json ?? "{}";
  try {
    const journal = journals ? journals(task.runId ?? task.run_id) : NULL_JOURNAL;
    const result = await runJournaled(engine, input, cfg, journal);
    return { taskId, outputJson: result.outputJson, state: "AGENT_TASK_STATE_COMPLETED", error: "" };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { taskId, outputJson: "", state: "AGENT_TASK_STATE_FAILED", error: msg };
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

// startA2AServer serves the Phase-1 A2A surface from inside the box:
//   GET  /agent-card  -> the seeded agent card (discovery)
//   POST /tasks       -> run one task, return the artifact
// A failed task still returns 200 with state FAILED so the caller (the daemon's
// SendAgentTask) receives the artifact rather than an HTTP error.
export function startA2AServer(seed: Seed, engine: Engine, cfg: EngineConfig, journals: TaskJournals, port: number = A2A_PORT): void {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.method === "GET" && req.url === "/agent-card") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(seed.agentCard ?? {}));
      return;
    }
    if (req.method === "POST" && req.url === "/tasks") {
      void (async () => {
        try {
          const body = await readBody(req);
          const task = JSON.parse(body || "{}") as AgentTaskWire;
          const artifact = await runTask(task, engine, cfg, journals);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(artifact));
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ taskId: "", outputJson: "", state: "AGENT_TASK_STATE_FAILED", error: msg }));
        }
      })();
      return;
    }
    res.writeHead(404);
    res.end();
  });
  server.listen(port, () => process.stdout.write(`agent-runtime: A2A server listening on :${port}\n`));
}
