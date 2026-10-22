import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Engine, EngineConfig } from "./engine.js";
import { NULL_JOURNAL, runJournaled, type JournalSink } from "./journal.js";
import type { Seed } from "./seed.js";

// A2A_PORT is the port the daemon resolves for a peer's in-box A2A server
// (resolvePeerA2A in internal/server/agent_server.go uses :8674).
export const A2A_PORT = 8674;

// A2A_TOKEN_ENV carries the per-box secret the daemon derived for THIS box
// (agentA2ASecret in internal/server/a2a_client.go); serveModeCommand exports it
// into the serve-mode process. It is the credential POST /tasks demands.
export const A2A_TOKEN_ENV = "CONTAINARIUM_A2A_TOKEN";

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

// POST /tasks is a DAEMON-ONLY endpoint (#2125; decision D1 in
// docs/architecture/execution-scoped-authorization.md).
//
// It used to authenticate nobody and journal a task under whatever run_id the
// body carried. Any box that could reach a peer's :8674 — which the egress
// policy compiled from allowed_peers grants, in LOG_ONLY mode by default —
// could therefore write output into a third party's run journal, which
// TailRunLog then serves to that run's viewer. The daemon-side run-claim check
// (#2112) does not cover it: the daemon is not on that path.
//
// The trust model: every A2A hop goes through the daemon's SendAgentTask, which
// is where run scoping lives. It is enforced here, and not only at the network
// layer, because the eBPF policy is LOG_ONLY until an operator arms it and a
// security boundary has to hold on a default install. The credential is
// per-box precisely so a peer cannot replay its own.

// A2AAuthOutcome is the result of checking one request's credential: allowed,
// or refused with the status the caller gets. A discriminated union, so a
// caller cannot read a `status` off an allowed outcome.
export type A2AAuthOutcome = { ok: true } | { ok: false; status: 401 | 403; error: string };

// A bearer credential per RFC 7235: the scheme is case-insensitive and is
// separated from the token by whitespace. A bare `Bearer` does not match.
const BEARER_HEADER = /^Bearer[ \t]+(\S+)$/i;

// sameSecret compares two secrets in constant time. Both sides are hashed
// first: timingSafeEqual requires equal-length inputs (it throws otherwise),
// and hashing means the comparison leaks neither the expected length nor how
// long a prefix matched.
function sameSecret(got: string, want: string): boolean {
  const a = createHash("sha256").update(got, "utf8").digest();
  const b = createHash("sha256").update(want, "utf8").digest();
  return timingSafeEqual(a, b);
}

// authorizeTask decides whether one POST /tasks request may run. expectedToken
// is this box's own secret; empty means the daemon seeded none, in which case
// every task is refused — fail closed, so an unseeded box serves nobody rather
// than serving everybody.
export function authorizeTask(authorization: string | undefined, expectedToken: string): A2AAuthOutcome {
  if (expectedToken === "") {
    return { ok: false, status: 401, error: `a2a: this box holds no daemon credential (${A2A_TOKEN_ENV} unset); every task is refused` };
  }
  const m = BEARER_HEADER.exec((authorization ?? "").trim());
  if (m === null) {
    return { ok: false, status: 401, error: "a2a: missing or malformed Authorization: Bearer credential" };
  }
  if (!sameSecret(m[1], expectedToken)) {
    return { ok: false, status: 403, error: "a2a: credential is not this box's daemon credential" };
  }
  return { ok: true };
}

// A2AServerOptions is everything the in-box A2A surface needs. expectedToken is
// the per-box daemon credential (A2A_TOKEN_ENV); warn reports operational
// problems (default: the process log).
export interface A2AServerOptions {
  seed: Seed;
  engine: Engine;
  cfg: EngineConfig;
  journals: TaskJournals;
  expectedToken: string;
  port?: number;
  warn?: (msg: string) => void;
}

function failedArtifact(error: string): AgentArtifactWire {
  return { taskId: "", outputJson: "", state: "AGENT_TASK_STATE_FAILED", error };
}

function respond(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

// createA2AServer builds the Phase-1 A2A surface served from inside the box:
//   GET  /agent-card  -> the seeded agent card (discovery; unauthenticated — it
//                        runs no engine and writes no journal)
//   POST /tasks       -> run one task for the daemon, return the artifact
// The server is returned un-listened so a test can bind an ephemeral port.
//
// A failed task still returns 200 with state FAILED so the caller (the daemon's
// SendAgentTask) receives the artifact rather than an HTTP error. A REFUSED
// task is different: 401/403, and it never reaches runTask — so no engine runs
// and no journal line is written.
export function createA2AServer(opts: A2AServerOptions): Server {
  const warn = opts.warn ?? ((msg: string) => process.stdout.write(`${msg}\n`));
  if (opts.expectedToken === "") {
    warn(`agent-runtime: ${A2A_TOKEN_ENV} is not set; POST /tasks refuses every task (fail closed)`);
  }
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.method === "GET" && req.url === "/agent-card") {
      respond(res, 200, opts.seed.agentCard ?? {});
      return;
    }
    if (req.method === "POST" && req.url === "/tasks") {
      // Authenticate FIRST: before the body is read or parsed, before the
      // engine is invoked, and before any journal is opened.
      const auth = authorizeTask(req.headers.authorization, opts.expectedToken);
      if (!auth.ok) {
        warn(`agent-runtime: refused an A2A task (${String(auth.status)}): ${auth.error}`);
        respond(res, auth.status, failedArtifact(auth.error));
        req.resume(); // discard the unread body; never parse it
        return;
      }
      void (async () => {
        try {
          const body = await readBody(req);
          const task = JSON.parse(body || "{}") as AgentTaskWire;
          const artifact = await runTask(task, opts.engine, opts.cfg, opts.journals);
          respond(res, 200, artifact);
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          respond(res, 400, failedArtifact(msg));
        }
      })();
      return;
    }
    res.writeHead(404);
    res.end();
  });
}

// startA2AServer serves the A2A surface on opts.port (default A2A_PORT) until
// the box stops.
export function startA2AServer(opts: A2AServerOptions): void {
  const port = opts.port ?? A2A_PORT;
  createA2AServer(opts).listen(port, () => process.stdout.write(`agent-runtime: A2A server listening on :${String(port)}\n`));
}
