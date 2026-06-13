import { runTask } from "./a2a.js";
import type { Engine, EngineConfig } from "./engine.js";

// poll.ts — worker side of the pull-based run queue (prototype). Instead of the
// daemon exec-ing a run into the box (push), a long-lived worker box LEASES
// tasks from the daemon/gateway over HTTP, runs them locally through the same
// engine, and reports the result back. All traffic is OUTBOUND from the box, so
// it works behind NAT / a tunnel with no inbound listener.
// See docs/AGENT-MODEL-GATEWAY-DESIGN.md (pull-queue section).

// Wire shapes match protojson (lowerCamelCase) on the agent-tasks endpoints.
interface LeaseResponseWire {
  hasTask?: boolean;
  taskId?: string;
  skillId?: string;
  inputJson?: string;
  leaseToken?: string;
}

export interface PollConfig {
  // Base URL of the daemon/gateway, e.g. "https://<host>:8080".
  baseUrl: string;
  // Bearer token authorizing the queue calls (needs agents:run). This is the
  // worker's *runtime* credential, distinct from the skill's in-box token —
  // see the design note's open question on who mints it.
  token: string;
  workerId: string;
  // Lease only this skill's tasks; "" = any skill.
  skillId: string;
  // Visibility timeout requested per lease; keep > worst-case run time.
  leaseSeconds: number;
  // Backoff when the queue is empty.
  idleMs: number;
  // When true, process exactly one task then return (live-test / one-shot).
  once: boolean;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function postJSON(url: string, token: string, body: unknown): Promise<Response> {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
}

async function lease(cfg: PollConfig): Promise<LeaseResponseWire> {
  const res = await postJSON(`${cfg.baseUrl}/v1/agent-tasks/lease`, cfg.token, {
    workerId: cfg.workerId,
    skillId: cfg.skillId,
    leaseSeconds: cfg.leaseSeconds,
  });
  if (!res.ok) throw new Error(`lease failed: HTTP ${res.status} ${await res.text()}`);
  return (await res.json()) as LeaseResponseWire;
}

async function complete(
  cfg: PollConfig,
  taskId: string,
  leaseToken: string,
  artifactJson: string,
  error: string,
): Promise<boolean> {
  const res = await postJSON(
    `${cfg.baseUrl}/v1/agent-tasks/${encodeURIComponent(taskId)}/complete`,
    cfg.token,
    { taskId, leaseToken, artifactJson, error },
  );
  if (!res.ok) throw new Error(`complete failed: HTTP ${res.status} ${await res.text()}`);
  const out = (await res.json()) as { accepted?: boolean };
  return out.accepted === true;
}

// runPollLoop leases → runs → completes until aborted (or once). Errors on a
// single iteration are logged and the loop backs off; one bad task never kills
// the worker.
export async function runPollLoop(
  cfg: PollConfig,
  engine: Engine,
  engineCfg: EngineConfig,
  signal?: AbortSignal,
): Promise<void> {
  while (!signal?.aborted) {
    try {
      const leased = await lease(cfg);
      if (!leased.hasTask || !leased.taskId || !leased.leaseToken) {
        if (cfg.once) return;
        await sleep(cfg.idleMs);
        continue;
      }

      // runTask (shared with the A2A path) never throws — a failed run comes
      // back as state FAILED, which we map to the completion's error field.
      const art = await runTask(
        { id: leased.taskId, inputJson: leased.inputJson },
        engine,
        engineCfg,
      );
      const errMsg = art.state === "AGENT_TASK_STATE_FAILED" ? art.error : "";
      const accepted = await complete(cfg, leased.taskId, leased.leaseToken, art.outputJson, errMsg);
      process.stdout.write(
        `agent-runtime poll: task ${leased.taskId} ${errMsg ? "failed" : "done"}` +
          `${accepted ? "" : " (lease stale — result dropped)"}\n`,
      );

      if (cfg.once) return;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      process.stderr.write(`agent-runtime poll: iteration error: ${msg}\n`);
      await sleep(cfg.idleMs);
    }
  }
}

// pollConfigFromEnv reads the worker's poll settings from the environment the
// daemon stamps onto a worker box.
export function pollConfigFromEnv(): PollConfig {
  const baseUrl = process.env.CONTAINARIUM_QUEUE_URL ?? "";
  const token = process.env.CONTAINARIUM_QUEUE_TOKEN ?? "";
  if (!baseUrl || !token) {
    throw new Error("poll mode needs CONTAINARIUM_QUEUE_URL and CONTAINARIUM_QUEUE_TOKEN");
  }
  return {
    baseUrl: baseUrl.replace(/\/$/, ""),
    token,
    workerId: process.env.CONTAINARIUM_WORKER_ID ?? "worker",
    skillId: process.env.CONTAINARIUM_QUEUE_SKILL ?? "",
    leaseSeconds: Number(process.env.CONTAINARIUM_LEASE_SECONDS ?? "300"),
    idleMs: Number(process.env.CONTAINARIUM_POLL_IDLE_MS ?? "2000"),
    once: process.env.CONTAINARIUM_POLL_ONCE === "1",
  };
}
