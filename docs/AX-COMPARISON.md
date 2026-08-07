# Containarium vs. Google AX (Agent Executor)

A comparison of Containarium against [google/ax](https://github.com/google/ax)
— "an open source distributed agent runtime", announced 2026-05-21
alongside GKE Agent Sandbox GA and the Agent Substrate preview.

**tl;dr:** Google published a three-layer decomposition of the stack
Containarium has been building as one vertical. Their Layer 1 is
literally the same code we already run on the K8s backend
(`sigs.k8s.io/agent-sandbox`). The layer that is genuinely *not* the
same is AX itself: its whole thesis is **durable execution — an event
log and a resumption protocol**, and that is the one part of our agent
surface that is explicitly in-memory today.

## The layering

Google's stack, per the
[GKE announcement](https://cloud.google.com/blog/products/containers-kubernetes/bringing-you-agent-sandbox-on-gke-and-agent-substrate):

| Layer | Google | What it does |
|---|---|---|
| 3 — runtime / harness | **AX** (`google/ax`) | Coordinates the agentic loop; event log; resumption; harness + skill + MCP-tool isolation |
| 2 — actor control plane | **Agent Substrate** | Maps actors onto warm worker pods; create/destroy/suspend/resume/route; density |
| 1 — secure runtime | **Agent Sandbox** (`kubernetes-sigs/agent-sandbox`) | Sandbox CRD, pod snapshots, warm pools, gVisor/Kata isolation, default-deny NetworkPolicy |

Containarium's equivalent, all in one repo:

| Layer | Containarium | Where |
|---|---|---|
| 3 | `AgentSkillService` / `CrewService` / the `agent-runtime` in-box loop / pull queue | `proto/containarium/v1/agent.proto`, `internal/server/agent_*.go`, `crew_server.go` |
| 2 | The daemon: placement, multi-backend fleet, tenant registry, TTL/auto-sleep, routing | `internal/server/`, `pkg/core/box/` |
| 1 | Unprivileged LXC/Incus **or** `sigs.k8s.io/agent-sandbox` on K8s | `pkg/core/incus/`, `pkg/core/box/k8s/` |

## The strongest similarity: we already run their Layer 1

`pkg/core/box/k8s/sandbox.go` imports
`sigs.k8s.io/agent-sandbox/api/v1beta1` and builds the same `Sandbox`
CR that Agent Substrate and AX sit on. Two consequences worth naming:

- We already use `SandboxOperatingModeSuspended` / `…Running` for
  autostart (`sandbox.go:125-157`) — i.e. the suspend/resume primitive
  is in our hands on the K8s path, not just Google's.
- We already support gVisor: `podOptions.RuntimeClass` is passed
  verbatim to `RuntimeClassName`, so `runsc` puts a box in a gVisor
  sandbox. It is unset by default (`sandbox_test.go` guards that as a
  no-regression), so it's opt-in rather than native-by-default.

This is convergent evolution, not imitation in either direction — both
projects landed on the same CRD because it's the K8s-native way to
express "isolated, stateful, singleton workload."

## Where the designs agree

| Concern | AX | Containarium |
|---|---|---|
| Not a framework | "not an agentic framework"; framework-agnostic | Same thesis, stated in `docs/AGENT-SKILLS-CREWS-DESIGN.md`: "Containarium is the trust fabric, not another agent framework" |
| Self-hosted | "not a managed service" | Self-hosted daemon; cloud is a separate wrapper |
| Isolated env per agent | Dynamically provisioned isolated environments | One box per agent/skill (`RunAgentSkill` provisions a box with a scoped JWT) |
| Skills + MCP tools | Agent Skills + MCP-compliant tools, run in isolation | `AgentSkill` proto + `cmd/agent-box` in-the-box MCP |
| Language | Go (+ Python) | Go |
| License / maturity | Apache 2.0, "active early development", breaking changes expected | Apache 2.0; agent surface is Phase 0–3 with prototype-marked pieces |
| Worker crash recovery | Resumption protocol | Lease + visibility-timeout redelivery (`internal/server/agent_task_queue.go`) |

## Where they genuinely differ

### 1. Durability — AX's core claim, our known gap

> **Corrected 2026-08-07 after running the spike**
> ([`AX-HARNESS-ADAPTER-SPIKE.md`](AX-HARNESS-ADAPTER-SPIKE.md)): the
> resumption claim below is AX's *stated* positioning, and it is **not
> implemented** at `f327e23`. Resuming an incomplete execution is a TODO
> (`internal/controller/controller.go:72`), `ExecRequest.last_step` is never
> read by the server, and a resume attempt fails before reaching the harness.
> The durable event log itself is real and works. Read this section as "what
> AX intends", not "what AX has" — and note that it makes the gap between us
> narrower than this comparison originally implied.

AX is built around a durable event log: interrupted executions are
*intended* to continue by **replaying missed events** rather than rewinding
the conversation. Ours does not survive a daemon restart, and the code says so:

- `internal/server/crew_run_store.go`: *"Phase 3 keeps runs in memory
  (they don't survive a daemon restart)."*
- `internal/server/agent_task_queue.go`: *"Durability (survive daemon
  restart), per-tenant fairness, and dead-letter handling are
  follow-ups; Phase 0 is memory-only."*

We have **worker**-crash recovery (lease expiry → redelivery). We do
not have **controller**-restart recovery, and there is no event log to
replay from. `EventService` is a subscribe-only stream
(`events.proto`), not a durable log.

This is the sharpest and most actionable difference.

### 2. Resume latency

Agent Substrate snapshots an idle actor's RAM + filesystem and
reactivates in under a second; GKE claims 90% of sandbox allocations
inside 200ms. Our `auto_sleep` **stops** the box; coming back is a cold
start. `docs/EPHEMERAL-SANDBOX-DESIGN.md` already logged this gap
(filed against CubeSandbox's MicroVM cold-start, same underlying
issue) and it remains unbuilt.

### 3. Deployment surface

AX and Substrate are Kubernetes-shaped. Containarium's primary backend
is bare LXC hosts — including BYOC hardware with no cluster at all —
with K8s as *one* backend behind the same box vocabulary. For an
operator who doesn't run Kubernetes, AX isn't an option and we are.

### 4. What the agent talks to

Ours is SSH → `ForceCommand agent-box` → stdio MCP, deliberately so any
off-the-shelf agent (Claude Code, Cursor, a customer-built agent) drives
a box unmodified — the BYOA shape. AX asks you to implement a
**harness** against its contract. Ours is a lower bar to adopt; theirs
gives the runtime more to work with (which is what buys the event log).

### 5. Multi-tenancy and the trust fabric

AX describes a "multi-tenant gRPC controller." Containarium's tenancy
story is considerably wider and is the thing we should not concede:
per-tenant eBPF egress policy (`internal/netbpf`), audit logging to
Postgres, scope-gated JWTs, KMS/secrets with audit-on-read, ingress /
routing / DNS / custom domains, GPU passthrough, metering. AX is
execution reliability; it is not a network, identity, or ingress
platform.

### 6. Where the agent's credential lives

AX runs the harness *inside* the isolated environment. Our
`docs/AGENT-DATA-PLANE-SEPARATION-DESIGN.md` argues the opposite
direction: the box is data + tools only; the skill logic and the model
credential stay with the agent *outside* the box, so a compromised box
yields neither. This is a real design disagreement, not a maturity gap
— and it's defensible positioning.

## Read

The similarity is close enough that "how is this different from
Google's AX?" is now a question we should expect from any technical
buyer, and the honest answer has three parts: we share their Layer 1;
we sit on hardware they don't serve; and they have a durable event log
today while our run state is in memory — but **neither of us can resume
an interrupted run**, theirs being a TODO rather than a shipped feature.

The gap worth closing is durability — not because AX exists, but
because "a daemon restart loses in-flight crew runs" is a defect on its
own terms, and our own code comments have flagged it as a follow-up
since Phase 0.

## Sources

- [google/ax](https://github.com/google/ax)
- [Bringing you Agent Sandbox on GKE and Agent Substrate](https://cloud.google.com/blog/products/containers-kubernetes/bringing-you-agent-sandbox-on-gke-and-agent-substrate) (2026-05-21)
- [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
