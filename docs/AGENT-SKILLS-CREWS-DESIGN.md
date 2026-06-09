# Agent Skills & Crews — Design Note

> Status: **Exploration / not yet approved.** Proto stub lives at
> `proto/containarium/v1/agent.proto` (also marked unapproved). This note
> proposes the **generic mechanism** for running collaborating agents on top of
> Containarium. Concrete skills and crews — compliance packs, research crews,
> domain catalogs — are built on this mechanism and ship **outside this
> repo**; nothing task-specific belongs here. Nothing below is wired yet.

## The thesis: Containarium is the trust fabric, not "another agent framework"

Anyone can stand up a CrewAI / LangGraph / AutoGen crew today. That is not a
moat, and we should not try to win on orchestration ergonomics.

What Containarium *uniquely already has* — and what almost no agent framework
has — is the thing that matters the moment agents start talking to each other
and touching real systems:

- **Per-box isolation** — every agent runs in its own LXC sandbox, not a
  thread in one process.
- **eBPF network policy** — deny-by-default, egress allowlist, enforced
  in-kernel (Phase A shipped; see `NetworkPolicyService`).
- **Audit logging** — every action, username, IP, timestamp, to Postgres
  (`internal/audit/`, `/v1/audit/logs`).
- **Scope-gated MCP tools** — `containers:create` etc., JWT-claim validated
  (`internal/auth/scopes.go`).
- **Secrets encryption + KMS** — AES-256-GCM, audit-logged on read.

So the product framing is: **agent-to-agent collaboration where every hop is
sandboxed, network-policy-gated, and audit-logged.** That is the moat. It is
also what makes Containarium the right substrate for the workloads where the
*how* of agent collaboration matters as much as the result — untrusted code,
multi-tenant fan-out, anything an auditor will later ask about. The mechanism
here is deliberately neutral about *which* such workload; those are built on
top, elsewhere.

## What's missing today

From the current surface (MCP, `RecipeService`, `EventService`, audit,
`NetworkPolicyService`, `SecurityService`, `PentestService`), exactly three
pieces are absent:

1. **An agent as a first-class, runnable, packaged unit.** A recipe gives you
   the box; nothing gives you the *agent* (its prompt, its allowed tools, its
   allowed peers).
2. **Agent-to-agent transport.** `EventService` is observe-only fan-out; MCP
   is agent→tool, not agent→agent request/reply.
3. **Crew / orchestration.** No workflow, choreography, or pipeline exists.

This note fills those three with the smallest surface that preserves the
trust-fabric guarantees.

## Three channels, kept separate

| Channel | Direction | Carries | Status |
|---|---|---|---|
| **MCP** | agent → platform / box | "do things": create container, run shell, read logs | exists |
| **A2A** | agent ↔ agent | "delegate a task, get an artifact back" | **new** |
| **EventService** | platform → agents | "container created → wake the worker" (async triggers/observation) | exists |

We adopt the **A2A (Agent2Agent) protocol** for inter-agent transport rather
than inventing a bus. It is the emerging standard (agent cards, tasks,
artifacts), it is request/reply with streaming, and it fits proto-first
cleanly. We **insulate it behind our own proto** (`AgentCard`, crew messages)
so upstream A2A churn can't break the `AgentSkill`/`Crew` surface — the same
way recipes are insulated from backend churn.

## The "skill" abstraction: Recipe + Agent Manifest

A **skill = a recipe (the box) + an agent manifest (the agent layer).** See
`AgentSkill` in the proto stub. The manifest's load-bearing fields:

```
AgentSkill {
  recipe_ref / recipe   // the box: image, resources, gpu
  system_prompt         // who this agent is
  allowed_scopes[]      // which MCP tools it may call  → minted into its JWT
  agent_card            // A2A discovery: name, capabilities, in/out schema
  allowed_peers[]       // which OTHER skills it may talk to → COMPILES TO eBPF
}
```

**`allowed_peers` is the keystone.** It compiles directly into an eBPF
`NetworkPolicy` egress allowlist. A skill that is only allowed to talk to one
peer *literally cannot open a socket to anything else* — dropped in-kernel, and
the attempt is logged. The crew topology and the network ACL are the same
artifact.

Corollary (and a hard rule per `CLAUDE.md`'s strong-typing convention):
`allowed_scopes` and `allowed_peers` are **typed, first-class fields, never a
prompt string**. If a skill is just "a recipe plus a system prompt blob," the
network-gating differentiator never materializes and we've built a worse
CrewAI. **The typing is the product.**

## Crews

A **crew** is a collaborating set of skills bound to a task purpose
(`Crew` + `CrewService`). The daemon, on `RunCrew`:

1. Validates the crew's topology against the union of member skills'
   `allowed_peers` — **rejects any A2A edge that network policy would drop**
   (no silent "the prompt says talk to X but the kernel blocks it").
2. Provisions each skill's box.
3. Compiles per-agent `NetworkPolicy` from `allowed_peers`.
4. Threads **one `trace_id`** through every agent's audit entries — so a crew
   run is itself an evidence artifact.

`CLI-first` per convention: `containarium crew run <crew.yaml>`; the MCP tool
and `CrewService` REST endpoint are thin wrappers over the same Go function.

The crew *mechanism* lives here; the crew *definitions* (which skills, what
topology, for what purpose) ship outside this repo as catalogs.

## Roadmap (mechanism only)

All phases below are the generic substrate that lives in this repo. Concrete
skill/crew catalogs are built on top of it and shipped separately.

| Phase | Deliverable |
|---|---|
| **0 — Agent-as-a-box** | `AgentSkill` proto; `containarium agent run <skill>` launches one agent in a box with scoped MCP access. Reuses agent-box + recipe + scopes. |
| **1 — A2A transport** | Agent card served per box; `containarium agent call` request/reply. Two agents collaborate; B returns an artifact to A. |
| **2 — Trust fabric** ← moat | `allowed_peers` → eBPF `NetworkPolicy`; every A2A hop audit-logged under a shared `trace_id`. **Demo: an agent that tries to reach a non-allowed peer is dropped in-kernel and logged.** This is the slide that separates us from CrewAI. |
| **3 — Crew primitive** | `containarium crew run <crew.yaml>` — declarative topology, shared artifact store, single trace. |

## Phase 0 — issue breakdown

1. **`proto/containarium/v1/agent.proto` → real.** Finalize `AgentSkill` +
   `AgentSkillService` (defer `Crew`/`CrewService` to Phase 3). `make proto`.
2. **`agent-runtime` recipe.** A box image with the model client + agent-box
   MCP preinstalled, so a skill's `recipe_ref` can point at it.
3. **`internal/server/agent_server.go`.** Implement `RunAgentSkill`: mint a
   JWT scoped to exactly `allowed_scopes`, provision the box (reuse
   `RecipeService` deploy path), inject prompt + scoped token, run one task,
   return the artifact. No peers yet.
4. **CLI: `internal/cmd/agent.go`.** `containarium agent list|get|run` →
   thin cobra over the generated client (CLI-first).
5. **MCP wrapper.** `run_agent_skill` tool in `internal/mcp/tools.go`,
   `RequiredScope: "agents:run"` — thin wrapper over the same Go function.
6. **Scope additions.** Add `agents:run` to `internal/auth/scopes.go`.
7. **A neutral reference skill.** A generic example (e.g. a shell/worker
   skill) used only to prove the runtime end-to-end — kept deliberately
   task-agnostic. Real, opinionated skills live outside this repo.
8. **Docs.** `docs/AGENT-SKILLS-QUICKSTART.md` (mirror `MCP-QUICKSTART.md`).

## Risks / open questions

1. **Don't let "skill" decay into "recipe + a prompt string."** If the
   manifest doesn't carry `allowed_scopes` / `allowed_peers` as typed,
   compiled fields, the network-gating differentiator never ships. Gate this
   in review.
2. **A2A is young.** Pin a version; keep it behind our proto so the wire
   format can be swapped without breaking `AgentSkill`/`Crew`.
3. **Model-driving runtime placement.** Where does the agent loop actually
   run — inside the box (agent-box reachable over stdio/SSH) or a
   daemon-side driver? Phase 0 leans "inside the box" to reuse agent-box and
   keep the model's blast radius inside the sandbox; revisit for crews.
4. **Cost/quotas.** Crews fan out boxes; tie into the existing per-tenant
   accounting + ephemeral-sandbox warm-pool work
   (`docs/EPHEMERAL-SANDBOX-DESIGN.md`) so an agent inner loop isn't paying
   30–90s box-create each hop.
5. **Secret exposure to agents.** Agents should read secret *metadata/config*,
   never plaintext, unless the skill explicitly declares the scope. Enforce
   via scope granularity, not convention.
