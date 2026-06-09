# Agent Runtime — In-Box Loop Design Note

> Status: **Exploration / not yet approved.** This proposes the `agent-runtime`
> box image's in-box loop — the one seam carried across Phases 0–3 of the
> agent-skills mechanism (see `docs/AGENT-SKILLS-CREWS-DESIGN.md`). Nothing
> here is built yet.

## What this closes

The daemon-side agent-skills mechanism is shipped (Phases 0–3): a skill is
provisioned into its own box with a scoped JWT, its `allowed_peers` compile to
an eBPF egress policy, A2A delegation is gated + audited, and crews validate
their topology against the trust fabric. But every one of those phases left the
**same seam**: the box is provisioned, scoped, network-gated, and seeded — and
then nothing runs inside it. Concretely:

- `agent run` returns an **empty `artifact_json`** (the box is up; no agent ran).
- `agent call` / `SendAgentTask` reaches **no A2A listener** (`Unavailable`).
- `crew run` lands in **`RUNNING`, never `COMPLETED`** (boxes up; no choreography).

The **in-box loop** is what turns a provisioned-scoped-gated-traced box into a
working agent. It is the `agent-runtime` image's job, deliberately kept out of
the daemon so the daemon stays a pure control plane.

## What the box already has (from RunAgentSkill)

Seeded under `/etc/containarium/agent/` at launch:

| File | Contents |
| --- | --- |
| `system_prompt.txt` | the skill's persona |
| `token` | a JWT scoped to **exactly** the skill's `allowed_scopes` (mode 0600) |
| `input.json` | the task input |
| `agent-card.json` | the skill's A2A discovery doc |

Plus: the **agent-box MCP** (`cmd/agent-box`) is already present in the box —
in-the-box shell + file ops over stdio. That is the in-box loop's tool surface.

## Architecture

The in-box loop is a long-lived process (the `agent-runtime` image's
entrypoint) that does two things:

```
            ┌──────────────────────── agent-runtime box ───────────────────────┐
            │                                                                   │
  /tasks ──▶│  A2A server (:8674)                                               │
            │     POST /tasks {AgentTask}  ──┐                                  │
            │     GET  /agent-card  ─────────┼─ serves agent-card.json          │
            │                                ▼                                  │
            │                         ┌──────────────┐   tool calls   ┌───────┐ │
            │   seed (/etc/.../agent) │  agent loop  │ ─────────────▶ │ agent │ │
            │   - system_prompt.txt ─▶│  (Claude API │   shell/files  │ -box  │ │
            │   - token (scoped JWT)  │   tool-use)  │ ◀───────────── │  MCP  │ │
            │   - input.json          └──────┬───────┘   results      └───────┘ │
            │                                │                                   │
            │                                │ artifact (JSON)                   │
            │                                ▼                                   │
            │                         /etc/.../agent/artifact.json               │
            └───────────────────────────────────────────────────────────────────┘
                                             │ drives the model
                                             ▼
                                   api.anthropic.com  (Claude API)
```

### The agent loop

A standard **Claude API tool-use loop** (Messages API — `client.messages` with
a manual loop, or the SDK tool runner). NOT Managed Agents — see the
alternative below; the whole premise is that the agent runs in *our* sandbox,
so we drive the model from inside the box.

- **Model:** from the skill manifest's `model` field; default `claude-opus-4-8`.
- **Thinking / effort:** adaptive thinking (`thinking: {type: "adaptive"}`) +
  `output_config: {effort: "high"}` for agentic work (per the Claude API
  guidance for long-horizon/tool-heavy tasks).
- **Tools:** the **agent-box MCP** tools (shell, read/write/edit, process,
  tail-log) are the loop's tool surface. A skill that needs *platform* actions
  (create a container, read audit logs) additionally points the loop at the
  **platform MCP**, authenticated with the seeded scoped `token` — so the
  agent can only do what its `allowed_scopes` permit. The two MCP surfaces stay
  distinct exactly as `CLAUDE.md` requires.
- **System prompt:** `system_prompt.txt`. **Task input:** `input.json`.
- **Artifact:** the loop's final structured output, validated against the
  skill's `agent_card.output_schema_json`, written to `artifact.json`.

### The A2A server

A small HTTP server on `:8674` (the `a2aPort` the daemon already resolves):

- `GET /agent-card` → serves `agent-card.json` (Phase-1 discovery; the daemon
  seeds it, the box serves it).
- `POST /tasks` → body is an `AgentTask` (protojson); run **one** agent-loop
  pass over `task.input_json`; return an `AgentArtifact`. This is the listener
  `SendAgentTask` already POSTs to.

## Two credentials, kept distinct

| Credential | What it authenticates | How it arrives |
| --- | --- | --- |
| **Scoped platform JWT** (`token`) | the agent → Containarium **platform MCP** (containers, audit, etc.), bounded by `allowed_scopes` | already seeded by RunAgentSkill |
| **Anthropic API key** | the agent loop → **Claude API** (drives the model) | seeded via the tenant **secrets** mechanism (AES-256-GCM, mode 0400); **never** in the prompt or task input |

These are not interchangeable. The platform JWT must never reach Anthropic; the
Anthropic key must never reach the platform API. The loop reads the key from
the secret-injected env (or file) at startup, like any other in-box secret.

## How `run` / `call` / `crew` close once this lands

- **`agent run`:** after the box is up, the daemon POSTs the seeded `input.json`
  to the box's `/tasks` and returns the resulting `AgentArtifact` —
  `RunAgentSkillResponse.artifact_json` is no longer empty. (Or the box runs the
  seeded input once at startup and writes `artifact.json`; the daemon reads it
  back. Decide in 4a.)
- **`agent call` / `SendAgentTask`:** already wired end-to-end on the daemon
  side and unit-tested against a stub peer — it starts working against real
  boxes the moment `/tasks` has a listener.
- **`crew run`:** `RunCrew` drives the topology by issuing `SendAgentTask` hops
  (threading the run's `trace_id`), collects the terminal artifact, and moves
  the `CrewRun` from `RUNNING` → `COMPLETED`.

## Interaction with the Phase-2 trust fabric

The in-box loop adds a **new egress requirement**: the box must reach
`api.anthropic.com`. Under observe-only (`LOG_ONLY`, the default) this just
shows up in the audit log. **Before ENFORCE is armed**, the agent-runtime box's
egress allowlist must include the Anthropic API (and DNS) — i.e.
`api.anthropic.com` belongs in the operator-supplied platform egress
(`CONTAINARIUM_AGENT_EGRESS_CIDRS`, or an `egress_domains` entry once domain
policy is wired) alongside the daemon API. Otherwise an armed agent box can
talk to its peers but not to the model — stranded. This is the concrete
instance of the "don't strand the agent" caveat from the Phase-2 docs.

## Security

- **API-key custody:** secrets store → mode 0400 → read once at startup. Never
  logged, never in the prompt/task input/artifact (which are audit-visible).
- **Prompt injection:** the task input is **untrusted** (it may come from
  another agent or a tenant). Containment is exactly the trust fabric we built:
  the loop runs in an isolated box, with a least-privilege scoped token, behind
  an eBPF egress allowlist, fully audited. A compromised loop can do only what
  its `allowed_scopes` + `allowed_peers` permit — that is the point of Phases
  0–2.
- **Cost / runaway:** bound the loop with `max_tokens`, a task budget
  (`output_config.task_budget`, beta), and a wall-clock cap; surface token spend
  in the artifact metadata.

## Alternative considered: Managed Agents (self-hosted sandboxes)

Anthropic's **Managed Agents** with `config: {type: "self_hosted"}` runs the
agent loop on Anthropic's orchestration layer while tool execution happens in a
container *you* control, via an outbound-polling worker. That is a real fit on
paper — less loop code to write. But it inverts control: Anthropic orchestrates,
the box must poll Anthropic's work queue, and the trust-fabric story ("every hop
sandboxed + network-gated + audited *by us*") gets muddier when the loop lives
off-box. For Phase 4 we lean to the **in-box Claude API loop** (full control,
the audit/network story stays clean, no dependency on Anthropic reachability
for orchestration). Managed-Agents-self-hosted is worth revisiting as an opt-in
runtime later — it would reuse the same box, secrets, and egress plumbing.

## Phasing

- **4a — in-box loop, single skill.** Agent-runtime image: read seed, drive the
  Claude API tool-use loop over the agent-box MCP, write `artifact.json`. Closes
  the empty-artifact seam for `agent run`.
- **4b — A2A server.** Add `:8674` serving `/agent-card` + `/tasks`. Closes
  `agent call` / `SendAgentTask` against real boxes.
- **4c — crew choreography.** `RunCrew` drives hops + reports `COMPLETED`.

Each phase is independently demoable, mirroring how Phases 0–3 were built.

## Open questions

1. **Tool runner vs manual loop.** The SDK tool runner is less code; a manual
   loop gives per-tool-call audit/gating hooks. Lean manual for the
   audit-everything posture, but evaluate the runner for 4a.
2. **Artifact-schema enforcement.** Validate the loop's output against
   `output_schema_json` in-box, or let the daemon validate on read? In-box keeps
   the daemon dumb; daemon-side gives a consistent rejection path.
3. **Default model + effort per skill.** `claude-opus-4-8` + `effort: high` is
   the agentic default; should a skill be able to request `medium`/`low` for
   cheap/fast leaf agents? (The manifest already carries `model`; consider an
   `effort` field.)
4. **API-key scoping.** One org key per deployment vs per-tenant keys (cost
   attribution, blast-radius). Ties into the secrets model.
5. **Runtime image distribution.** The `agent-runtime` recipe currently points
   at a base Ubuntu LXC; 4a needs the image to actually contain the loop binary
   + agent-box MCP + the model client. Build + ship that image how?

## See also

- `docs/AGENT-SKILLS-CREWS-DESIGN.md` — the mechanism (Phases 0–3)
- `docs/AGENT-SKILLS-QUICKSTART.md` — the shipped CLI/MCP surface + trust fabric
