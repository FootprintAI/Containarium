# Agent / Data-Box Separation — the box is the data plane, the agent is the control plane

> Status: **Proposal / direction.** This evolves the in-box loop described in
> `docs/AGENT-RUNTIME-INBOX-LOOP-DESIGN.md` (shipped: the `agent-runtime` loop
> runs *inside* the box). It records the target separation: the box holds **data
> + tools only**; the **agent runs outside the data box**, holding the skill and
> driving the model. Not all of this is built — the current code runs the loop
> in-box; this is the direction to migrate toward.

## The one-line model

```
   ┌──────────────── data box (per task / per domain) ───────────────┐
   │  the customer's DATA            agent-box MCP (shell / files)    │   ← data plane
   │  (no skill, no API key)         = the tool + data surface        │
   └───────────────────────────────────────┬─────────────────────────┘
                                            │  MCP (read data, call tools)
                                            ▼
   ┌──────────────────────── the agent (outside the box) ────────────┐
   │  holds the SKILL logic + drives the MODEL                        │   ← control plane
   │  reads data from the box, generates output, writes it back       │
   │  per-tenant isolated; credential held here, never in the box     │
   └──────────────────────────────────────────────────────────────────┘
```

The box is a **sandboxed data plane**: it holds the data and exposes it through
the `agent-box` MCP server (in-the-box shell + file ops). The **agent is the
control plane**: it connects to the box's MCP surface, reads the data, runs the
skill logic and the model call **on its own side**, and writes outputs back into
the box. The skill definition and the model-provider credential **never enter
the data box**.

## Two invariants

1. **A data box never holds the skill or a credential.** It holds data + the
   `agent-box` tool surface, nothing else. The curated skill logic (the
   valuable part) and any API key stay with the agent. This both protects the
   skill IP and removes the box as a place a credential can be read from.
2. **The agent is per-tenant isolated.** Because the agent now holds the
   credential and the skill (a wider blast radius than a sandboxed box), the
   agent itself must run in a per-tenant-isolated context — a compromised agent
   (e.g. via prompt injection from data it read) must not be able to reach
   another tenant's boxes or the raw credential. See "Prompt-injection" below.

## Why separate them

- **Credential safety.** With the loop in-box, the model key has to be present
  in the box (env / seeded secret) so the in-box loop can call the provider.
  Whoever can reach that box's filesystem/process can read the key — and the
  egress allowlist doesn't help (it *permits* the provider endpoint, so a
  hostile in-box process can exfiltrate to it). Moving the model call to the
  agent means the key is never in the box at all.
- **Skill-IP protection.** The skill (system prompt, tool plan, the curated
  logic) is the differentiated, often paid, part. Shipping it into a box exposes
  it to the box owner. Keeping it agent-side keeps it off the box.
- **It is the BYOA shape we already have.** `agent-box` (`cmd/agent-box`) was
  built as the in-the-box MCP surface that *any external agent* (Claude Code,
  Cursor, a customer-built agent) drives over stdio/SSH. "Agent outside, box is
  the tool surface" is exactly that primitive — this aligns the agent-skills
  mechanism with it instead of inverting it.

## Credential model

- **Bring-your-own-key (self-host / OSS).** The agent runs with the **user's
  own** provider key, held by the agent process (outside the box). The user
  holding their own key, in their own agent, is fine — there is no foreign key
  in a box.
- **Hosted (a platform runs the agent for tenants).** The platform's raw
  provider key must **never** reside in any box — not even the agent's box.
  Hosted inference goes through a **model gateway**: the agent calls the gateway
  with a scoped, revocable, per-tenant token; the gateway holds the real
  provider key and proxies to the provider (and meters). The gateway and the
  hosted/multi-tenant specifics are a cloud concern and out of scope for this
  OSS note (see the cloud PRDs); what OSS fixes is the **shape**: the agent, not
  the box, talks to the model.

## Transport

Today the in-box loop spawns `agent-box` as an MCP server over **local stdio**
(same box). Under this model the agent connects to the box's `agent-box` over a
**remote transport** (e.g. SSH-wrapped stdio, the existing BYOA path, or a
network MCP transport) — the data box still runs `agent-box`; only the agent
moved out. The agent-runtime engines already mount `agent-box` as an MCP server;
the change is the transport, not the engine contract (see the engine interface
in `agent-runtime/src/engine.ts`).

## Relationship to the shipped in-box loop

`docs/AGENT-RUNTIME-INBOX-LOOP-DESIGN.md` and the merged Phase-4 code run
`agent-runtime` **inside** the box, with `system_prompt.txt` / `input.json` /
`token` / the model key seeded into the box. That was the simplest way to close
the "box up, nothing runs" seam and is correct for self-host single-principal
use. This note records the next step:

- **Keep** `agent-box` in the box (the data + tool surface).
- **Move** the agent loop (`agent-runtime`) **out** of the data box, into a
  per-tenant-isolated agent context that reads the box over MCP.
- **Stop** seeding the skill and the credential into the data box; the agent
  holds them.

Migration is incremental: the engine code is reusable (it already speaks MCP to
`agent-box`); the work is relocating where the loop runs and switching the MCP
transport from local stdio to remote.

## Prompt-injection containment

In-box, a hijacked agent was trapped in the sandbox. With the agent outside
holding the credential, containment must be re-established on the agent side:
the agent runs per-tenant-isolated, reaches only its own tenant's boxes (the
trust-fabric `allowed_peers` / network policy still applies to box↔box and
agent↔box edges), and — hosted — never holds the raw key (gateway token only,
revocable). The net blast radius of a hijack is then: one tenant's data boxes +
a revocable scoped token, never the provider key or another tenant.

## Validated: gateway key-custody on the RunAgentSkill path

The credential-custody invariant ("a data box never holds the key") is
independent of *where the agent loop runs*, and the **model-gateway** half is
already shipped and validated. Below is the live `RunAgentSkill` flow with the
daemon serving the gateway (provider keys held only in the daemon; each box gets
a scoped, revocable token + the gateway URL).

> Scope note: in this validation the agent loop still runs **in-box** (the
> shipped in-box loop) — only the model call is externalized to the gateway. That
> already establishes the credential invariant. Relocating the loop *out* of the
> data box (the rest of this note) is the remaining step; it does not change the
> custody mechanism shown here.

```
  ┌────────────┐  containarium agent run <skill> --input '{...}'   (HTTP + JWT)
  │  operator  │───────────────────────────────────────────────────────────────┐
  └────────────┘                                                                 ▼
                                  ┌──────────────────────────────────────────────────┐
                                  │  DAEMON  (model-gateway enabled; holds provider key)│
   POST /v1/agent-skills/<id>/run │  ┌────────────────────────────────────────────────┐│
  ───────────────────────────────┼─▶│ RunAgentSkill                                    ││
                                  │  │  1. resolve manifest (CONTAINARIUM_SKILLS_DIR)   ││
                                  │  │  2. provision / REUSE box  agent-<id>-container  ││
                                  │  │  3. mint scoped JWT (= skill.allowed_scopes)     ││
                                  │  │  4. mint GATEWAY token (bound to tenant+skill)   ││
                                  │  │  5. seed: system_prompt.txt · input.json ·       ││
                                  │  │           token · gateway.env                    ││
                                  │  └───────────────┬──────────────────────────────────┘│
                                  │                  │ exec: bash -lc agent-runtime        │
                                  │                  ▼                                     │
                                  │  ┌────────────────────────────────────────────────┐  │
                                  │  │ agent box (LXC) — DATA / TOOL plane              │  │
                                  │  │  • engine + agent-box (in-box MCP tool surface) │  │
                                  │  │  • NO provider key in the box                   │  │
                                  │  │  • gateway.env → MODEL_GATEWAY_URL + token      │  │
                                  │  └───────────────┬──────────────────────────────────┘  │
                                  │   model call     │ Authorization: Bearer <gateway-token>│
                                  │   ◀──────────────┘                                      │
                                  │  ┌────────────────────────────────────────────────┐  │
                                  │  │ MODEL GATEWAY: verify token → inject REAL key → │──┼──▶ provider API
                                  │  │ proxy → meter per-tenant usage                  │  │   (e.g. Anthropic /
                                  │  └────────────────────────────────────────────────┘  │    Gemini / OpenAI)
                                  └──────────────────────────────────────────────────────┘
                                                     │ artifact.json (outputJson)
   ◀──────────────────────────────────────────────────┘   ← RunAgentSkill returns the artifact
```

What this demonstrates, observed end-to-end: the box's env carries **no**
provider key — only `CONTAINARIUM_MODEL_GATEWAY_URL` + a scoped
`CONTAINARIUM_GATEWAY_TOKEN` — yet the run produces a real artifact. Every model
call therefore crosses `box → gateway → provider`; a compromised box yields a
revocable token, never the key. This is the credential half of the two
invariants above, on the real `RunAgentSkill` path.

## See also

- `docs/AGENT-RUNTIME-INBOX-LOOP-DESIGN.md` — the in-box loop this evolves.
- `docs/AGENT-SKILLS-CREWS-DESIGN.md` — the mechanism (skill = box + manifest;
  crew = collaborating skills; `allowed_peers` → eBPF; trace_id audit).
- `cmd/agent-box` — the in-the-box MCP surface (the data plane's tool surface).
- `agent-runtime/` — the engine-pluggable loop (Claude / Codex / Gemini); the
  component that relocates from in-box to agent-side under this model.
