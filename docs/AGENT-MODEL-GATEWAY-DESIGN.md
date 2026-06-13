# Agent Model Gateway — Design Note

> Status: **Exploration / not yet approved.** This proposes a daemon-side
> *model gateway* that every agent box calls instead of reaching the model
> provider directly. Nothing here is built yet. Builds on the in-box loop
> (`docs/AGENT-RUNTIME-INBOX-LOOP-DESIGN.md`) and the agent-skills mechanism
> (`docs/AGENT-SKILLS-CREWS-DESIGN.md`).

## What this closes

Today every agent box talks to the model provider **directly**: the in-box
`claude` engine uses the Claude Agent SDK against `api.anthropic.com`, authed
with an `ANTHROPIC_API_KEY` that the daemon stamps onto the LXC as an
environment variable from the tenant secrets store
(`internal/server/secrets_server.go`; egress allow-listed in
`agent_server.go`'s `defaultAgentEgressDomains`). The `codex` engine does the
same against OpenAI.

That works, but it bakes in four problems that compound as the agent fleet
grows:

1. **Key sprawl.** A live, long-lived provider API key sits **inside every
   agent box** as an env var. Any agent (or a prompt-injected one) can read
   `$ANTHROPIC_API_KEY` and exfiltrate it. Rotation means re-stamping every
   box. The blast radius of one compromised box is "the whole key."
2. **No per-tenant model metering.** Token spend is invisible to the platform
   — it lands on whatever provider account the key belongs to, with no
   attribution to the tenant/skill/run that caused it. The metering/billing
   plane meters box-uptime, not model tokens; model spend has **no writer**
   (cf. the egress-meter gap).
3. **No shared cache or pooling.** N boxes each open their own provider
   connection with their own prompt prefix; identical system prompts and tool
   schemas are re-sent and re-billed per box. Prompt caching is per-box, so the
   cache-hit rate across a fleet of same-skill agents is near zero.
4. **Wide egress.** Every agent box must be allowed out to the provider
   API directly, so the egress allow-list can't be tightened to "the platform
   and nothing else."

The **model gateway** is a single daemon-side egress point that holds the
provider key, brokers every box's model calls, and becomes the natural place
to cache, meter, tier, and rate-limit. It is **not** a way to avoid metered
billing — it is metered API, consolidated and attributed. (Using a personal
subscription login across a box fleet is out: it violates the provider's
per-seat subscription terms and that path is being closed off anyway. The
gateway is the ToS-clean way to get the cost/operational wins people reach for
when they ask about the subscription trick.)

## Goals / non-goals

**Goals**

- The provider API key lives in **exactly one place** (the gateway), never in
  an agent box.
- Every model call is **attributed** to `(tenant, skill, run)` and metered in
  tokens.
- **Shared prompt caching** across boxes that share a system prompt / tool
  schema.
- **Model tiering** enforced centrally (cap a skill to Haiku; let another use
  Opus) without trusting the box.
- Agent-box egress shrinks to **the gateway only** — no direct provider egress.
- **Drop-in**: the in-box engines keep using the Agent SDK / Codex SDK
  unchanged; only their *base URL* and *credential* change (see below).

**Non-goals**

- Not a general LLM router/marketplace. Two providers (Anthropic, OpenAI),
  matching today's two engines.
- Not a caching proxy for arbitrary HTTP. Model endpoints only.
- Not a subscription-auth bridge (explicitly excluded — see above).
- Not changing the in-box loop's tool surface (agent-box MCP) or the seed
  contract (`/etc/containarium/agent/`).

## Architecture

```
        ┌──────────────── agent box (per skill/run) ─────────────────┐
        │                                                            │
        │  agent-runtime                                             │
        │    engine (claude | codex)                                 │
        │      Agent SDK / Codex SDK                                 │
        │      ANTHROPIC_BASE_URL = https://<gateway>/v1/model/...   │
        │      ANTHROPIC_AUTH_TOKEN = <short-lived gateway token>    │
        │            │  (model HTTP, bearer = gateway token)         │
        └────────────┼───────────────────────────────────────────────┘
                     │  egress allow-list: gateway ONLY
                     ▼
        ┌──────────────── daemon: model gateway ─────────────────────┐
        │  1. authenticate gateway token  → (tenant, skill, run)     │
        │  2. enforce model tier / policy (allowed models, caps)     │
        │  3. inject provider key (held here, never in the box)      │
        │  4. set/forward prompt-cache breakpoints                   │
        │  5. proxy to api.anthropic.com / api.openai.com            │
        │  6. on response: meter tokens → usage rollups (per tenant) │
        └────────────┬───────────────────────────────────────────────┘
                     │  one key, one egress, shared cache
                     ▼
              api.anthropic.com / api.openai.com
```

### How a box reaches the gateway (the one real change)

The in-box engines are **unchanged Go/TS code**. The Anthropic SDK (and Claude
Code, which the Agent SDK is built on) honor two environment variables:

- `ANTHROPIC_BASE_URL` — the API base the SDK dials.
- `ANTHROPIC_AUTH_TOKEN` — a bearer token sent as `Authorization: Bearer …`
  (used **instead** of a raw `x-api-key` when the base URL is a gateway/proxy).

> ⚠️ Verify against the pinned `@anthropic-ai/claude-agent-sdk` version before
> building — this is the design's linchpin. The pattern is the standard one
> used for LiteLLM / Bedrock-style proxies; if a future SDK changes the env
> contract, the fallback is a thin client option (`baseURL`, `authToken`) wired
> in `agent-runtime/src/engines/claude.ts`. Codex SDK has the analogous
> `OPENAI_BASE_URL` / `OPENAI_API_KEY`.

So the daemon's box-seeding changes from *"stamp `ANTHROPIC_API_KEY` = the real
provider key"* to:

```
ANTHROPIC_BASE_URL  = https://<gateway-host>/v1/model/anthropic
ANTHROPIC_AUTH_TOKEN = <gateway token: scoped to this tenant/skill/run, short-lived>
```

The **real provider key is never in the box.** The box holds only a gateway
token that (a) is bounded to one tenant/skill, (b) expires, and (c) is useless
anywhere but the gateway. A compromised box leaks a throwaway, not the key.

### Gateway token

Reuse the existing scoped-JWT machinery that already mints the box's platform
token (`agent_server.go` `provisionSkillBox`). Add a model-scope claim, e.g.
`model:invoke` plus `tenant`, `skill_id`, `run_id`, and an allowed-model set.
The gateway validates it with the same secret/PKI the rest of the daemon uses
— no new trust root. Short TTL (a run's lifetime); a long-running A2A/serve box
refreshes via the platform token it already holds.

## Gateway responsibilities

| # | Concern | Behavior |
| --- | --- | --- |
| 1 | **Key custody** | The single provider key is read from the daemon's secret store at startup and held in memory; never written to a box. Rotation = restart the gateway, no box churn. |
| 2 | **Auth → identity** | Validate the gateway token; resolve `(tenant, skill, run, allowed_models)`. Reject unknown/expired tokens with `401`. |
| 3 | **Policy / tiering** | If the requested `model` isn't in the token's allowed set, either reject or down-route to the tier ceiling (config). This is where "this skill may only use Haiku" is *enforced*, not merely requested. |
| 4 | **Prompt caching** | Ensure cache breakpoints are set on the stable prefix (system prompt + tool schema) so same-skill boxes share cache hits. Pass through provider cache headers/usage. |
| 5 | **Metering** | On each response, read provider `usage` (input/output/cache-read/cache-write tokens) and write a per-tenant rollup keyed by `(tenant, skill, model)`. This is the model-token *writer* the metering plane lacks today. |
| 6 | **Egress consolidation** | The gateway is the only host allowed out to provider APIs. Agent boxes' egress allow-list drops `api.anthropic.com` / `api.openai.com` and gains only the gateway. |
| 7 | **Rate limiting** | Central per-tenant token-bucket so one tenant's runaway agent can't exhaust the shared account's provider rate limit and starve others. |

## CLI-first surface (proto → gateway is plumbing)

Per repo convention, anything an operator/agent can trigger lands as a
`containarium <verb>` first; the gateway data-plane itself (the proxied model
HTTP) is infrastructure plumbing, like `/healthz` — **not** a product RPC, so
it lives in the gateway layer, not the proto contract.

What *does* go through proto (operator/agent-visible):

- `containarium agent usage [--tenant X] [--skill Y] [--since …]` → reads the
  per-tenant model-token rollups the gateway writes. New `GetAgentModelUsage`
  RPC on the agent service.
- Model-tier policy is part of the **AgentSkill manifest** (a new
  `allowed_models` / `model_tier` field on the skill proto), so the ceiling is
  declared with the skill and compiled into the gateway token at provision
  time — same pattern as `allowed_scopes` → JWT and `allowed_peers` → eBPF.

No new "mint model token" verb is needed: it's minted inside `provisionSkillBox`
exactly where the platform JWT already is.

## Security model

- **Key isolation.** Provider key: gateway only. Box: a scoped, expiring
  gateway token. This is the headline win — it removes the standing
  exfiltration target from every box.
- **Least privilege.** The gateway token's allowed-model set and tenant binding
  mean a compromised box can at most spend *its own* tenant's tokens on *its
  allowed* models, all metered and attributable — versus today, where reading
  one env var yields a fleet-wide provider key.
- **Egress.** With direct provider egress removed from agent boxes, the eBPF
  egress policy for an agent box becomes "platform + gateway," tightening the
  default-deny posture (#315 enforcement still applies).
- **Audit.** Every proxied call is an attributable event `(tenant, skill, run,
  model, tokens)` — a far better audit surface than "some box called Anthropic."

## Metering / billing fit

The gateway is the missing **writer** for model-token usage. It emits per-tenant
rollups in the same shape the uptime sampler uses, so model spend can be rated
alongside box-uptime (a `PerModelTokenCents`-style rate, Cloud-side) without a
new pipeline. OSS ships the *mechanism* (the gateway + the token-usage rollup);
Cloud owns the *rating* (named tiers, per-model cents) — consistent with the
"generic mechanism in OSS, named packs in Cloud" split.

## Phasing

- **Phase 0 — transparent proxy.** Gateway proxies Anthropic only; holds the
  key; validates the gateway token; boxes seeded with `ANTHROPIC_BASE_URL` +
  gateway token instead of the raw key. No metering yet. Acceptance: an agent
  run completes with a non-empty artifact and **no provider key in the box**.
- **Phase 1 — metering.** Parse `usage`, write per-tenant rollups, add
  `containarium agent usage`.
- **Phase 2 — tiering + rate limits.** `allowed_models` on the skill manifest;
  enforce ceiling + per-tenant token bucket at the gateway.
- **Phase 3 — caching + OpenAI.** Shared prompt-cache breakpoint management;
  add the `codex`/OpenAI path (`OPENAI_BASE_URL`).
- **Phase 4 — egress tighten.** Drop provider domains from
  `defaultAgentEgressDomains`; agent boxes egress to the gateway only.

## Open questions

1. **Where does the gateway run?** A core-service LXC (like the platform
   Postgres / Caddy core services), or in-daemon as an HTTP handler? Leaning
   in-daemon for Phase 0 (no new core box), carve out later if it needs
   independent scaling.
2. **Streaming + tool-use passthrough.** The Agent SDK streams SSE and does
   multi-turn tool-use. The gateway must be a faithful streaming proxy, not a
   buffering one, or it breaks the agent loop's latency. Needs a passthrough
   that preserves SSE framing and only *observes* usage on the terminal event.
3. **Multi-backend topology.** Agent boxes run on tunnel-connected backends.
   Does each backend run a local gateway (key on each backend — back to sprawl,
   but bounded to backends not boxes), or do boxes reach a single central
   gateway over the tunnel (one key, but a cross-tunnel hop on every model
   call)? This is the real architectural fork — see the pull-queue note, which
   shares the same "central vs per-backend" tension.
4. **SDK base-URL contract.** Confirm the pinned Agent SDK honors
   `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` headless; otherwise wire the
   client options directly in the engine (still a ~3-line change).

## Appendix — pull-queue prototype (built)

The pull-based run model (raised as the inverse of today's push-exec trigger)
is prototyped, Phase 0:

- **Contract**: `EnqueueAgentTask` / `LeaseAgentTask` / `CompleteAgentTask` on
  `AgentSkillService` (`proto/containarium/v1/agent.proto`) — producer enqueues,
  workers lease (SQS-style visibility timeout + redelivery), workers complete
  with a lease-token check that rejects a stale (expired-then-redelivered)
  completion.
- **Queue core**: `internal/server/agent_task_queue.go` — an in-memory,
  lock-guarded FIFO lease queue with an injectable clock; unit-tested for
  lease-hiding, expiry redelivery, stale-token rejection, FIFO, skill filtering,
  and concurrent-lease uniqueness (`agent_task_queue_test.go`, race-clean).
- **RPC handlers**: `internal/server/agent_queue_server.go` (gated on
  `agents:run`).
- **Producer CLI**: `containarium agent enqueue <skill> --input …`
  (`internal/cmd/agent_enqueue.go`), plus gRPC/HTTP client methods.
- **Worker**: `agent-runtime` `poll` mode (`agent-runtime/src/poll.ts`,
  `CONTAINARIUM_AGENT_MODE=poll`) — lease → run engine → complete, **outbound
  only** (NAT/tunnel-friendly), reusing the A2A path's `runTask`.

**Open before promoting past prototype**: (a) durability — the queue is memory
only, so a daemon restart drops in-flight tasks; (b) the worker's *queue*
credential (needs `agents:run`) is distinct from the skill's in-box token and
isn't minted yet — same "who issues the runtime credential" question the
gateway token raises; (c) per-tenant fairness + dead-letter on repeated
failure. These are deliberately deferred — the prototype proves the
lease/redelivery semantics and the outbound-only worker shape.
