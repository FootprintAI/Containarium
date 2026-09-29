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
  enforce ceiling + a per-tenant rolling quota at the gateway. *Shipped: the
  model ceiling rides the gateway token, and per-tenant quota + the response
  ladder are below. Rolling window rather than a token bucket — there is no
  burst allowance or refill rate, just "how much in the last N minutes".*
- **Phase 3 — caching + OpenAI.** Shared prompt-cache breakpoint management;
  add the `codex`/OpenAI path (`OPENAI_BASE_URL`).
- **Phase 4 — egress tighten.** Drop provider domains from
  `defaultAgentEgressDomains`; agent boxes egress to the gateway only.

## Enforcement: quota + the graduated response ladder

Metering answers "what did this tenant spend"; it does not stop a runaway. The
gateway is the only place a limit can actually be enforced, because a limit
applied inside the box is advice the box can ignore — it holds the credential.
`internal/modelgateway/{quota,anomaly,policy}.go` add that, off by default.

**Quota** (`QuotaLimits`) caps calls, total tokens, and output tokens per tenant
over a rolling window. The window is a ring of buckets, so a budget is a rolling
budget and not a lifetime cap: a tenant that overspent an hour ago works again
without an operator. Cached tokens count — replaying a huge cached prefix is
exactly the runaway a budget exists to stop.

**Signals** (`AnomalyConfig`) are per-tenant and relative, never absolute. An
absolute threshold is either high enough for a stolen token to live under or low
enough to fire on a normal Monday. The detectors:

| signal | fires when |
| --- | --- |
| `rate_baseline` | token rate exceeds this tenant's own learned baseline by a factor |
| `model_switch` | a model the tenant has not used within the novelty TTL |
| `endpoint_mix` | an upstream path the tenant has not used |
| `concurrent_source_nets` | one tenant's token in use from more networks than a box population explains |
| `auth_failure_ratio` | a large share of the tenant's recent calls are rejected — a token being probed |

Two properties are load-bearing and easy to regress. The baseline learns only
from windows that were quiet *and* evaluated first, or the spike being judged
raises the bar it is judged against. And the novelty signals stay silent until a
tenant is learned, because a new tenant's first model and first endpoint are
novel by construction — emitting them escalates every new tenant on its first
call, and an escalated tenant stops feeding its baseline, so it would never
become learned.

**The ladder** (`PolicyState`) is observe → throttle → alert → circuit-break →
revoke. Escalation is immediate; descent is damped by a cooldown and goes one
rung at a time. Every rung except the last is reversible with no human, which is
what lets the detector be wrong: being wrong costs latency, not an outage. A
circuit-break is time-boxed and steps down on its own — unless the condition is
still live, in which case it extends rather than flapping. Revocation is sticky,
needs an operator to clear, and is never reached automatically unless
`RevokeAt` is explicitly configured.

The check runs after the gateway token is verified and before the reverse
proxy's Director, so a denied call never has the real key injected and never
reaches the provider. `Policy.Revoke` takes effect on the next call with no
token re-issue and no box restart — an already-issued 30-minute token stops
working immediately.

Operator surface: `GET /__gateway/policy` reports every tenant's rung, what put
it there, and consumption against budget. Configuration is env, and a daemon
that sets none of it meters exactly as before:

| var | meaning |
| --- | --- |
| `CONTAINARIUM_GATEWAY_QUOTA_WINDOW` | rolling window (Go duration, default `1m`) |
| `CONTAINARIUM_GATEWAY_QUOTA_CALLS` | calls per tenant per window |
| `CONTAINARIUM_GATEWAY_QUOTA_TOKENS` | input+output+cached tokens per tenant per window |
| `CONTAINARIUM_GATEWAY_QUOTA_OUTPUT_TOKENS` | generated tokens per tenant per window |
| `CONTAINARIUM_GATEWAY_ANOMALY` | `1` enables the detectors |
| `CONTAINARIUM_GATEWAY_ANOMALY_REVOKE_AT` | score (0..1] for automatic revocation; unset = never |

A window alone is not a configuration — it says when to measure, not how much is
allowed — so it does not switch enforcement on by itself.

## Per-owner keys and OpenAI-compatible upstreams (built, #1725)

The gateway originally held one real key per provider for the whole daemon
(`Config.ProviderKeys`). That is right for a single-operator install and wrong
as soon as one daemon brokers for several owners who each pay for their own
upstream: the key to inject is a property of the **token**, not of the process.

So a gateway token may carry a `key_owner` claim — a namespaced string,
`user:<username>` or `org:<org_id>` — and the gateway resolves the real key
through an injected `KeyResolver` (`KeyFor(ctx, keyOwner, provider)`).
Resolution order, per call:

1. no `key_owner` → `Config.ProviderKeys` only; the resolver is never asked, so
   every token issued before this existed behaves exactly as before;
2. `key_owner` with a key → that key;
3. `key_owner` with no key → the daemon-global key, logged (that call is billed
   to the operator, not the owner);
4. neither → the call is refused without touching an upstream.

The prefix is load-bearing: local usernames and org ids are arbitrary strings
from the same space, so `user:` / `org:` keeps a crafted username from resolving
to an org's key.

Per-owner keys live in the daemon's **encrypted secrets store** under the
reserved namespace `__gateway/<key_owner>/<provider>`, written with `broker`
delivery. A `/` cannot appear in a tenant username, so no tenant can name that
namespace; the tenant-facing store methods refuse it outright, and no delivery
mode ships those rows into a box.

Two kill-switches, both checked ahead of the key lookup so a dead token never
causes a real key to be touched: the per-`jti` revocation list (above), and
`RevokeByKeyOwner` — every token issued for one owner up to that instant stops
on its next call. It records a **cutoff**, not a flag, so an owner who
re-registers a key works again on freshly minted tokens with no un-revoke verb.
Both fail open on a lookup error, for the same reason.

**Registering an OpenAI-compatible upstream.** Setting
`<PROVIDER>_UPSTREAM_URL` registers a provider of that name
(`ACMEAI_UPSTREAM_URL` → `acmeai`) that speaks OpenAI's chat-completions
protocol at that endpoint: bearer auth, OpenAI-shaped usage on both the
non-streaming and the SSE path. Its daemon-global fallback key, if any, comes
from `<PROVIDER>_API_KEY`; per-owner keys arrive through the resolver instead.
No upstream is compiled in — a brokered endpoint is deployment configuration —
and registering one is enough to bring the gateway up even when the daemon holds
no key of its own, which is the multi-owner shape.

## ModelGatewayService: the admin + mint RPCs (built, #1726)

#1725 made the real upstream key a property of the token. This is the control
surface that puts keys in and takes tokens out — `ModelGatewayService`, in
`proto/containarium/v1/model_gateway.proto`, proto-first with grpc-gateway REST
mappings under `/v1/model-gateway/`. That prefix is the **control** plane; the
gateway's **data** plane stays the `/v1/model/<provider>` proxy, and the two do
not overlap.

Two scopes, deliberately not one:

| Scope | RPCs | Why separate |
|---|---|---|
| `gateway:admin` | `SetTenantProviderKey`, `DeleteTenantProviderKey`, `GetTenantProviderKeyStatus` | The REAL upstream key goes in under it. A control-plane/operator verb; `secrets:write` would be the wrong home, because that scope is a tenant's own secrets and a tenant must never be able to write the key its calls are billed against. |
| `gateway:mint` | `MintGatewayToken`, `ListGatewayModels` | Tenant-reachable: mint a scoped, expiring token for a box you own. Must be grantable without also granting the ability to write a real key. |

Neither satisfies the other. The MCP surface carries **only** `mint_gateway_token`
— there is no tool through which any agent token can write a provider key.

**The key verbs are write-only.** Nothing on this service reads a registered key
back. `GetTenantProviderKeyStatus` returns set/unset, a **fingerprint** (the first
16 hex characters of the key's SHA-256) and `set_at`. Deleting a key also calls
`RevokeByKeyOwner`, so the key stops being spendable on the next call rather than
when the last token expires; the response says `tokens_revoked=false` when the
daemon holds no revocable owner-revocation store, instead of implying a clean
revocation.

**`key_owner` at mint time.** `MintGatewayToken` takes a *box*, never a
`key_owner`, and resolves the owner itself: the box's `cloud_org_id` attribution
label when it is stamped (`ContainerService.SetContainerAttribution`) →
`org:<org_id>`, else the box's owning username → `user:<username>`. The pull-mode
`user.containarium.tenant` config key is deliberately **not** consulted: the
sandbox path writes a *username* there and the cloud actuator writes an *org id*,
and reading a username as an org id is exactly the namespace collision the
`user:`/`org:` prefixes exist to make impossible.

**`key_owner` on skill and crew runs (#2134).** A run's box does not go through
`MintGatewayToken`: `provisionSkillBox` mints the run's token itself, for every
push run, crew member and queue worker. That mint resolves the owner the same
way — the box's `cloud_org_id` attribution → `org:<org_id>` — except that its
fallback is the run's **dispatching caller** → `user:<username>`, not the box
name: a skill box is `agent-<skill>`, shared by everyone who runs that skill,
so the box name identifies no one. An owner that fails `ValidateKeyOwner` is
never stamped. Two differences from the mint RPC, both deliberate:

- An owner **with no registered key** is still minted a `key_owner` token, and
  the gateway's case-3 fallback bills the daemon-global key and logs it. A run
  that fails outright is worse than one that runs and is logged; a caller of
  `MintGatewayToken` can fix its config and retry.
- A run with **no attributable owner** (system-started, no authenticated
  subject) mints no claim and uses the daemon-global key, as before, logged
  once per run at mint (decided on the Containarium-cloud#1917 sprint,
  2026-09-29).

Because runs now carry the claim, `RevokeByKeyOwner` kills an owner's in-flight
run tokens. The 401 body (`modelgateway.OwnerRevokedMessage`) says the
revocation was intentional, so the run's own error does not read as an
unexplained auth failure.

**Ownership, and why cross-tenant reads as NotFound here.** A caller may only
mint for a box it owns (admins excepted). Cross-tenant and non-existent return
the *same* `NotFound`, byte for byte. This differs from
`SandboxServer.lookupOwnedSandbox`, which returns `PermissionDenied` for
cross-tenant on purpose — and both are right, because the identifiers differ: a
sandbox id is a server-generated opaque string, so confirming one exists reveals
nothing an attacker could have guessed, whereas a box name is `<username>-container`
and therefore derivable. `PermissionDenied` on this path would be a working
oracle for "does tenant X have a box on this daemon".

**Refusing rather than silently billing the operator.** Resolution case 3 above
(a `key_owner` with no key falls back to the daemon-global key) is correct for
tokens already in the wild, but a *new* token that is known in advance to bill
the operator is a billing bug we can decline to create. So the mint path returns
`FailedPrecondition` when the resolved owner has no key for the provider, even
when a global key exists.

**Token lifetime.** Per run: 24h default, capped server-side at 24h. A request
above the cap is capped, not rejected, and the response's `expires_at` (which
equals the signed `exp`) is the only truth. The response also carries the minted
`token_id`, so `containarium token revoke --jti <id>` kills exactly that token
without re-parsing it. `dry_run` validates everything a real mint validates —
ownership, the provider, the owner's key — and issues nothing, which is how an
install step names a misconfiguration before the first model call.

**`ListGatewayModels`** reads the provider's own `/v1/models` through the same key
resolution the proxy path uses, so the list a caller gets is the list its calls
can actually use. A non-OpenAI-shaped provider has no such contract and is
refused rather than reported as having no models.

**CLI-first**, per CLAUDE.md: `containarium gateway key set|delete|status`,
`containarium gateway mint <box> [--run-id --ttl --allow-model --dry-run --env]`,
`containarium gateway models --provider …`. `--env` prints the two exports that
become the box's 0600 `gateway.env` — the caller writes that file over SSH, the
daemon never does.

**Still open after this:** the owner-revocation store is in-memory, so owner
revocations do not survive a daemon restart (the per-`jti` list and removing the
key itself are the durable halves). A durable store is its own change.

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
- **Worker provisioning**: `StartAgentWorker` RPC + `containarium agent worker
  <skill>` (`internal/server/agent_queue_server.go`, `internal/cmd/agent_worker.go`).
  Provisions/reuses the skill's box, **mints a queue credential** — a JWT scoped
  to `agents:run` only, *separate* from the skill's in-box token, since leasing
  is a runtime action the skill's own scopes don't grant — and launches the
  runtime in poll mode with that credential + the daemon URL seeded as env
  (`buildWorkerPollCommand`). The worker resolves the daemon host from its
  default route (the backend) at launch, so the daemon needn't know the bridge
  address. Gated on `agents:run`; the launch is best-effort like serve mode.
- **Worker**: `agent-runtime` `poll` mode (`agent-runtime/src/poll.ts`,
  `CONTAINARIUM_AGENT_MODE=poll`) — lease → run engine → complete, **outbound
  only** (NAT/tunnel-friendly), reusing the A2A path's `runTask`.

End-to-end loop:

```
containarium agent worker  hello-agent --server <host>   # start a poll-mode worker
containarium agent enqueue hello-agent --input '{"q":…}' --server <host>   # produce
# worker leases → runs the engine → completes; repeat per enqueue.
```

The producer→worker cycle (enqueue → lease → run → complete, incl. the
`agents:run`-credential auth and the stale-lease guard) is covered end-to-end
through the real RPC handlers in `agent_queue_server_test.go`.

**Open before promoting past prototype**: (a) **durability** — the queue is
memory only, so a daemon restart drops in-flight tasks; (b) **credential
lifetime** — the worker's `agents:run` token has the 30-minute agent TTL, so a
long-lived worker needs a refresh path (the same open question the gateway token
raises; a durable answer is a re-mint-on-401 or a daemon-side renew); (c)
**egress** — when the eBPF policy is enforced, a worker box must be allowed out
to the daemon's host:port (today's allowlist is the model providers); (d)
**per-tenant fairness + dead-letter** on repeated failure. These are
deliberately deferred — the prototype proves the credential-scoped lease/run/
complete loop and the outbound-only worker shape.
