# PRD: Agent router — several agent engines on one runtime, routed per skill

**Date:** 2026-10-01
**Status:** draft
**Owner:** hsinhoyeh

## Problem

The agent runtime already ships three agent engines — Claude Code (Claude Agent
SDK), Codex (OpenAI Codex SDK) and Gemini — behind one `Engine` interface
(`agent-runtime/src/engine.ts`, `agent-runtime/src/engines/`). But the daemon
can only ever drive **one of them at a time**, chosen by the operator's key
inventory rather than by the work:

| What exists | Where | What it means for the user |
| --- | --- | --- |
| Engine selection is an env var, `CONTAINARIUM_AGENT_ENGINE`, read by the in-box loop | `agent-runtime/src/index.ts:24` | The choice is invisible to the manifest, the API and the UI |
| The daemon pins **every** skill box to the engine of one "primary" provider: the first of anthropic → openai → gemini that has a key | `internal/server/agent_gateway.go:192` (`gatewayPrimaryProvider`), `internal/server/agent_server.go:937` (`engineEnvPrefix`) | An operator who holds both an Anthropic and an OpenAI key gets Claude for every skill, always |
| The gateway token minted for a run names that same primary provider | `internal/server/agent_gateway.go:62` (`mintGatewayToken` uses `g.provider`) | Even a box that overrides the engine cannot reach the other provider through the gateway |
| The only per-skill override is a tenant secret, documented in a runbook | `docs/AGENT-SKILLS-BRINGUP-RUNBOOK.md:62` (`secrets set <box> CONTAINARIUM_AGENT_ENGINE codex`) | Out of band, untyped, per box not per skill, and not visible anywhere |
| The skill manifest has a free-text `model` field and **no engine field** | `proto/containarium/v1/agent.proto` (`AgentSkill.model = 10`); YAML loader `pkg/core/skills/skills.go` | `model: "gpt-5"` on a skill is silently handed to the Claude engine |
| The manifest's `model` **never reaches the runtime**: nothing exports `CONTAINARIUM_AGENT_MODEL` from `skill.Model`; it is only copied into the in-memory run registry and the tracker identity stamp | `internal/server/agent_server.go:528`; the only exporter is `scripts/engineer-crew-e2e.sh:570` | `docs/AGENT-RUNTIME-INBOX-LOOP-DESIGN.md:79` says the model comes from the manifest. The code disagrees. Two built-in skills pin `model: claude-opus-4-8` to no effect |
| Built-in skills document the status quo as the rule | `pkg/core/skills/skills.yaml:69` — code-review and product-define "run on whatever engine the box's gateway provider selects" | The skill cannot say what it needs, so it says nothing |
| The runtime README has promised the fix since the engines landed | `agent-runtime/README.md:30` — "a later phase moves this onto the skill manifest as an `engine` field" | The gap is known, named and unfilled |
| Nothing reports which engines a deployment can run | `gateway key status` is per (owner, provider) key; `gateway models` is one provider's model list; the web UI has no agents page (`web-ui/app/*`: alerts, apps, audit, containers, monitoring, network, security, traffic, versions) | "Which agents can run here?" is answered by reading daemon startup logs |
| There are **three** engine vocabularies and none is in the proto: the runtime's `claude \| codex \| gemini` (SDKs), `containarium code`'s `claude \| pi` in `code.json` (CLIs; `codex` is rejected by test), and `quickstart --agent`'s `claude \| gemini \| codex` (laptop CLIs) | `agent-runtime/src/index.ts:39`, `internal/coderun/engine/engine.go:43`, `internal/cmd/quickstart.go:116` | Three typed sets, no shared type, no shared status |

**Who hurts, how often.** The operator (self-hosted or a cloud org admin) who
holds more than one provider key and the skill or crew author who wants one
member on Codex and another on Claude. Today they either run everything on the
primary engine or hand-patch a secret per box. The wrong-engine failure mode is
already on record: #748 was filed because a Gemini or OpenAI gateway run fell
back to the Claude engine and died with `Not logged in` — the fix pinned the
engine daemon-wide, which closed the crash and created this PRD's problem.

**Why now.** The team's own delivery loop already routes work by capability
tier: the sprint skill labels every issue `model:sonnet | model:opus |
model:fable` with a rationale, and the issue-triggered-agents PRD
(`docs/product/issue-triggered-agents.md`) turns labels into skill runs. That
loop picks a brain per task **by hand, inside one vendor**. The tracker
allow-lists `model:*` labels (`internal/tracker/policy.go:40`) and then
ignores them: dispatch routes on `scope:<role>` only. The platform cannot
honour a per-task choice across vendors, and cannot even tell the user what
it would be able to honour.

**Evidence.** In-repo state above, issue #748, and one internal request. **No
user quotes, tickets or usage data exist** — demand is an assumption (Open
question 7).

## Target user

1. **The operator** — configures the daemon, holds the provider keys, wants to
   see at a glance which engines are ready and which skills use them.
2. **The skill / crew author** — writes manifests, wants to say "this skill
   runs on Codex" and have the platform do exactly that, or refuse up front.

**JTBD:** *"Configure every agent engine I have a key for on one runtime, see
which ones are ready, and have each skill run on the engine its manifest
names — so I can put the best-suited agent on each kind of work."*

**Not this PRD:** the browser-chat workspace's per-box LLM settings page
(OpenHands, `web-ui/src/components/workspace/WorkspaceView.tsx`), which is a
different surface with its own provider picker; and the `containarium code`
engine seam, which this PRD converges with later (P1) but does not change now.

## Success metrics

| Metric | Baseline | Target |
| --- | --- | --- |
| **Manifest engine honoured** — share of skill runs whose recorded engine equals the manifest's engine | not possible today (no field) | 100%, proven by a crew test with two members on two engines |
| **Wrong-engine start failures** — runs that die at the first model call with a credential / `Not logged in` error because the box got an engine its gateway token cannot serve | unknown — instrument first (count run artifacts whose `error` matches the #748 signature) | 0 for any engine the status surface reports as ready |
| **Time to answer "which agents can run here"** | read daemon logs or env; expert-only | one CLI command or one UI panel, under 10 s |
| Adoption — share of runs on a non-default engine 30 days after release | unknown — instrument first | > 0 on the dogfood deployment (proves the feature is used, not just built) |

The first metric is the north star: it is the one property the manifest field
exists to deliver, and it is binary.

## MVP scope — the core journey

> An operator sets an Anthropic key and an OpenAI key on one daemon. They run
> one command (or open one panel) and see Claude: ready, Codex: ready, Gemini:
> no key. An author sets `engine: codex` on one skill and leaves another on
> Claude. A crew with both members runs; each member runs on its own engine,
> the artifact says so, and a skill naming an engine with no key is refused at
> start with a message that names the fix.

**Design constraints carried in from the repo** (`CLAUDE.md`): the engine is
a proto **enum**, not a string with a comment; the CLI verb lands first and the
MCP tool wraps the same Go function; every new endpoint is proto-first.

---

**Story 1 — a typed engine on the skill manifest, honoured per run**

**Story:** As a skill author, I want to name the engine a skill runs on in its
manifest, so that the platform drives it with that agent and not with whatever
engine the daemon's primary key happens to be.

**Acceptance criteria:**
- [ ] `proto/containarium/v1/agent.proto` gains `enum AgentEngine {
      AGENT_ENGINE_UNSPECIFIED, AGENT_ENGINE_CLAUDE, AGENT_ENGINE_CODEX,
      AGENT_ENGINE_GEMINI }` and `AgentSkill.engine`. `make proto` regenerates;
      the YAML / JSON skill loader accepts the lower-case names.
- [ ] `RunAgentSkill`, `RunCrew` and the pull-queue worker export
      `CONTAINARIUM_AGENT_ENGINE` **per skill** from the manifest.
      `UNSPECIFIED` keeps today's behaviour exactly (primary-provider pinning
      in gateway mode, box default in direct mode) — no existing skill
      changes engine.
- [ ] The same exec exports `CONTAINARIUM_AGENT_MODEL` from the manifest's
      `model` when set, closing the gap where the field is recorded but never
      delivered. The two built-in skills that pin `claude-opus-4-8` start
      actually running on it; a test asserts the exported value.
- [ ] The gateway token minted for a run is bound to the **engine's provider**
      (`engineForProvider` inverted), not the daemon primary, and the box's
      gateway env is written for that provider. A crew whose members name two
      engines gets two differently-bound tokens.
- [ ] A skill naming an engine whose provider has no resolvable key (global or
      per-owner) fails at `RunAgentSkill` with `FailedPrecondition` naming the
      provider and the command that fixes it — not minutes later inside the
      box with `Not logged in`.
- [ ] The effective engine is recorded on the run: in the in-memory run
      registry (`runlease.Info`, beside `Model`), in `artifact.json` (already
      carries `engine` from the runtime) and in the run-lease audit payload.
- [ ] `containarium agent get <skill-id>` prints the engine.
- [ ] Tests: table test over (engine × gateway/direct mode) pinning the exact
      exec prefix; a crew fixture with two members on two engines asserting
      each box's env and token provider; the no-key refusal.

**Priority:** P0 — this is the whole routing property.

---

**Story 2 — one surface that reports which engines are configured**

**Story:** As an operator, I want one command that lists every agent engine
and whether this deployment can run it, so that I stop reading daemon logs to
find out.

**Acceptance criteria:**
- [ ] `ListAgentEngines` RPC on `AgentSkillService` (proto-first, grpc-gateway
      REST path, swagger description). One row per `AgentEngine` value with:
      provider, `ready` (bool), `reason` when not ready (`no key for provider`,
      `engine not in runtime bundle`, …), `default` (true for the engine
      `UNSPECIFIED` resolves to), the credential source that makes it ready
      (`global key` | `per-owner key` | `direct mode`), and the ids of the
      skills whose manifest names it.
- [ ] Readiness is computed from **state the daemon already holds** — the
      provider key registry and the runtime bundle manifest — with no live
      model call (Open question 2).
- [ ] Per-owner resolution matches `MintGatewayToken`: a tenant sees readiness
      for *their* key owner; an admin with no owner scope sees the global view.
- [ ] `containarium agent engines` prints the table; `--json` prints the
      response. The platform MCP tool wraps the same client function
      (CLI-first).
- [ ] Tests: readiness truth-table over (global key, owner key, bundle present)
      per engine; the CLI golden output.

**Priority:** P0 — without it the operator cannot tell whether Story 1 will
work before trying it.

---

**Story 3 — the UI shows the configured engines**

**Story:** As an operator, I want the dashboard to show which agent engines are
configured and which skills use each, so that the state is visible without a
terminal.

**Acceptance criteria:**
- [ ] An **Agents** entry in the web UI (`web-ui/app/agents/page.tsx`, same
      layout and data-fetch pattern as the sibling pages) renders
      `ListAgentEngines`: one card or row per engine with ready / not-ready,
      the reason, the provider, the default badge, and the list of skills on
      it.
- [ ] Not-ready engines render the same `reason` text the CLI prints — one
      source of truth, no UI-only copy.
- [ ] The page is read-only in the MVP. Keys are still set through the
      existing `gateway key set` path; the page links to the doc for it.
- [ ] Empty state: a daemon with no keys shows every engine as not ready with
      the `no key` reason and the direct-mode note, rather than a blank page.
- [ ] A happy-path e2e screenshot exists (pairs with `/qa-e2e-test`).

**Priority:** P0 — the second half of the user's ask.

---

**Story 4 — the crew e2e proves two engines on one runtime**

**Story:** As a maintainer, I want the existing crew e2e to run a two-engine
crew, so that "several agents on one runtime" is a tested property and not a
claim.

**Acceptance criteria:**
- [ ] `scripts/engineer-crew-e2e.sh` (or a sibling) runs a two-member crew
      with members on two different engines against a daemon holding both
      keys; asserts each member's artifact records its own engine and each
      box's gateway token names its own provider.
- [ ] `containarium agent engines` on that daemon reports both as ready and
      the third as not ready, and the assertion is on the `reason` string.
- [ ] Gated behind the keys being present, like today's e2e; skipped, not
      green, when they are absent (per project memory: a check that cannot
      fail proves nothing).

**Priority:** P0 — this is the acceptance test for the whole PRD.

**Delivery:** Story 1 → #2222, Story 2 → #2223, Story 3 → #2224, Story 4 →
#2225 (all labeled `product`; 2 depends on 1, 3 on 2, 4 on 1 and 2).

## Later phases

- **P1 — per-invocation override.** `agent run --engine`, `agent enqueue
  --engine`, `crew run --engine <skill-id>=<engine>` and the matching
  `RunAgentSkillRequest.engine` field, refused when the engine is not ready.
  Deferred because the routing rule belongs on the skill ("this topic runs on
  this agent"); a one-off override is a convenience on top.
- **P1 — model validated against engine, and enforced.** Reject `model` ids
  the named engine cannot serve, using `ListGatewayModels` for gateway
  providers, and set the run token's `allowed_models` ceiling from the
  manifest (`gatewayProvisioning.allowedModels` exists and is never
  assigned today). Today a mismatch is passed through and fails in-box.
- **P1 — one engine vocabulary.** Fold `internal/coderun/engine`'s
  `claude | pi` and `quickstart --agent`'s `claude | gemini | codex` into
  the same `AgentEngine` enum, with a per-engine "where it can run" flag
  (runtime SDK, repo-box CLI, laptop CLI), so `containarium agent engines`
  reports all of them and `code install --engine codex` stops being a
  rejected value for no product reason.
- **P1 — cloud dashboard consumes `ListAgentEngines`.** The cloud control
  plane's org view reads the same RPC per daemon; no new OSS code. Filed as a
  cloud PRD when Story 3 lands.
- **P2 — policy router: pick the engine from the topic.** Map tracker labels
  or skill tags (`model:sonnet | opus | fable` today, allow-listed and
  ignored) to (engine, model), and let the tracker dispatcher
  (`docs/product/issue-triggered-agents.md`) choose at enqueue time. This is the "optimise the agent to the topic" goal
  in the request; it is P2 because it needs the per-engine run and cost data
  that Stories 1–2 start producing before any policy can be evidence-based.
- **P2 — failover.** Retry a run on a second ready engine when the first
  provider returns quota or outage errors. Needs the skill to declare that a
  swap is acceptable (prompts and tool semantics differ per engine).
- **P2 — cost-aware routing** from gateway metering (`agent_gateway_metrics`).

## Out of scope

- **Switching engines mid-run.** A Claude session cannot be handed to Codex
  with its context; the SDKs share no session format. The unit of routing is
  the skill run.
- **An LLM router inside the model gateway** (serving one provider's API
  shape against another's models, or choosing a model per request).
  `docs/AGENT-MODEL-GATEWAY-DESIGN.md:66` names that a non-goal and this PRD
  keeps it one: routing happens at the **daemon, per skill run, to an
  engine**; the gateway keeps proxying, metering and key custody only.
- **New engines** (pi in the runtime, aider, opencode). Separate request;
  the enum makes the slot, this PRD does not fill it.
- **Credential custody changes.** Keys stay in the gateway, per owner or
  global, exactly as `docs/AGENT-MODEL-GATEWAY-DESIGN.md` has them. Readiness
  reports a key's *existence*, never its value or fingerprint.
- **Key management in the Agents UI page.** Read-only in the MVP; writing
  keys from the browser is a security review of its own.
- **The OpenHands workspace LLM settings page.** Already multi-provider, per
  box, and a different product surface.

## Open questions & assumptions

1. **Does the runtime bundle ship all three engines on every box image?**
   `make bundle-agent-runtime` verifies it since #748. *Assumption:* yes;
   Story 2 still reads the bundle manifest rather than assuming, so a trimmed
   image reports `engine not in runtime bundle`.
2. **What does "ready" mean?** *Default:* key resolvable for the caller's
   owner + engine present in the bundle. No live probe call in the MVP: it
   costs money, takes seconds and needs a box. A `--probe` flag that runs the
   engine's verify command in a scratch box is a P1 candidate.
3. **Which UI?** *Default:* the OSS web UI (Story 3), because it is in this
   repo and reads the daemon directly; the cloud dashboard follows as P1 via
   the same RPC. *Validate:* confirm with the owner that the ask was not
   cloud-first.
4. **Should `UNSPECIFIED` keep primary-provider pinning or become an error?**
   *Default:* keep it — every existing manifest has no engine field, and
   changing their engine on upgrade is a breaking change to shipped
   behaviour (same reasoning as `engine.DefaultName` in `containarium code`).
5. **Per-owner keys and the engine list.** When the caller's owner has a key
   for a provider the global registry does not, the engine is ready *for that
   owner*. *Default:* readiness is always evaluated for the resolved owner,
   never union-of-all-owners, so one tenant cannot learn what another has
   configured.
6. **Crew-wide engine?** Should `Crew` carry a default engine for members
   that leave theirs unspecified? *Default:* no in the MVP — the member's
   manifest decides, the crew only bounds the set. Revisit with the P1
   override.
7. **Demand is assumed, not evidenced.** One internal request and #748. The
   MVP is small enough to be its own test: ship it, dogfood a two-engine crew
   in the sprint loop for two weeks, and measure the adoption metric.
