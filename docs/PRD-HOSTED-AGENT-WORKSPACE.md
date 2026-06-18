# PRD — Hosted always-on agent workspace

> Status: **Draft — for review.** Anchored on a working spike
> (`docs/AGENT-WORKSPACE-SPIKE.md`, the `agent-workspace` recipe), not a
> hypothesis. Generic mechanism only; opinionated agent images/skills ship
> outside this repo per [AGENT-SKILLS-CREWS-DESIGN.md](./AGENT-SKILLS-CREWS-DESIGN.md).

## 1. Problem

A developer's coding agent (Claude Code, Cursor, …) runs on their **laptop**. A
laptop is the wrong host for an agent: it sleeps, goes offline, and drops the
session the moment you close the lid. The workaround people reach for —
"SSH into a server and run the agent in tmux, reconnect when I'm back" — works
but is a manual, expert-only ritual: provision a host, secure it, install the
agent, manage the key, remember to `tmux attach`.

**The job:** *"I want my coding agent to live somewhere always-on that I can
re-attach to from any browser, keep working with it where I left off, and ship
what we build — without running my own server."*

## 2. Why now / why us

This is the natural next turn of Containarium's thesis. We already have the
pieces that make a *safe, always-on, browser-reachable* agent host trivial:

- Always-on isolated boxes (per-tenant LXC).
- A **browser terminal** straight into a box (shipped: `internal/gateway/terminal.go`).
- One-command box provisioning with in-box setup (`RecipeService`).
- eBPF network policy, audit logging, secrets — the trust fabric an agent with
  real credentials needs.

The spike proved the missing piece is **one recipe**, not a new platform. That
is our unfair advantage: competitors selling "cloud agent workspaces" are
building the isolation + networking + audit we already shipped.

## 3. Target user & JTBD

**Primary persona — "the always-on builder."** Already lives in a coding agent.
Wants it off the laptop and on a URL, without becoming a sysadmin.

**JTBD:** *"When I step away from my laptop, I want my agent to keep its place
in a box I can re-open from a browser, and ship from there — so my work isn't
tied to one machine being awake."*

**Not this PRD:** the headless one-shot AgentSkill user (that is `agent-runtime`
/ Phase 4a), and the multi-agent crew operator (Phases 1–3).

## 4. The experience (target)

1. **Launch** — user creates an agent workspace (one `deploy_recipe` /
   `recipe deploy agent-workspace`). Box comes up always-on. *(spike: works)*
2. **Attach** — user opens the workspace in the browser; lands directly in a
   live Claude Code session. *(spike: via web terminal)*
3. **Co-work** — converse with the agent, it edits files, runs commands,
   builds. *(spike: raw TTY; v1 polish: chat surface)*
4. **Walk away / re-attach** — close the tab; the agent session persists; re-open
   from any browser and resume. *(spike: tmux session survives WS drop)*
5. **Ship** — agent creates + exposes a *separate* box for the artifact
   (workshop box ≠ product box). *(shipped: platform MCP create/expose)*

## 5. Scope

### In scope (v1)
- The **`agent-workspace` recipe** as the supported launch path (spike → harden).
- **Secrets-based model credential** delivery (replace the spike's parameter).
- A **"workspace" affordance in the WebUI** — a first-class entry that opens the
  agent session (initially the existing terminal; chat surface is a fast follow).
- **Session durability** acceptance: re-attach resumes the same agent.
- **Audit + scope gating** of workspace lifecycle (inherited).

### Out of scope (v1, deferred)
- **Chat-style co-work UI** (stream agent output as messages, not a TTY) — fast
  follow once the terminal path is accepted.
- **Central model gateway / metering** — needed for cost control at scale; v1 can
  ship with per-tenant keys via secrets. (Project memory: model-gateway RFC.)
- **Multi-agent / crews** ([AGENT-SKILLS-CREWS-DESIGN.md](./AGENT-SKILLS-CREWS-DESIGN.md)).
- **Multiple parallel agents per user** (the cmux-style fan-out) — v2.
- **Non-Claude agents** — v1 ships one reference (Claude Code); others are
  outside-repo images on the same recipe pattern.

## 6. Requirements

| # | Requirement | Dependency status |
|---|---|---|
| R1 | One command launches an always-on box running a persistent coding agent. | **Spike-proven**; needs live acceptance. |
| R2 | A browser attach lands in the live agent; detach/re-attach resumes the same session. | **Spike-proven** (tmux + web terminal); needs live acceptance. |
| R3 | The agent survives websocket disconnect and laptop sleep. | **Spike-proven** by design; needs live acceptance. |
| R4 | The model credential is delivered via the secrets mechanism, not a deploy parameter. | **New** — swap spike param for secrets seed. |
| R5 | The workspace is reachable from a first-class WebUI entry, not just an admin terminal dialog. | **Partial** — terminal shipped; needs a "workspace" surface. |
| R6 | Workspace create/attach/destroy is audit-logged and scope-gated. | **Shipped** (inherited). |
| R7 | What the agent builds ships to a separate box. | **Shipped** (platform MCP). |

**Read of the gap:** R1–R3, R6–R7 are done or proven. The only real build is
**R4 (secrets)** and **R5 (a workspace UI entry)** — both small, both on shipped
substrate.

## 7. Success metrics

- **North star — time-to-first-agent-turn**: launch → first agent response in
  the browser, target **< 5 min** (dominated by box provision + npm install;
  mitigate with a pre-baked image).
- **Re-attach success rate**: % of re-opens that resume a live session > 99%.
- **Activation**: % of new users who launch a workspace and reach ≥ 1 agent turn
  in their first session.
- **Stickiness signal**: median days a workspace stays alive (proves the
  "always-on, my place is kept" value over laptop-local).

## 8. Risks & open questions

- **Cost / runaway model spend.** An always-on agent with a key is a spend risk.
  v1 mitigations: per-tenant key via secrets, auto-sleep/idle TTL on the box
  (shipped scale-down primitives), and surfacing usage. Real fix = model gateway
  (deferred). *Decision needed: idle policy default.*
- **Pre-baked vs install-on-deploy.** npm install at deploy hurts time-to-wow.
  *Decision: bake an `agent-workspace` image vs keep post_start install.*
- **TTY vs chat as the v1 surface.** Shipping the raw web terminal is faster but
  less polished than a chat UI. *Recommendation: ship terminal-backed v1, chat as
  immediate fast follow — don't block v1 on the UI.*
- **Relationship to `agent-runtime`.** Two recipes (interactive vs headless) on
  one substrate is intentional; messaging must not conflate them.
- **Cloud packaging.** Pricing, quotas, idle billing belong in the
  Containarium-cloud `prd/` tree; this note is the OSS-mechanism PRD. A cloud
  companion PRD is the follow-up.

## 9. Phasing

- **Phase 0 — spike (DONE):** `agent-workspace` recipe; path proven in-tree.
- **Phase 1 — v1 launch:** live acceptance of R1–R3; secrets-based key (R4);
  pre-baked image; WebUI "workspace" entry (R5); idle/auto-sleep default.
- **Phase 2 — co-work UI:** chat-style streaming surface over the in-box agent.
- **Phase 3 — scale:** model gateway/metering; multiple/parallel agents;
  non-Claude images.

## 10. Relationship to existing plans

- **Reuses**: `RecipeService`, the web terminal, secrets, scale-down, platform
  MCP create/expose — all shipped.
- **Sibling of** [AGENT-RUNTIME-INBOX-LOOP-DESIGN.md](./AGENT-RUNTIME-INBOX-LOOP-DESIGN.md):
  same box-as-agent substrate; this is the *interactive, human-in-the-loop*
  variant, that is the *headless one-shot* variant.
- **Below** [AGENT-SKILLS-CREWS-DESIGN.md](./AGENT-SKILLS-CREWS-DESIGN.md): single
  agent, single box; crews are the multi-agent superset.
- **cmux** (`manaflow-ai/cmux`) is **not** a dependency: it is a *local* native
  macOS multiplexer (opposite of cloud-hosted) and is **GPL-3.0** vs our
  **Apache-2.0**. Borrow its agent-reattach / session-restore *concepts* only.
