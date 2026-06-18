# PRD — Hosted agent chat workspace

> Status: **Draft — for review.** Anchored on a working spike
> (`docs/AGENT-WORKSPACE-SPIKE.md`, the `agent-workspace` recipe packaging
> OpenHands). Generic mechanism only; per
> [AGENT-SKILLS-CREWS-DESIGN.md](./AGENT-SKILLS-CREWS-DESIGN.md), opinionated
> agent images/skills ship outside this repo.

## 1. Problem

A developer's coding agent runs on their **laptop**: it sleeps, goes offline,
and its chat history + working state are tied to one machine being awake. People
who want an always-on agent fall back to "SSH to a server, run an agent in tmux,
reconnect later" — expert-only, no chat UI, no preview, no notion of multiple
saved conversations.

What people actually want is the experience they already know from Claude / 
ChatGPT / bolt.new: **a browser chat UI, a live preview of what's being built,
and multiple conversations they can leave and come back to** — but hosted
somewhere always-on, isolated, and able to *ship* the result.

**The job:** *"Let me open a browser, chat with a coding agent to design a site
or system, watch it come together in a preview, keep multiple projects as
separate saved conversations — all living in a box I don't have to run myself —
and ship what I build."*

## 2. Why now / why us

The chat + agent + preview + sessions problem is *solved* by OSS engines
(OpenHands, MIT). What is **not** commoditized — and what Containarium already
ships — is the safe, always-on, shippable substrate underneath:

- always-on isolated per-tenant boxes,
- one-command provisioning with in-box setup (`RecipeService`),
- managed subdomain + TLS routing (expose-port),
- eBPF network policy, audit logging, secrets — the trust fabric a browser-
  reachable coding agent (with a shell and a key) demands,
- one-click **ship-to-box** for the artifact.

So we don't build a chat UI to compete with OpenHands — we **package it** and win
on the wrapper. The spike showed the integration is ~one recipe.

## 3. Target user & JTBD

**Primary persona — "the always-on builder."** Comfortable chatting with a
coding agent; wants it hosted, persistent, and able to publish — without running
infrastructure.

**JTBD:** *"When I have an idea, I open my workspace, chat it into existence with
a preview in front of me, save it as one of my projects, and ship it — from any
browser, without my laptop being involved."*

**Not this PRD:** the headless one-shot AgentSkill user (`agent-runtime` / Phase
4a) and the multi-agent crew operator (Phases 1–3).

## 4. The experience (target)

1. **Launch** — user creates a workspace (one `deploy_recipe` /
   `recipe deploy agent-workspace`). Always-on box comes up running OpenHands.
   *(spike: wired, live-acceptance pending)*
2. **Open** — browser to `https://<name>-workspace.<base-domain>`; the chat UI
   loads behind platform auth. *(spike: via the recipe's exposed port + routing)*
3. **Chat + preview** — converse with the agent; it edits files, runs commands,
   and a **preview pane** shows the running app. *(OpenHands built-in)*
4. **Multiple sessions** — start/switch between conversations; all persisted to
   the box (`/opt/openhands-state`). *(OpenHands built-in)*
5. **Walk away / resume** — close the tab; the box stays up; re-open from any
   browser and the conversations are there. *(box is always-on)*
6. **Ship** — publish the build to a *separate* box (workshop box ≠ product box)
   via the platform MCP. *(shipped: create/expose)*

## 5. Scope

### In scope (v1)
- The **`agent-workspace` recipe** (OpenHands-in-a-box) as the supported launch
  path — spike → live-validated → hardened.
- **Platform auth in front of** the exposed OpenHands UI (it's a full coding
  agent; must require the tenant's session).
- **Secrets-based** Anthropic key delivery (replace the spike parameter).
- **A WebUI entry** to launch + open a workspace (vs. raw `recipe deploy`).
- **Idle policy** (auto-sleep / TTL) to bound always-on cost.

### Out of scope (v1, deferred)
- **Native chat UI** (our own surface over an in-box agent server) — v2 once
  demand is proven; v1 embeds OpenHands.
- **Central model gateway / metering** — needed at scale; v1 ships per-tenant
  keys via secrets. (Project memory: model-gateway RFC.)
- **Multi-agent / crews** ([AGENT-SKILLS-CREWS-DESIGN.md](./AGENT-SKILLS-CREWS-DESIGN.md)).
- **Non-Claude / alternative engines** — same recipe pattern, later.

## 6. Requirements

| # | Requirement | Dependency status |
|---|---|---|
| R1 | One command launches an always-on box running a web chat workspace. | **Spike-wired**; live-acceptance pending. |
| R2 | The chat UI + live preview are reachable in the browser over managed TLS. | **Spike-wired** (ports + routing); live-acceptance pending. |
| R3 | Multiple conversations persist in the box and survive disconnect/reload. | **OpenHands built-in**; live-acceptance pending. |
| R4 | The exposed agent UI sits behind platform auth. | **New** — route/auth work. |
| R5 | The Anthropic key is delivered via the secrets mechanism, not a parameter. | **New**. |
| R6 | A WebUI affordance opens a workspace. | **Shipped (embed + zero-click auth)** — `web-ui` "Workspace" tab embeds the box's UI in an iframe and authenticates it seamlessly via `GetWorkspaceAccess` bootstrap; launch-from-UI still to do. |
| R7 | Workspace lifecycle is audit-logged + scope-gated; build ships to a box. | **Shipped** (inherited). |

**Read of the gap:** the *experience* (R1–R3) is reuse + wiring, proven to load
in-tree and pending one live box. The genuine new build is **R4 (auth in front),
R5 (secrets), R6 (a launch button)** — all small, all on shipped substrate.

## 7. Success metrics

- **North star — time-to-first-agent-reply**: launch → first agent response in
  the browser, target **< 5 min** (dominated by image pulls; mitigate with a
  pre-baked box image).
- **Resume success**: % of re-opens that show prior conversations intact > 99%.
- **Activation**: % of new users who launch a workspace and complete ≥ 1
  conversation in their first session.
- **Stickiness**: median days a workspace stays alive (proves always-on value).
- **Ship-through**: % of workspaces that ship at least one artifact to a box.

## 8. Risks & open questions

- **Integration risk (the spike's #1 unknown):** OpenHands spawning its runtime
  sandbox via the box's Podman socket. If it doesn't hold, fall back to
  OpenHands local/CLI runtime (box = sandbox). *Must be settled in live
  acceptance before commit to GA.*
- **Security of an exposed coding agent.** A world-reachable OpenHands UI is a
  shell + key. R4 (auth in front) is non-negotiable; the box's eBPF egress
  policy should also bound what the agent can reach.
- **Cost / runaway spend.** Always-on + a key. v1: secrets-scoped key +
  auto-sleep/idle-TTL; real fix = model gateway (deferred).
- **Pre-baked vs pull-on-deploy.** Pulling OpenHands + runtime images at deploy
  hurts time-to-wow. *Decision: bake an image vs keep post_start pulls.*
- **Embed vs native UX.** Embedding OpenHands ships fast but the UX is theirs
  (incl. branding). *Recommendation: embed for v1 to validate demand; native
  surface is v2.*
- **Cloud packaging.** Pricing, quotas, idle billing belong in the
  Containarium-cloud `prd/` tree; this is the OSS-mechanism PRD. Cloud companion
  PRD is the follow-up.

## 9. Phasing

- **Phase 0 — spike (DONE):** `agent-workspace` recipe; wiring proven in-tree.
- **Phase 1 — live validation:** settle the integration unknowns
  (`docs/AGENT-WORKSPACE-SPIKE.md`) on a backend.
- **Phase 2 — v1 launch:** auth-in-front (R4), secrets key (R5), WebUI launch
  (R6), idle policy, pre-baked image.
- **Phase 3 — native + scale:** our own chat surface over an in-box agent
  server; model gateway/metering; alternative engines.

## 10. Relationship to existing plans & reuse decision

- **Reuses**: `RecipeService`, expose-port + managed TLS, secrets, scale-down,
  platform MCP create/expose — all shipped.
- **Reuse engine — OpenHands** (MIT, Apache-compatible): packaged, not forked.
  Considered and rejected: **Open WebUI** (chat-only fit + branding-restricted
  license); **cmux** (local macOS app, GPL-3.0). See
  `docs/AGENT-WORKSPACE-SPIKE.md` §"Why reuse OpenHands".
- **Sibling of** [AGENT-RUNTIME-INBOX-LOOP-DESIGN.md](./AGENT-RUNTIME-INBOX-LOOP-DESIGN.md):
  same box-as-agent substrate; this is interactive/human-in-the-loop, that is
  headless/one-shot.
- **Below** [AGENT-SKILLS-CREWS-DESIGN.md](./AGENT-SKILLS-CREWS-DESIGN.md):
  single agent, single box; crews are the multi-agent superset.
