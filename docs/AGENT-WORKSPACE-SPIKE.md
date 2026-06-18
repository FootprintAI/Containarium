# Spike — always-on agent workspace via the `agent-workspace` recipe

> Status: **Spike / proof-of-path.** Goal: prove that "a coding agent that
> lives in your laptop tmux dies when the laptop sleeps; move it into an
> always-on box you re-attach to over the browser" is buildable almost entirely
> from **already-shipped** parts — no new runtime, no new transport, no new UI.
> This note records what the spike does, what is proven in-tree, and what still
> needs a live box to accept.

## The idea in one line

Run **Claude Code in a persistent tmux session inside an always-on box**, and
**re-attach to it over the existing web terminal** — then ship what you build to
a separate box via the platform MCP.

## Why this is the lightest path

Every moving part except the recipe already ships:

| Part | Status | Where |
|---|---|---|
| Always-on box | shipped | core platform |
| Browser terminal → box (xterm.js ↔ WS ↔ incus exec) | shipped | `web-ui/.../TerminalDialog.tsx`, `internal/gateway/terminal.go` |
| Recipe deploy (provision box + run setup inside) | shipped | `RecipeService`, `internal/server/recipe_server.go` |
| Ship-to-box (create + expose + HTTPS) | shipped | platform MCP / recipes |
| **`agent-workspace` recipe (tmux + Claude Code + auto-attach)** | **this spike** | `pkg/core/recipes/recipes.yaml` |

The spike adds **one recipe**. Nothing else.

## How it works

The web terminal execs `su - <user>` — a **login shell** — so it sources
`/etc/profile.d/*.sh`. The recipe drops `zz-agent-workspace.sh` there, which on
any interactive login that is not already inside tmux does:

```sh
exec tmux new-session -A -s agent "claude || true; exec bash"
```

- `new-session -A -s agent` **attaches** to the session named `agent` if it
  exists, else **creates** it. So every browser attach reconnects to the *same*
  running agent — the "re-attach to my server tmux" experience.
- The tmux server keeps running as the box user after the websocket drops, so
  the agent **survives disconnect** (the whole point).
- `claude || true; exec bash` keeps the pane (and session) alive if the agent
  exits or needs `/login`, so re-attach never lands on a dead session.
- The hook is **username-agnostic** — it works whatever the box user is, so the
  recipe needs no knowledge of the tenant name at deploy time.

Contrast with the existing **`agent-runtime`** recipe: that one is the *headless,
one-shot* sibling (seeded task in → `artifact.json` out, no human). This recipe
is the *interactive, human-in-the-loop* sibling. They share the same box-as-
agent substrate; they differ only in who drives the loop.

## What is proven in-tree (this spike)

- `go build ./pkg/core/recipes/... ./internal/server/...` — clean.
- `go test ./pkg/core/recipes/... ./internal/server/...` — green, including the
  new `TestAgentWorkspaceRecipe` (catalog loads the recipe; it is GPU-free,
  port-free; post_start installs Claude Code + tmux and drops the auto-attach
  hook; the API key is an optional `password` parameter).
- Deploy wiring is **inherited, not new**: `DeployRecipe` provisions the box and
  runs `post_start` exactly as it does for `ollama`/`agent-runtime`, and the web
  terminal path is unchanged. No server, proto, CLI, or MCP change was needed —
  `recipe deploy agent-workspace <name>` and the `deploy_recipe` MCP tool work
  by virtue of the catalog entry.

## What still needs a live box to accept (out of spike scope)

1. **End-to-end deploy on a backend** — `containarium recipe deploy
   agent-workspace ws1 --param anthropic_api_key=… --server <host>`, then open
   the box's web terminal and confirm it lands directly in Claude Code, detach,
   re-open, and confirm re-attach to the same session. (Same "live-acceptance-
   pending" posture as #608's in-box loop.)
2. **npm install footprint** — `@anthropic-ai/claude-code` global install size /
   time on a 40GB box; pin a version for reproducibility.
3. **Disconnect durability** — confirm the tmux session and a long-running agent
   turn survive a websocket drop and reconnect.

## Required hardening before this is a product (NOT spike scope)

- **API key delivery.** The spike takes the Anthropic key as a recipe
  *parameter* and writes it to a root-owned `/etc/containarium/agent-workspace.env`.
  Production must seed it via the **tenant secrets mechanism** (AES-256-GCM,
  mode 0400) per `AGENT-RUNTIME-INBOX-LOOP-DESIGN.md`, never as a deploy-time
  parameter (parameters can land in audit logs / process args).
- **Model access / metering.** Direct box → `api.anthropic.com` has no cost
  control. The hosted-workspace product wants the central model gateway (per
  project memory: model-gateway + pull-queue RFC) so usage is per-tenant
  metered and key rotation is centralized.
- **Co-work UI.** The web terminal proves the path, but the product wants a
  chat-style co-work surface (stream agent output, not a raw TTY). That is the
  next build after this spike validates, and feeds the PRD.

## Verdict

The path holds: an always-on, re-attachable coding agent is **one recipe** on
top of shipped infrastructure. The spike is the proof; the PRD
(`PRD-...`, to follow) can now be written against a working mechanism rather
than a hypothesis.
