# Spike — web chat workspace via OpenHands-in-a-box (`agent-workspace` recipe)

> Status: **Spike / proof-of-path, NOT live-validated.** Goal: prove that a
> hosted web chat workspace — Claude/ChatGPT-style chat + live preview +
> multiple persisted conversations, all stored inside one always-on box — is
> buildable mostly by *packaging an existing OSS engine* rather than building a
> chat UI + agent loop + session store from scratch.

## The idea in one line

Run **OpenHands** (web chat coding-agent with preview + persisted conversations)
**inside an always-on Containarium box**, expose its web UI as a subdomain, and
let the user co-work in the browser — then ship what they build to a separate
box via the platform MCP.

## Why reuse OpenHands

The product the user actually wants is the bolt.new / Lovable / OpenHands shape:
a chat surface, a live preview of what's being built, many conversations, all
persisted. Building that natively is a real frontend+backend effort. OpenHands
(All-Hands-AI, **MIT** — clean against our Apache-2.0) already provides:

- a web **chat UI**,
- a **coding agent** that edits files and runs commands,
- an in-container **workspace + browser/preview**,
- **multiple conversations**, persisted to disk,
- **bring-your-own Anthropic key**, single-container self-host.

Reuse candidates considered: **Open WebUI** (great multi-session chat + SQLite,
but a chat-to-LLM front — weak on "build a website + preview" — and a custom
license with a branding-preservation clause); **cmux** (already ruled out:
local macOS app, GPL-3.0). OpenHands won on fit + license.

**Containarium's value is the wrapper, not the chat UI:** an isolated always-on
box, eBPF/audit/secrets trust fabric, and one-click **ship-to-box**. We are the
safe, persistent host; OpenHands is the cockpit.

## How it works

The `agent-workspace` recipe (`pkg/core/recipes/recipes.yaml`):

- `post_start` runs the OpenHands web app via **Podman** (the box already runs
  OCI workloads via Podman — same as `ollama`/`llamacpp`), persisting
  conversations under **`/opt/openhands-state`** in the box — so "all sessions
  stored inside a box" holds.
- OpenHands spawns a per-conversation runtime sandbox; it drives the box's
  **Podman socket** (`DOCKER_HOST=unix:///run/podman/podman.sock`), so there is
  no docker-in-docker nesting beyond what the GPU recipes already do.
- The recipe's `ports` block exposes OpenHands' `:3000` as the `workspace`
  subdomain, so the whole **chat + preview + conversation-list** surface is
  reachable at `https://<name>-workspace.<base-domain>` over the platform's
  existing route + managed-TLS path.
- The Anthropic key + model are seeded via parameters into a root-only env-file
  the app reads (spike delivery — see hardening below).

Contrast with `agent-runtime`: same box-as-agent substrate, but that recipe is
headless/one-shot (seeded task → `artifact.json`); this one is the interactive,
human-in-the-loop chat workspace.

## What is proven in-tree (this spike)

- `go build ./pkg/core/recipes/... ./internal/server/...` — clean.
- `go test ./pkg/core/recipes/...` green, including `TestAgentWorkspaceRecipe`
  (catalog loads the recipe; GPU-free; exposes `:3000`; post_start runs
  OpenHands, persists to `/opt/openhands-state`, wires the Podman socket; the
  key is an optional `password` param; a model param exists).
- Deploy + routing are **inherited, not new**: `DeployRecipe` provisions the box
  and runs `post_start`; the `ports` block reuses the standard expose/route +
  managed-cert path. No server/proto/CLI/MCP change — `recipe deploy
  agent-workspace <name>` and the `deploy_recipe` MCP tool work from the catalog
  entry alone.

## What MUST be confirmed on a live box (this spike does NOT prove)

This `post_start` is a **first-draft integration**, written from OpenHands' docs,
not run. Before it ships, a live deploy on a backend must confirm:

1. **OpenHands image tag** (`openhands_version`, default `0.39`) and the matching
   `…/runtime:<ver>-nikolaik` sandbox image — confirm the current tags.
2. **Podman-socket wiring** — that OpenHands can spawn its runtime sandbox via
   `DOCKER_HOST=unix:///run/podman/podman.sock` inside the LXC. Fallback if not:
   OpenHands "local/CLI runtime" mode (the box *is* the sandbox, no nested
   engine). This is the single biggest integration risk.
3. **LiteLLM model id** (`llm_model`, default `anthropic/claude-sonnet-4-6`) —
   confirm OpenHands/LiteLLM accepts it; operator-overridable.
4. **Resource sizing** — OpenHands + the runtime image are heavy; confirm
   4c/8GB/60GB is enough for a smooth first conversation.
5. **Preview reachability** — that a dev server the agent starts is previewable
   (via OpenHands' built-in browser, and/or a second exposed port).

Live-acceptance steps: `containarium recipe deploy agent-workspace ws1 --param
anthropic_api_key=… --server <host>`, open `https://ws1-workspace.<base-domain>`,
start a conversation, have the agent scaffold + run a small site, confirm the
preview renders, open a second conversation, reload, confirm both persist.

## Required hardening before this is a product (NOT spike scope)

- **Key delivery** — replace the recipe parameter with the **tenant secrets
  mechanism** (AES-256-GCM, mode 0400). Parameters can land in audit logs /
  process args.
- **Auth in front of the UI** — OpenHands' `:3000` exposed on a subdomain needs
  the platform's auth in front of it (it is a full coding agent with shell). The
  route must require the tenant's session, not be world-open.
- **Cost / idle** — an always-on keyed agent is a spend risk; apply auto-sleep /
  idle-TTL (shipped scale-down primitives) and, at scale, the model gateway.
- **Native UI (v2)** — embedding OpenHands proves demand fast; owning the UX
  (our own chat surface over an in-box agent server) is the eventual build.

## Verdict

The path holds and is light: a hosted chat+preview+multi-session workspace is
**one recipe** packaging OpenHands on top of shipped box/route/TLS
infrastructure. This spike proves the wiring loads and deploys through existing
machinery; the integration details (above) need one live box to lock down. The
PRD (`PRD-HOSTED-AGENT-WORKSPACE.md`) is written against this mechanism.
