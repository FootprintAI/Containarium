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

## Live validation (2026-06-18, fts-13700k)

Stood the engine up in a throwaway box (`oh-spike`, Ubuntu 24.04 + Podman
4.9.3) to settle the integration unknowns. Findings updated the recipe:

- **OpenHands has been rewritten as "Agent Canvas."** The current image is
  `ghcr.io/openhands/agent-canvas:1.0.0-rc.11` on port **8000** — not the old
  `all-hands-ai/openhands:0.x` on 3000. The recipe was corrected.
- **No container-engine socket needed (biggest risk eliminated).** Agent Canvas
  runs the coding agent in the app container itself (box = sandbox); the run
  command takes no `DOCKER_HOST` / `SANDBOX_RUNTIME_CONTAINER_IMAGE`. The
  Podman-socket wiring was removed from the recipe.
- **Bind mounts need Podman `:U`.** First run crashed with SQLite "unable to
  open database file" — the non-root `openhands` user couldn't write the
  root-owned mount. `:U` (chown source to the container user) fixed it; the app
  then served **HTTP 200** with `<title>OpenHands</title>`.
- **Iframe headers are absent.** The root response sets **no
  `X-Frame-Options` and no `Content-Security-Policy`**, so the UI can be embedded
  cross-origin without stripping headers at the proxy — good news for the
  deferred "embed in the webui" goal.
- **Auth lives in the box, not at the edge.** OpenHands is rebound to
  `127.0.0.1:8000` and an in-box Caddy basic-auth proxy fronts it on `:8080`.
  Validated: no creds → **401**, wrong creds → **401**, correct creds → **200**,
  and OpenHands is not directly reachable. The box self-protects, so the
  platform edge just forwards plain HTTP to `:8080` (and terminates TLS) — no
  auth logic at core-caddy. This is now baked into the recipe (required
  `auth_password` parameter, bcrypt-hashed at deploy).
- **Still pending:** a real model call (needs an Anthropic key — set in the
  OpenHands settings UI, none available this session).

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

## Web UI embedding (shipped)

The console embeds the workspace directly: a **"Workspace" tab** in `web-ui`
(`src/components/workspace/WorkspaceView.tsx`) discovers `workspace`-subdomain
routes from the network route list and renders the box's UI in an iframe
(typechecks + lints clean). Embedding works because the OpenHands root response
carries no `X-Frame-Options`/`CSP` (validated above).

**Zero-click auth (implemented).** The in-box proxy supports three ways in,
all validated live on the box (2026-06-18):

- a **`/__ws_login?t=<token>` bootstrap** route → sets the `SameSite=None`
  session cookie and `302`-redirects to the app;
- the **cookie** itself, accepted in lieu of auth;
- **HTTP basic auth** as the fallback, which also issues the cookie.

The console gets zero-click by asking the daemon for a bootstrap URL:
`RecipeService.GetWorkspaceAccess(name)` (`GET
/v1/recipes/workspace/{name}/access`, scope `containers:read` + tenant authz)
reads the box's token via `ExecWithOutput cat /opt/wsauth/token` and returns
`https://<box>-workspace.<domain>/__ws_login?t=<token>`. `WorkspaceView` fetches
that and uses it as the iframe `src`, so the embedded workspace authenticates
with **no prompt and no first sign-in**. CLI parity:
`containarium recipe workspace-access <name>`. If the lookup fails (older box,
no route), the panel falls back to the plain URL + the "Open in new tab" path.

Validated on the box: bootstrap `/__ws_login?t=TOKEN` → `302` + `Location: /` +
`Set-Cookie`; cookie alone → `200`; no creds → `401`; basic auth → `200`.

Security note: the bootstrap token rides in a URL query (iframe `src`); it is a
per-box secret returned only to a `containers:read`-authorized caller, and the
cookie takes over immediately after the redirect. Acceptable for v1; a POST-based
handoff would remove it from URLs as a follow-up.

## Model provider + key (multi-provider, set in the UI)

The workspace is **provider-agnostic** — the recipe pins no model. Users choose
their provider and key in the UI: the Workspace tab has a **"Model setup"** view
that deep-links the iframe to OpenHands' own **Settings → LLM** (`/settings/llm`),
which supports **Anthropic, OpenAI / Codex, Google Gemini, Mistral, and any
LiteLLM model**, with saved profiles and mid-conversation switching. The
bootstrap cookie from the Chat view authenticates that page too.

Why deep-link instead of a form in our chrome: OpenHands' settings API is
internal, session-key-gated (a per-box `X-Session-API-Key`), and schema-
versioned (`agent_settings.llm`, model as a LiteLLM string) — reimplementing it
in the console would be cross-origin (CORS) and would drift every OpenHands
release. Deep-linking reuses their robust multi-provider form with ~zero
coupling. (A pre-seed-at-launch-via-secrets path remains the option if we later
want the console to own provider/key input centrally.)

## Operational notes — exposing via the cloud control plane

Validated live by standing the workspace up on a cloud-managed box and exposing
it on a public managed subdomain (auth + the zero-click bootstrap both confirmed
end-to-end over HTTPS). Two gotchas worth recording:

- **`expose_port` auto-appends the org zone suffix.** Pass the **bare
  subdomain** (e.g. `agentws`), not a full hostname. The cloud CP appends
  `-<org>.<zone>` itself, so passing a full domain doubles it
  (`<name>-<org>-<org>.<zone>`). The recipe's `ports.subdomain` is already a
  bare label, so a recipe-driven deploy is unaffected — this only bites manual
  `expose_port` calls that pass a full domain.

- **Rootless Podman needs persistence handling.** Containers set up by hand as
  the **non-root tenant** user die on SSH logout (the user session is torn down
  and `loginctl enable-linger` is denied to tenants). The `agent-workspace`
  recipe avoids this entirely: its `post_start` runs as **root**, so the
  containers live under the box's init with `--restart=always`. Only a
  by-hand, non-root setup needs linger enabled (by root) to survive logout.

## Remaining live-acceptance items (NOT yet proven)

The engine + wiring are validated (above). What a fuller live acceptance still
needs:

1. **A real model call** — set an Anthropic key in the OpenHands settings UI and
   confirm an end-to-end conversation that edits files and runs commands.
2. **Edge forward** — point a managed subdomain + TLS at the box's `:8080`
   (a plain reverse-proxy forward; auth already lives in the box, so the edge
   carries no auth logic). Operator's step (touches core-caddy).
3. **Persistence across recreate** — confirm conversations under
   `/opt/openhands-state` survive a container restart and a second conversation.
4. **Preview reachability** — that a dev server the agent starts is previewable
   (OpenHands' built-in browser, and/or a second exposed port).
5. **Resource right-sizing** — 4c/8GB/60GB is generous; trim after profiling.

Via the recipe (once a daemon carrying it is deployed): `containarium recipe
deploy agent-workspace ws1 --server <host>`, then expose `:8000` behind auth and
open the workspace.

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
