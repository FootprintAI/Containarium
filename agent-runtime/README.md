# agent-runtime — the in-box agent loop (Phase 4a)

The in-box loop for Containarium agent-skills. It runs *inside* an
`agent-runtime` box, reads what the daemon seeded, runs one task to completion,
and writes the result back — closing the seam every earlier phase left open
(`agent run` returning an empty artifact). Design:
`docs/AGENT-RUNTIME-INBOX-LOOP-DESIGN.md`.

This is a Node/TypeScript component (not Go) because the in-box loop uses an
**agent harness SDK**, and those are TS/Python — there is no Go Agent SDK.

## Engine-pluggable

The loop is harness-agnostic behind a small `Engine` interface
(`src/engine.ts`), and ships with two engines:

| Engine | SDK | Model default | Auth env |
| --- | --- | --- | --- |
| `claude` (default) | `@anthropic-ai/claude-agent-sdk` (powers Claude Code) | `claude-opus-4-8` | `ANTHROPIC_API_KEY` |
| `codex` | `@openai/codex-sdk` | engine default (set `CONTAINARIUM_AGENT_MODEL`) | `OPENAI_API_KEY` / `CODEX_API_KEY` |

Both mount the in-box **`agent-box`** binary as their MCP server, so agent-box's
tools (shell, files, process) are the agent's tool surface. The Claude engine
takes the MCP config inline (`mcpServers`); the Codex engine writes a
`~/.codex/config.toml` registering the same server.

Select with `CONTAINARIUM_AGENT_ENGINE=claude|codex` (a later phase moves this
onto the skill manifest as an `engine` field).

## Two modes

`CONTAINARIUM_AGENT_MODE` selects how the loop runs:

- `run` (default) — one-shot: read `input.json`, run once, write `artifact.json`.
  This is the `agent run` path (Phase 4a).
- `serve` — start the in-box **A2A server** on `:8674` and stay up:
  - `GET /agent-card` → the seeded agent card (peer discovery)
  - `POST /tasks` → run one delegated task (`AgentTask` in → `AgentArtifact`
    out), the listener the daemon's `SendAgentTask` reaches (Phase 4b).

  A failed task returns `200` with `state: AGENT_TASK_STATE_FAILED` so the caller
  still gets the artifact rather than an HTTP error.

## What it reads (the seed)

`RunAgentSkill` seeds `/etc/containarium/agent/` at launch
(`internal/server/agent_server.go`):

| File | Used as |
| --- | --- |
| `system_prompt.txt` | the engine's system prompt |
| `input.json` | the task |
| `agent-card.json` | discovery / output schema |
| `token` | scoped platform JWT (for the platform MCP; not the model key) |

…and writes `artifact.json` (`{outputJson, engine, model, usage, error?}`,
mode 0600) for the daemon to return.

## Two credentials, never interchangeable

- **Anthropic / OpenAI key** → drives the model. Seeded via the tenant
  **secrets** store (never in the prompt/input/artifact).
- **Scoped platform JWT** (`token`) → only for the Containarium **platform
  MCP**, bounded by the skill's `allowed_scopes`. Never sent to the model
  provider.

## Egress (interacts with the Phase-2 trust fabric)

The loop must reach the model provider API (`api.anthropic.com` /
`api.openai.com`) + DNS. Under `LOG_ONLY` this just shows in the audit log;
**before ENFORCE is armed** the provider API must be in the agent box's egress
allowlist or the agent is stranded (issue #611).

## Build

```bash
npm install
npm run typecheck   # tsc --noEmit
npm run build       # -> dist/
```

Verified: `tsc --noEmit` passes against the installed types of both SDKs
(`@anthropic-ai/claude-agent-sdk` 0.3.x, `@openai/codex-sdk` 0.138.x).

## Status / remaining 4a work

- ✅ The component: engine interface + Claude + Codex engines + seed/artifact +
  one-shot runner (4a) + the A2A server / serve mode (4b). Typechecks against
  real SDK types.
- ✅ **Daemon invoke + read-back** (4a) — `RunAgentSkill` execs the runtime and
  reads `artifact.json` into `RunAgentSkillResponse.artifact_json` (#614).
- ⏳ **Box image assembly** — the `agent-runtime` recipe must ship Node + this
  component + `agent-box` into the box (design-note open question #5).
- ⏳ **Serve-mode lifecycle** — a peer/crew-member box must run
  `CONTAINARIUM_AGENT_MODE=serve` as a long-running process so `:8674` is up;
  wired in 4c (crew choreography) alongside the daemon starting members.
- ⏳ **Live validation** — needs the assembled image + a provider API key + a
  backend (the standing "needs a live box" seam). Not runnable in CI alone.

4c wires crew choreography (`RunCrew` starts members in serve mode, drives the
hops, reports `COMPLETED`).
