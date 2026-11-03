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
(`src/engine.ts`), and ships with three engines:

| Engine | SDK | Model default | Auth env |
| --- | --- | --- | --- |
| `claude` (default) | `@anthropic-ai/claude-agent-sdk` (powers Claude Code) | `claude-opus-4-8` | `ANTHROPIC_API_KEY` |
| `codex` | `@openai/codex-sdk` | engine default (set `CONTAINARIUM_AGENT_MODEL`) | `OPENAI_API_KEY` / `CODEX_API_KEY` |
| `gemini` | `@google/genai` (Google Gen AI SDK) | `gemini-2.5-flash` | `GEMINI_API_KEY` / `GOOGLE_API_KEY` |

All mount the in-box **`agent-box`** binary as their MCP server, so agent-box's
tools (shell, files, process) are the agent's tool surface. The Claude engine
takes the MCP config inline (`mcpServers`); the Codex engine writes a
`~/.codex/config.toml` registering the same server; the Gemini engine connects an
MCP stdio client (`@modelcontextprotocol/sdk`) and hands it to the SDK via
`mcpToTool()`, with automatic function calling running the tool-use loop.

Select with `CONTAINARIUM_AGENT_ENGINE=claude|codex|gemini` (a later phase moves
this onto the skill manifest as an `engine` field). The `gemini` engine's cheap
default model makes it a budget-friendly way to exercise the mechanism end-to-end.

## Two modes

`CONTAINARIUM_AGENT_MODE` selects how the loop runs:

- `run` (default) — one-shot: read `input.json`, run once, write `artifact.json`.
  This is the `agent run` path (Phase 4a).
- `serve` — start the in-box **A2A server** on `:8674` and stay up:
  - `GET /agent-card` → the seeded agent card (peer discovery; unauthenticated)
  - `POST /tasks` → run one delegated task (`AgentTask` in → `AgentArtifact`
    out), the listener the daemon's `SendAgentTask` reaches (Phase 4b).

  A failed task returns `200` with `state: AGENT_TASK_STATE_FAILED` so the caller
  still gets the artifact rather than an HTTP error.

  **`POST /tasks` is daemon-only** (#2125). Every request must carry
  `Authorization: Bearer $CONTAINARIUM_A2A_TOKEN` — the per-box secret the daemon
  derives for this box and exports when it launches serve mode. A missing
  credential is `401`, a wrong one `403`, and neither reaches the engine or
  writes a journal line. Without `CONTAINARIUM_A2A_TOKEN` in the environment the
  server still starts, and still serves `/agent-card`, but refuses every task: a
  box that cannot tell the daemon from a peer serves nobody. Why it is shaped
  this way: `docs/architecture/execution-scoped-authorization.md`.

## What it reads (the seed)

`RunAgentSkill` seeds `/etc/containarium/agent/` at launch
(`internal/server/agent_server.go`):

| File | Used as |
| --- | --- |
| `system_prompt.txt` | the engine's system prompt |
| `input.json` | the task |
| `agent-card.json` | discovery; its `outputSchemaJson` is the artifact's enforced schema |
| `token` | scoped platform JWT (for the platform MCP; not the model key) |

…and writes `artifact.json` (`{outputJson, engine, model, usage, error?}`,
mode 0600) for the daemon to return.

When the skill's `agent_card.output_schema_json` is set, the engine hands it
to its provider's structured-output mechanism and `outputJson` is the
provider-validated result (#2002): Claude via the Agent SDK's `outputFormat`
(validated, re-prompted on mismatch; a run that never conforms fails with
`error` set rather than writing prose), Codex via the turn's `outputSchema`.
Gemini is prompt-only for now — its API accepts a response schema alongside
function calling only on Gemini 3 preview models — and journals that gap as a
`status` line. A malformed schema fails the seed load, never a silent
unenforced run.

## Run journal

Every run leaves an append-only JSON-lines journal on its box at
`/var/log/agent-runtime/runs/<run_id>/<skill_id>.jsonl` (#2095), one event per
line, written from each engine's message loop:

| `kind` | Fields | Notes |
| --- | --- | --- |
| `status` | `text` | `run started` / `run ended exit=N` bracket every run |
| `assistant` | `text` | model text |
| `tool_use` | `tool`, `input` | `input` truncated to 2 KiB |
| `tool_result` | `tool`, `text` | `text` truncated to 2 KiB |
| `error` | `text` | |

Every line also carries `seq` (monotonic per file, from 1) and `t` (ISO
timestamp). The zod schema and one fixture line per kind are exported from
`src/journal.schema.ts`; `fixtures/journal.jsonl` holds the same lines.
Credentials the runtime holds (the gateway token / provider keys from the
environment and the seeded platform JWT) are replaced with `[REDACTED]`
before a line is written.

- **Run mode** takes the ids from `CONTAINARIUM_RUN_ID` and
  `CONTAINARIUM_SKILL_ID`, which the daemon exports; missing either is a hard
  failure (exit 2, reason in `artifact.json`).
- A journal that cannot be opened or written (full disk, unwritable root)
  never fails a run in either mode: the run continues unjournaled and the
  process log says why.
- **Serve mode** takes `run_id` from each A2A task (`AgentTask.run_id`, set
  from the crew run) and the skill id from `CONTAINARIUM_SKILL_ID`. A task
  without a `run_id` runs unjournaled and says so on the process log.

`/var/log/agent-runtime.log` is unchanged: it stays the serve-mode process log.

## Two credentials, never interchangeable

- **Model-provider key** (Anthropic / OpenAI / Gemini) → drives the model.
  Seeded via the tenant **secrets** store (never in the prompt/input/artifact).
- **Scoped platform JWT** (`token`) → only for the Containarium **platform
  MCP**, bounded by the skill's `allowed_scopes`. Never sent to the model
  provider.

## Egress (interacts with the Phase-2 trust fabric)

The loop must reach the model provider API (`api.anthropic.com` /
`api.openai.com` / `generativelanguage.googleapis.com`) + DNS. Under `LOG_ONLY`
this just shows in the audit log; **before ENFORCE is armed** the provider API
must be in the agent box's egress allowlist or the agent is stranded (issue
#611). The daemon's `defaultAgentEgressDomains` covers all three providers.

## Python toolchain (opt-in, #3491)

The `agent-runtime` recipe takes an optional `toolchains` parameter, a
comma-separated list. Empty (the default) is the box as it always was. The only
supported value is `python`; any other value fails `post_start` before the box
installs anything:

```text
agent-runtime: unsupported toolchain "ruby" in toolchains="ruby" (supported: python)
```

With `toolchains=python`, `post_start` installs `python3-venv`, `python3-pip`
and `python3-pytest` from the Ubuntu archive, after the in-box loop assembly,
and fails if the `agent-python` helper did not come with that assembly (the
helper ships in this package's `bin/`, inside the release bundle). Python itself
is part of the Ubuntu 24.04 image.

`agent-python` is what a skill runs, through its shell tool, in its checkout:

| Command | Does |
| --- | --- |
| `agent-python setup [DIR]` | Creates (or reuses) a venv for `DIR` outside the checkout, then installs what `DIR` declares: `requirements.txt` and every other `requirements*.txt`, then `DIR` itself (`pip install -e .`, or `-e .[test]` / `-e .[tests]` when that extra is declared) if `pyproject.toml` has a `[project]` table or `setup.cfg` has `[metadata] name`. |
| `agent-python test [DIR] [-- CMD...]` | Runs `CMD` (default `python -m pytest`) in `DIR` inside that venv, prints `agent-python: test command executed: exit=N` on stderr, and exits `N`. |
| `agent-python venv [DIR]` | Prints the venv path. |

Nothing beyond the repo's own manifests is installed: a `setup.py` without
`pyproject.toml` `[project]` or `setup.cfg` `[metadata]` is not run, and a
`pyproject.toml` with only tool configuration is not installed. A repo with no
manifest gets an empty venv and a note saying so. The venv sees the system
site-packages, so the toolchain's pytest is used when the repo does not declare
its own.

Every failure is one line on stderr starting `agent-python: error:` and a
non-zero exit; pip's output goes to a log file whose last lines are printed and
whose path is in the error. Dependency installs can take minutes: call the shell
tool with a `timeout_seconds` long enough for them (its default is 30 s).

**Egress.** No default network policy changes. `setup` needs the Python package
index: by default `pypi.org` (the index) and `files.pythonhosted.org` (the
files it links to). Before installing, `setup` checks that the index answers
(`PIP_INDEX_URL` if set, else `https://pypi.org/simple/`); if not, it fails at
once with:

```text
agent-python: error: package index unreachable: pypi.org (...); dependencies were NOT installed; under restricted egress allow the Python package index (default hosts: pypi.org and files.pythonhosted.org); ...
```

A file host that is blocked while the index answers fails the install itself,
with the same host class named. A deployment that arms enforcement for agent
boxes (`CONTAINARIUM_AGENT_NETWORK_POLICY_ENFORCE=1`) and wants Python installs
must add both hosts to `CONTAINARIUM_AGENT_EGRESS_DOMAINS`. Setting that
variable replaces the built-in model-provider list, so list the providers too,
for example
`CONTAINARIUM_AGENT_EGRESS_DOMAINS=api.anthropic.com,api.openai.com,generativelanguage.googleapis.com,pypi.org,files.pythonhosted.org`.
The enforcer resolves domains to addresses, and `files.pythonhosted.org` is
served from a CDN, so a mirror reached through `PIP_INDEX_URL` on a stable
address is the more predictable choice. There is no recipe-level egress
allowlist, and the toolchain does not add one. The box's `apt-get` installs run
in `post_start`, at first provision, before the skill's egress policy is
applied.

**Getting a skill run into a Python box.** A skill run provisions its box
(`agent-<skill-id>`) with only the `release` parameter, and reuses a box that
already exists. To run a skill with the Python toolchain, deploy that box
yourself first:

```bash
containarium recipe deploy agent-runtime agent-<skill-id> \
  --param release=<daemon release tag> --param toolchains=python --server <host>
```

An existing box keeps the toolchains it was deployed with; delete it and deploy
again to change them.

## Build

```bash
npm install
npm run typecheck   # tsc --noEmit
npm run build       # -> dist/
```

Verified: `tsc --noEmit` passes against the installed types of all three SDKs
(`@anthropic-ai/claude-agent-sdk` 0.3.x, `@openai/codex-sdk` 0.138.x,
`@google/genai` 2.8.x + `@modelcontextprotocol/sdk` 1.29.x).

## Status / remaining 4a work

- ✅ The component: engine interface + Claude + Codex + Gemini engines +
  seed/artifact + one-shot runner (4a) + the A2A server / serve mode (4b).
  Typechecks against real SDK types.
- ✅ **Daemon invoke + read-back** (4a) — `RunAgentSkill` execs the runtime and
  reads `artifact.json` into `RunAgentSkillResponse.artifact_json` (#614).
- ✅ **Box image assembly** — `make bundle-agent-runtime` packages this
  component; `scripts/install-agent-runtime.sh` (run by the `agent-runtime`
  recipe's `post_start`) pulls agent-box + the bundle from the daemon's release
  and installs `agent-box` + `agent-runtime` onto PATH. Best-effort: a
  dev/unpublished release just skips it.
- ✅ **Serve-mode lifecycle** — `RunCrew` starts each member in serve mode
  (`startServeMode`); `agent run` uses run mode. Wired in 4c.
- ⏳ **Live validation** — needs the assembled image + a provider API key + a
  backend (the standing "needs a live box" seam). Not runnable in CI alone.

4c wires crew choreography (`RunCrew` starts members in serve mode, drives the
hops, reports `COMPLETED`).
