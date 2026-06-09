# Agent Skills Quick Start

Run a packaged agent in its own Containarium box in a couple of minutes.

> **Phase 0 (agent-as-a-box).** This is the generic mechanism only. The
> in-box agent loop is the box image's job and is not wired yet, so a run
> provisions and seeds the box but returns an empty artifact. See
> `docs/AGENT-SKILLS-CREWS-DESIGN.md` for the full design and the later
> phases (A2A transport, the `allowed_peers` → eBPF trust fabric, crews).

## What is a skill?

An **agent skill** is a packaged, runnable agent = a **box** (a recipe) plus a
typed **manifest**:

| Field | Meaning |
| --- | --- |
| `recipe_id` | the box the agent runs in (e.g. `agent-runtime`) |
| `system_prompt` | who the agent is |
| `allowed_scopes` | the platform scopes its in-box token may use — minted into a JWT at run time |
| `agent_card` | A2A discovery doc (used from Phase 1) |
| `allowed_peers` | which other skills it may talk to — compiles to eBPF network policy from Phase 2 (inert in Phase 0) |

The catalog ships in-tree as embedded YAML (`pkg/core/skills/skills.yaml`) and
is exposed as typed `AgentSkill` values. It ships **one neutral reference
skill**, `hello-agent`. Opinionated/domain skills live outside this repo.

## Browse the catalog (offline, no daemon)

The catalog is compiled into the CLI, so `list` and `get` work with no
`--server`:

```bash
containarium agent list
# ID               BOX              SCOPES            DESCRIPTION
# hello-agent      agent-runtime    containers:read   Neutral reference skill...

containarium agent get hello-agent
# ID:            hello-agent
# Box (recipe):  agent-runtime
# Allowed scopes: containers:read
# Allowed peers: (none — leaf agent)
# Capabilities:  echo, summarize
# ...
```

## Run a skill (needs a daemon)

`run` provisions the skill's box, mints a token scoped to **exactly** the
skill's `allowed_scopes`, and seeds the system prompt + token + task input
under `/etc/containarium/agent` inside the box.

```bash
containarium agent run hello-agent \
  --input '{"q":"hi"}' \
  --server <host>

# Running agent skill "hello-agent"...
#
# ✓ box ready: agent-hello-agent-container (RUNNING)
#
# (no artifact — the in-box agent loop is a Phase 0 seam; see docs/AGENT-SKILLS-QUICKSTART.md)
```

### Scopes

The operator/agent token that drives the AgentSkillService needs:

| Action | Required scope |
| --- | --- |
| `agent list` / `agent get` (via `--server`) | `agents:read` |
| `agent run` | `agents:run` (+ `containers:write`, since a run provisions a box) |

These gate the *caller*. They are separate from the skill's **own** in-box
token, which carries only the skill's declared `allowed_scopes`.

## From an AI agent (MCP)

The platform MCP server exposes the same surface as thin wrappers:

- `list_agent_skills` — scope `agents:read`
- `run_agent_skill` — scope `agents:run`

```jsonc
// run_agent_skill arguments
{ "skill_id": "hello-agent", "input_json": "{\"q\":\"hi\"}" }
```

## Add your own skill (local)

Add an entry to `pkg/core/skills/skills.yaml`. The loader validates at startup:

- `recipe_id`, `system_prompt`, and **at least one** `allowed_scope` are required.
- every `allowed_scope` must be a known scope (`internal/auth/scopes.go`) — a
  typo is a load-time error, not a silently-overbroad token.

```yaml
skills:
  - id: my-skill
    name: My Skill
    description: What it does.
    recipe_id: agent-runtime
    system_prompt: >-
      You are ...
    allowed_scopes:
      - containers:read
    allowed_peers: []      # inert until Phase 2
    model: claude-opus-4-8
    agent_card:
      id: my-skill
      capabilities: [example]
```

## Phase 0 limitations (by design)

- **No in-box loop yet** — the box is provisioned and seeded; producing the
  artifact is the `agent-runtime` image's job (a later phase). `run` returns an
  empty artifact.
- **Box name is derived from the skill id** (`agent-<skill-id>`), so two
  concurrent runs of the same skill collide. Per-run boxes / a warm pool are a
  later concern (see `docs/EPHEMERAL-SANDBOX-DESIGN.md`).
- **`allowed_peers` is inert** until Phase 2 wires it to eBPF network policy.

## See also

- `docs/AGENT-SKILLS-CREWS-DESIGN.md` — the full design + roadmap (Phases 0–3)
- `docs/MCP-QUICKSTART.md` — getting an AI agent talking to the daemon
