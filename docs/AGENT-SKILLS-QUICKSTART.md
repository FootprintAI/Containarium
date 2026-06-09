# Agent Skills Quick Start

Run a packaged agent in its own Containarium box in a couple of minutes.

> **Phases 0–1.** This is the generic mechanism only. The **in-box agent
> loop and the in-box A2A server are the box image's job and are not wired
> yet**, so a `run` seeds the box but returns an empty artifact, and a `call`
> to a real box reaches no listener. The daemon-side surface (run, discovery,
> agent-to-agent send) is wired and tested. See
> `docs/AGENT-SKILLS-CREWS-DESIGN.md` for the full design and the later phases
> (the `allowed_peers` → eBPF trust fabric in Phase 2, crews in Phase 3).

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
| `agent call` | `agents:call` |

These gate the *caller*. They are separate from the skill's **own** in-box
token, which carries only the skill's declared `allowed_scopes`.

## Talk to a peer (A2A) — Phase 1

Once two skills are running, one can delegate a task to the other over the
**agent-to-agent (A2A)** transport and get an artifact back:

```bash
containarium agent run hello-agent --server <host>          # the peer
containarium agent run my-agent   --server <host>           # the caller

containarium agent call hello-agent \
  --from my-agent \
  --input '{"q":"hi"}' \
  --server <host>

# Delegating task to peer "hello-agent"...
#
# ✓ task task-my-agent-hello-agent — AGENT_TASK_STATE_COMPLETED
#
# Artifact:
# {"ok":true}
```

How it works: the daemon resolves the peer's box, finds its in-box A2A server
at `http://<box-ip>:8674/tasks`, POSTs an `AgentTask`, and returns the
`AgentArtifact`. The peer's agent card (seeded at `run` into
`/etc/containarium/agent/agent-card.json`) is what the in-box server serves for
discovery.

Driving the call needs the `agents:call` scope.

> **Phase 1 seam.** The in-box A2A *server* (which receives `/tasks`) is the
> `agent-runtime` image's job. Until it ships, `agent call` to a real box
> returns `Unavailable`. The daemon-side transport + discovery + resolution are
> wired and unit-tested against a stub peer.

> **Phase 2 preview.** `allowed_peers` becomes enforced: the daemon rejects a
> `call` to a peer not in the caller's `allowed_peers`, and eBPF network policy
> drops the hop in-kernel. In Phase 1 the send is best-effort.

## From an AI agent (MCP)

The platform MCP server exposes the same surface as thin wrappers:

- `list_agent_skills` — scope `agents:read`
- `run_agent_skill` — scope `agents:run`
- `call_agent` — scope `agents:call`

```jsonc
// run_agent_skill arguments
{ "skill_id": "hello-agent", "input_json": "{\"q\":\"hi\"}" }

// call_agent arguments
{ "to_peer_id": "hello-agent", "from_skill_id": "my-agent", "input_json": "{\"q\":\"hi\"}" }
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

## Limitations (by design, Phases 0–1)

- **No in-box loop / A2A server yet** — the box is provisioned and seeded; the
  in-box agent loop and the A2A `/tasks` server are the `agent-runtime` image's
  job (a later phase). `run` returns an empty artifact; `call` to a real box
  returns `Unavailable`.
- **Box name is derived from the skill id** (`agent-<skill-id>`), so two
  concurrent runs of the same skill collide. Per-run boxes / a warm pool are a
  later concern (see `docs/EPHEMERAL-SANDBOX-DESIGN.md`).
- **`allowed_peers` is inert** until Phase 2 wires it to eBPF network policy
  (the send is best-effort and ungated in Phase 1).

## See also

- `docs/AGENT-SKILLS-CREWS-DESIGN.md` — the full design + roadmap (Phases 0–3)
- `docs/MCP-QUICKSTART.md` — getting an AI agent talking to the daemon
