# Agent Skills Quick Start

Run a packaged agent in its own Containarium box in a couple of minutes.

> **Phases 0–3.** This is the generic mechanism only. The daemon-side surface
> (run, discovery, agent-to-agent send, `allowed_peers` enforcement, audit) is
> wired and tested. The **in-box agent loop and the in-box A2A server are the
> box image's job and are not wired yet**, so a `run` seeds + network-gates the
> box but returns an empty artifact, and a `call` to a real box reaches no
> listener. See `docs/AGENT-SKILLS-CREWS-DESIGN.md` for the full design and
> crews (Phase 3).

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

## Trust fabric (Phase 2): `allowed_peers` enforcement

This is the differentiator. A skill's `allowed_peers` is enforced at two layers,
so an agent can only talk to the peers it declared:

1. **API boundary (always on).** `agent call` / `SendAgentTask` rejects a call
   to a peer not in the caller's `allowed_peers` with `PermissionDenied`,
   *before* any traffic leaves. The caller's identity is the authenticated token
   subject (an agent box's JWT subject is `agent-<skill-id>`), so a box cannot
   spoof a different caller to bypass the gate.
2. **In-kernel (opt-in).** At launch the daemon compiles `allowed_peers` into a
   per-box eBPF egress allowlist (each running peer's box IP as a `/32`). With
   enforcement armed, traffic to anything else is **dropped in the kernel** —
   not refused by a prompt — and the attempt is audit-logged. The crew topology
   and the network ACL are the same artifact.

Every A2A hop is recorded in the audit log under a shared `trace_id` (action
`agent.a2a_call`), so an auditor can follow a whole run. A caller (a crew, in
Phase 3) threads the `trace_id`; otherwise the daemon generates one and returns
it.

### Arming in-kernel enforcement

Off by default (observe-only). Arming needs **both** the daemon-wide eBPF
enforcer and the agent opt-in, on a Linux backend:

```bash
# daemon-wide eBPF enforcer (eBPF Phase A)
CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=/path/to/netpolicy.bpf.o
CONTAINARIUM_NETWORK_POLICY_ENFORCE=1

# agent-skill policies in ENFORCE mode, plus the platform egress an agent
# legitimately needs so a peer-only allowlist doesn't strand it (daemon API, DNS)
CONTAINARIUM_AGENT_NETWORK_POLICY_ENFORCE=1
CONTAINARIUM_AGENT_EGRESS_CIDRS=10.0.0.10/32,10.0.0.53/32
```

Without `CONTAINARIUM_AGENT_EGRESS_CIDRS`, an armed agent could only reach its
peers — review the audit `network_policy.deny_logged` events in LOG_ONLY first,
then add the platform CIDRs and flip ENFORCE.

## Crews (Phase 3)

A **crew** is a collaborating set of skills bound to a task purpose, wired by a
**topology**:

- `pipeline` — output of skill[i] feeds skill[i+1]
- `orchestrator` — a coordinator skill fans tasks to workers and synthesizes
- `freeform` — members coordinate freely within their `allowed_peers`

```bash
containarium crew list
containarium crew get hello-crew
containarium crew run hello-crew --input '{"q":"hi"}' --server <host>
containarium crew status <run-id> --server <host>
```

`crew run` does, in order:

1. **Validate topology against the trust fabric.** Every A2A edge the topology
   implies must be permitted by the members' `allowed_peers` — a crew can never
   ask for a hop Phase 2 would drop. A bad edge is rejected *before* any box is
   provisioned. (The reference `hello-crew` is a pipeline `relay-agent →
   hello-agent`, and `relay-agent.allowed_peers` includes `hello-agent`.)
2. **Provision each member's box** by reusing `agent run` — scoped token +
   per-box `allowed_peers` network policy, all under **one shared `trace_id`**
   so the whole run correlates in the audit log.
3. **Record the run** (`crew status <run-id>` polls it).

Driving a crew needs `crews:run` (plus `agents:run` + `containers:write`, since
it provisions boxes).

As of Phase 4c, `RunCrew` provisions each member in **serve mode**, drives the
topology hops over A2A under the shared `trace_id` (pipeline chains outputs;
orchestrator/freeform deliver to the entry skill), and moves the `CrewRun`
`RUNNING → COMPLETED` (or `FAILED` with the hop error). `crew status <run-id>`
shows the terminal state + artifact.

> **Seam.** This runs end-to-end only once the box image ships the in-box loop
> (`agent-runtime`) + `agent-box` so members actually serve `/tasks` — until
> then a run lands `FAILED` (no listener). Topology validation, provisioning,
> network gating, serve-mode start, hop sequencing, and the shared trace are all
> wired and tested.

## From an AI agent (MCP)

The platform MCP server exposes the same surface as thin wrappers:

- `list_agent_skills` — scope `agents:read`
- `run_agent_skill` — scope `agents:run`
- `call_agent` — scope `agents:call`
- `list_crews` — scope `crews:read`
- `run_crew` — scope `crews:run`

```jsonc
// run_agent_skill arguments
{ "skill_id": "hello-agent", "input_json": "{\"q\":\"hi\"}" }

// call_agent arguments
{ "to_peer_id": "hello-agent", "from_skill_id": "my-agent", "input_json": "{\"q\":\"hi\"}" }

// run_crew arguments
{ "crew_id": "hello-crew", "input_json": "{\"q\":\"hi\"}" }
```

## Add your own skill

Built-in: add an entry to `pkg/core/skills/skills.yaml` (compiled in).

External (no rebuild): drop `*.yaml` skill catalogs in `CONTAINARIUM_SKILLS_DIR`
and crew catalogs in `CONTAINARIUM_CREWS_DIR`; the daemon merges them onto the
built-ins at startup (skills first — crews reference them). Either way the
loader validates:

- `recipe_id`, `system_prompt`, and **at least one** `allowed_scope` are required.
- every `allowed_scope` must be a known scope (`internal/auth/scopes.go`) — a
  typo is a load-time error, not a silently-overbroad token.
- an id that collides with an already-loaded skill/crew is rejected.

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
    allowed_peers: []      # peers this skill may A2A-call (enforced, Phase 2)
    model: claude-opus-4-8
    agent_card:
      id: my-skill
      capabilities: [example]
```

## Limitations (by design)

- **No in-box loop / A2A server yet** — the box is provisioned, seeded, and
  network-gated; the in-box agent loop and the A2A `/tasks` server are the
  `agent-runtime` image's job (a later phase). `run` returns an empty artifact;
  `call` to a real box returns `Unavailable`.
- **Box name is derived from the skill id** (`agent-<skill-id>`), so two
  concurrent runs of the same skill collide. Per-run boxes / a warm pool are a
  later concern (see `docs/EPHEMERAL-SANDBOX-DESIGN.md`).
- **In-kernel drop is opt-in** — `allowed_peers` is enforced at the API
  boundary always, but the eBPF drop is observe-only (`LOG_ONLY`) until armed
  (see *Trust fabric* above) and requires a Linux backend.

## See also

- `docs/AGENT-SKILLS-CREWS-DESIGN.md` — the full design + roadmap (Phases 0–3)
- `docs/MCP-QUICKSTART.md` — getting an AI agent talking to the daemon
