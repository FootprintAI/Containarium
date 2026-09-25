# PRD: Issue-triggered role agents (tracker → agent → follow-up issues)

**Date:** 2026-09-25
**Status:** reviewed (defaults accepted 2026-09-25)
**Owner:** hsinhoyeh

## Problem

The team's delivery loop is already role-shaped — product → architecture →
sprint → implement → review — and the hand-off medium is already the issue
tracker (`product`, `model:*`, `phase-*` labels). But every hop is a human
opening a terminal, invoking the right role, and copying context in and
results out. The platform has the agent-side pieces and nothing connecting
them to the tracker:

| Piece | State today |
| --- | --- |
| Pull-queue worker (`agent enqueue` / `agent worker`) | prototype, built |
| Tracker broker: `view`, `list`, `comment`, `claim`, `label`, `change submit` | shipped (epic #1920, GitHub + GitLab adapters) |
| Skill manifests with `tracker:read/write` scopes, run-scoped JWT | shipped |
| **Anything that turns "issue got a label" into "a run was enqueued"** | **missing** |
| **A verb to create an issue** (follow-ups) | **missing** — broker is comment/claim/label only |
| Event ingest | broker design deliberately says "pull is sufficient" |

Who hurts and how often: the maintainer(s) driving every cycle, once per
issue per role. Evidence: repo state above only. **No usage data or user
quotes exist** — the pain is an assumption (see Open questions).

## Target user

A maintainer or small team that already tracks work in GitHub or GitLab
issues and wants role agents (product, architecture, ...) to pick up
labeled issues unattended, report back on the issue, and queue the next
role's work — while a human stays the approver.

## Success metrics

| Metric | Baseline | Target |
| --- | --- | --- |
| Label-applied → result comment posted (p50) | unknown — instrument first | < 15 min for a product-scope issue |
| Runs reaching a terminal state (`done` / `failed`), not silently stalled | unknown — instrument first | 100% (every run ends in a visible label + comment) |
| Follow-up issues a human accepts without edits | unknown — instrument first | ≥ 60% after first 20 runs (quality signal, not a gate) |
| Human actions per role hand-off | ~4 (open terminal, invoke role, paste, file next issue) — assumption | 1 (approve the follow-up) |

## MVP scope — the core journey

A human labels an issue `scope:product`. Within one poll interval the
dispatcher claims it, enqueues a run for the product skill, the run reads
the issue through the broker, posts its result as a comment, and files
follow-up issues labeled `scope:architecture` (etc.) linked to the parent,
held behind an approval label. The parent ends `agent:done` (or
`agent:failed` with the reason). No credential enters the box at any step.

**Label contract (proposed):**
- Trigger: `scope:<role>` (e.g. `scope:product`, `scope:architecture`)
- State: `agent:queued` → `agent:running` → `agent:done` | `agent:failed`
- Gate: `agent:needs-approval` on agent-created follow-ups; human removes it to release

### P0 stories

**Story 1 — scope → skill routing** (#2021)
As an operator, I want to map a scope label to a skill on a tracker
connection so that labeling an issue selects which role agent runs.
- [ ] `containarium tracker route set <user> <connection> --scope product --skill <id>` stores the mapping; `route list` shows it
- [ ] An unmapped `scope:*` label is ignored and produces one warning comment, not a run
- [ ] Mapping is typed in proto (no free-form maps)

**Story 2 — dispatcher: labeled issue → claimed → enqueued, exactly once** (#2022, blocked by #2021)
As an operator, I want labeled issues picked up automatically so that no
one has to invoke the role by hand.
- [ ] `containarium tracker dispatch <user> <connection>` polls for open issues with a routed `scope:*` label and no `agent:*` state label
- [ ] For each: `claim` → set `agent:queued` → enqueue with the issue reference as input
- [ ] Restarting the dispatcher or running two instances never yields two runs for one (issue, scope) — proven by a test
- [ ] Re-labeling a `done` issue with the same scope re-runs it; a still-`running` one is skipped

**Story 3 — product run reports back on the issue** (#2023, blocked by #2022)
As the issue author, I want the result on the issue so that I don't have to
find a terminal or a run log.
- [ ] Run reads the issue via broker verbs only (`tracker:read`), no forge credential in the box
- [ ] Result posted as one comment carrying the platform-stamped `(skill, run, model)` identity line
- [ ] State label moves `queued → running → done`; the trigger label is removed
- [ ] Long output (the PRD itself) goes out via `change submit` as a doc PR/MR, with the comment linking to it

**Story 4 — create follow-up issues (new broker verb)** (#2024)
As a role agent, I want to file follow-up issues so that the next role has
scoped, linked work.
- [ ] `tracker issue create` verb, proto-first, CLI-first, platform MCP wraps the same client function; needs `tracker:write`
- [ ] Created on GitHub and GitLab through the shared adapter interface; the conformance suite covers both
- [ ] Body links the parent (`#N` / `!N` resolved per provider); parent gets a comment listing children
- [ ] Labels restricted to a per-connection allow-list (`scope:*`, `model:*`, `agent:needs-approval`); anything else is rejected

**Story 5 — loop and injection guards** (#2025, blocked by #2022, #2024)
As an operator, I want bounded, human-gated chains so that a bad or
injected issue body can't fan out unattended.
- [ ] Follow-ups always carry `agent:needs-approval`; the dispatcher ignores them until a human removes it (`auto_chain` per connection, default off)
- [ ] Max chain depth (default 3) and max children per run (default 5), enforced by the daemon, not the prompt
- [ ] Issue body/comments are passed to the agent as untrusted data; an issue that instructs the agent to widen scopes or labels cannot — the allow-list rejection is asserted in a test

**Story 6 — failures are visible** (#2026, blocked by #2022)
As a maintainer, I want a failed or stuck run to say so on the issue.
- [ ] Run error, lease expiry, or timeout → `agent:failed` + comment with reason and run id
- [ ] A run stuck in `running` past its timeout is failed by the dispatcher, not left silent
- [ ] Dispatcher emits the timing/terminal-state counts needed for the metrics above

## Later phases

- **P1** Live GitLab end-to-end run (P0 proves adapter parity via conformance only)
- **P1** `scope:engineering` role: implement → `change submit` (Phase 2 machinery already exists), gated
- **P1** Per-run cost / token budget with auto-fail
- **P2** Webhook ingest to replace polling (broker design defers this; revisit if poll latency hurts)
- **P2** GitHub App installation token as the daemon-held credential (already the broker's preferred type)
- **P2** Scope roles beyond product/architecture (review, QA, release)

## Out of scope

- Merge, approve, branch deletion, deploy — the broker excludes them on purpose; a human owns every irreversible step
- A general workflow/DAG engine — the "workflow" is labels; anything richer belongs to crews, not this
- Cross-tracker chains (GitHub issue spawning a GitLab issue)
- Auto-chaining by default — needs data from P0 runs before we trust it

## Open questions & assumptions

1. **Assumption:** the delivery bottleneck is hand-off toil, not agent quality. Validate: time 5 real hand-offs manually before building.
2. **Decided 2026-09-25:** human gate by default; `auto_chain` per connection stays opt-in and off.
3. **Decided 2026-09-25:** dispatcher is a `containarium tracker dispatch` CLI process using broker verbs — no forge credential beyond what the broker already holds; a daemon loop can wrap the same function later.
4. **Decided 2026-09-25:** long output goes out as a doc PR/MR via `change submit`; the issue comment links it.
5. **Assumption:** the "product agent" is the existing product-define role packaged as a skill; its packaging (agent-skills repo, manifest scopes) is not yet verified for unattended use.
6. **Constraint:** model access for unattended runs goes through the model gateway; confirm which upstream is available before promising latency numbers.
7. Polling rate limits against GitHub/GitLab at many connections — unmeasured.
