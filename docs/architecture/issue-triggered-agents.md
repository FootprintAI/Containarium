# Design: issue-triggered role agents

**Date:** 2026-09-25
**Status:** proposed
**Stack:** Go 1.26 (daemon, CLI, platform MCP); protobuf/gRPC + grpc-gateway;
Postgres (existing daemon store). No new languages, no new services, no new
deployables.
**PRD:** `docs/product/issue-triggered-agents.md` (#2021–#2026)
**Builds on:** `docs/architecture/agent-tracker-broker.md` (#1920, accepted)

## Problem

The tracker broker lets an agent run read, comment on, claim, label and open
a change for an issue without a forge credential in the box — but every run
is still started by a human. The PRD wants the tracker itself to be the
trigger: a `scope:<role>` label starts the matching skill, the run reports
back on the issue, and files human-gated follow-up issues for the next role.
Three things are missing and this doc designs them: a **dispatcher** that
turns a label into a run exactly once, an **issue-create verb** with a label
allow-list, and **chain guards** (approval gate, depth, fan-out) enforced by
the daemon rather than the prompt.

## Design

### The one decision that shapes everything: run-per-issue, not the pull queue

The PRD says "enqueue". This design **starts a run per issue through the same
internal path as `RunAgentSkill`** instead of the pull-queue prototype
(`EnqueueAgentTask`/`LeaseAgentTask`), and the PRD wording should be read that
way. Reasons, from the code as it stands:

1. The queue worker holds one coarse `agents:run` credential minted at
   `agent worker` start (`internal/server/agent_queue_server.go`). A leased
   task carries **no run-scoped JWT**, so no `tracker_conn` claim, no run id
   in `runlease`, and therefore no identity stamp — every brokered write
   would fail authz or be unattributable. `RunAgentSkill` already binds
   `tracker_connection` into the run JWT, registers the run in
   `runlease.Registry`, and revokes on end (`agent_server.go:344–440`).
2. The queue is in-memory and non-durable (`agent_task_queue.go`); a
   dispatcher restart would lose queued work and the "exactly once" story
   needs durable state anyway.

Closing both gaps in the queue is real work that buys nothing the MVP needs
(a handful of runs per tenant per day). It stays the 10× path (below).

### State owned by the daemon, content owned by the agent

| Writes | Owner | Mechanism |
| --- | --- | --- |
| `agent:queued` / `agent:running` / `agent:done` / `agent:failed`, removing the trigger label | **daemon** (dispatcher) | state machine on the durable dispatch row |
| Result comment, doc PR/MR, follow-up issues | **agent run** | existing verbs + new `CreateTrackerIssue`, stamped with the run identity |
| `agent:needs-approval` on follow-ups | **daemon** (forced on create) | policy, not prompt |

A run that forgets to comment still ends in a visible state; a run that is
prompt-injected cannot move state labels because state labels are on the
allow-list for the *dispatcher's* identity only (see Policy).

### Components

All Go, all inside existing binaries.

| Component | Lives in | Responsibility |
| --- | --- | --- |
| **Route store** | `internal/tracker/route.go` + `tracker_routes` table | `(tenant, connection, scope) → skill_id`. Typed; unmapped scope = no run |
| **Dispatch store** | `internal/tracker/dispatch_store.go` + `tracker_dispatches`, `tracker_issue_lineage` tables | Durable per-dispatch row with state, run id, depth, timestamps. **Exactly-once is a partial unique index**, not application logic |
| **Dispatcher core** | `internal/tracker/dispatch.go` | Pure tick: `List` routed issues → filter → insert row → start run → label. Injected `Provider`, `RunStarter`, `Clock`, store |
| **Policy** | `internal/tracker/policy.go` | `TrackerPolicy` on the connection: label allow-list, `auto_chain`, `max_depth`, `max_children`, `run_timeout`. Pure functions over typed inputs |
| **`CreateTrackerIssue` verb** | `internal/server/tracker_server.go`, `Provider.CreateIssue` on both adapters | Sanitize, allow-list, lineage/depth/fan-out checks, forced gate label, parent back-link, stamp, audit |
| **`DispatchTrackerIssues` RPC** | `internal/server/tracker_server.go` | One tick, server-side, `tracker:admin`. The CLI loop and a future daemon loop both call this |
| **Run completion hook** | `internal/server/agent_server.go` | On run end (artifact, error, or `runlease` timeout) → dispatch row `done`/`failed` → labels + failure comment |
| **CLI** | `internal/cmd/tracker_route.go`, `tracker_dispatch.go`, `tracker_issue_write.go` (create) | `tracker route set/list/delete`, `tracker dispatch [--once|--interval]`, `tracker issue create` |
| **Platform MCP** | `internal/mcp/tools.go` | `tracker_issue_create`, `tracker_route_list` — thin wrappers over the same client functions (CLI-first) |

```mermaid
sequenceDiagram
  participant H as Human
  participant F as Forge (GitHub/GitLab)
  participant C as CLI tracker dispatch
  participant D as Daemon (dispatcher core + broker)
  participant B as Skill box (run)
  H->>F: label issue scope:product
  loop every --interval
    C->>D: DispatchTrackerIssues(user, conn)
    D->>F: ListIssues(open, label scope:*)
    D->>D: filter: routed, no agent:* label, not needs-approval, depth <= max
    D->>D: INSERT tracker_dispatches (active-unique) — loser skips
    D->>B: start run (RunAgentSkill path, tracker_conn bound, input = TrackerDispatchInput)
    D->>F: labels +agent:queued
  end
  B->>D: GetTrackerIssue (tracker:read)
  D->>F: labels +agent:running −agent:queued (on run start)
  B->>D: CommentOnTrackerIssue / SubmitTrackerChange / CreateTrackerIssue
  D->>D: allow-list, depth, fan-out; force agent:needs-approval
  D->>F: create follow-up, comment on parent
  B-->>D: run ends (artifact | error | timeout)
  D->>F: labels +agent:done|failed −scope:product (+failure comment)
  H->>F: remove agent:needs-approval on a follow-up → next tick dispatches it
```

### Dispatch state machine

```
            insert row            run registered           run ended ok
 (no row) ───────────▶ queued ───────────────▶ running ───────────────▶ done
                         │                        │
                         │ start-run error        │ artifact error / runlease end without artifact
                         ▼                        │ / now > started_at + policy.run_timeout (tick)
                       failed ◀───────────────────┘
```

- Transitions are `UPDATE … WHERE state = $expected` (compare-and-set);
  a lost race is a no-op, never a double transition.
- `done` and `failed` are terminal. A re-run is a **new row**: the human
  removes `agent:done|failed` and re-adds `scope:<role>`; the tick sees no
  `agent:*` label and no active row, and inserts generation `n+1`.
- Label writes are applied *after* the row transition and are idempotent
  (add/remove sets). If the forge call fails the row keeps a
  `labels_pending` flag and the next tick retries — state is authoritative
  in Postgres, the forge is a projection of it.

### Exactly-once

```sql
CREATE UNIQUE INDEX tracker_dispatches_active
  ON tracker_dispatches (username, connection, issue_number)
  WHERE state IN ('queued','running');
```

Two dispatcher processes (or one restarted mid-tick) both list the same
unlabeled issue; both attempt the insert; one gets a unique-violation and
skips. The label is written only by the winner. This is the whole
correctness argument for #2022's third criterion, and it is tested against
a real Postgres (below), not a mock.

The index covers only *active* rows, so it cannot stop a stale list from
re-running an issue a peer has already finished (row `done`, labels
`agent:done`, scope label removed — all between this tick's list and its
insert). So after winning the insert the tick re-reads the issue (#2023)
and starts the run only if it is still open, still carries the routed
scope label, and has no state or gate label; otherwise it deletes its
never-started `queued` row and skips. `agent:running` is projected
synchronously before the in-box agent is launched, so any row that reaches
`done` has already put a state label on the forge by the time a peer
re-reads it.

### Run workspace (#2023)

A dispatched run's `git_source` is the connection's own repository
(`remoteURLFor`, the same URL `SubmitTrackerChange` pushes to), fetched
**without a credential** — the broker credential never enters the box.
The fetch is best-effort for dispatched runs only: a private repository
yields no workspace, the run still reads the issue and comments, and
`SubmitTrackerChange` answers `FAILED_PRECONDITION` (no recorded
`git_commit`), in which case the skill puts the document in its comment.
A daemon-side fetch for private repositories is a follow-up.

### Data flow of the run input

The run's `input_json` is not free-form: it is the protojson encoding of
`TrackerDispatchInput` (contract below). The agent gets the issue *reference*
and the dispatch id, never the issue body — it fetches the body through
`GetTrackerIssue` under its own `tracker:read`, so the body arrives as
brokered, untrusted data through the same path as every other read and is
never smuggled through the launch payload.

### Chain guards (Story 5)

- **Approval gate.** `CreateTrackerIssue` from a run token always adds
  `agent:needs-approval` unless `policy.auto_chain` is true. The dispatcher
  filter skips any issue carrying it. The human's only action per hop is
  removing that label.
  **Known gap (#2060, open):** that is not yet the only path. `scope:*` is
  on the default label allow-list, so a run token can add a routed scope
  label to an existing, ungated, human-created issue, which then dispatches
  at depth 0, uncounted against fan-out. A run token can also remove
  `agent:needs-approval` itself (open question on #2055). Both are pinned
  as current behavior by the `*_CurrentBehavior` tests in
  `internal/server/tracker_chain_guard_test.go`.
- **Depth.** `tracker_issue_lineage(child → parent, depth)` is written by
  `CreateTrackerIssue` with `depth = parent.depth + 1` (a human-created
  issue has no row → depth 0). Create is rejected when
  `depth > policy.max_depth` (default 3); the dispatcher also refuses to
  start a run for an issue whose depth exceeds the max, so a policy
  lowered later still holds.
- **Fan-out.** Create is rejected when the calling run already created
  `policy.max_children` (default 5) rows in lineage — counted by `run_id`,
  in the same transaction as the insert.
- **Label allow-list.** Policy default: `scope:*`, `model:*`,
  `agent:needs-approval`. Glob-matched, checked **before** any upstream
  call, for both `CreateTrackerIssue` and `SetTrackerIssueLabels`. The
  `agent:queued|running|done|failed` state labels are *not* on the run
  allow-list — only the dispatcher's own code path writes them, so an
  injected "mark this done" cannot.

### Failure paths (Story 6)

| Failure | Detected by | Result |
| --- | --- | --- |
| Skill box fails to provision / run start error | dispatcher tick, synchronously | row `failed`, `agent:failed`, comment with reason |
| Agent exits with error / empty artifact | completion hook | row `failed`, `agent:failed`, comment with run id + error |
| Run exceeds `policy.run_timeout` (default 1h) | next tick: `running` rows with `started_at + timeout < now` (and `queued` rows past it from `created_at`) | row `failed` (`TIMEOUT`), comment "timed out after …"; a provisioned run's lease is ended (`runlease.End`: revokes its JWTs, wipes its seed); a run still provisioning has no lease yet, so it is torn down the moment provisioning returns — its start report loses the compare-and-set, its lease is ended and its agent is never launched |
| Daemon restarts mid-run | `runlease` is single-process; every tick sweeps `running` rows (age from `started_at`) and `queued` rows (age from `created_at`) whose run this daemon does not hold, after a 5-minute grace | row `failed` (`LEASE_LOST`), `agent:failed`, comment naming the run — visible, never silently stuck, and a stranded `queued` row no longer locks the issue. The pre-restart run's JWTs cannot be revoked by this daemon (it never held them); they expire on their own |
| Forge unreachable during label write | row keeps `labels_pending`; tick retries with backoff | state never lost; labels catch up |
| Unmapped `scope:*` label | tick | one stamped warning comment per (issue, scope); recorded in a `tracker_dispatch_warnings` row so it is not repeated every tick |

Every failure above is one compare-and-set into `failed` carrying a typed
`TrackerDispatchFailure` cause (`START_ERROR`, `RUN_ERROR`, `TIMEOUT`,
`LEASE_LOST`); only the winner ends the lease, projects `agent:failed` plus
one comment (run id + reason from the cause, never the raw error), and emits
one terminal event — `containarium.tracker.dispatch.terminal` by state,
cause and scope, and `containarium.tracker.dispatch.result_latency` from the
row's insert (the `agent:queued` label) to the result (#2026). The sweep's
lease end runs on its own bounded budget and the projection on a fresh one
after it, so a lease end that hangs cannot leave a failed row silent on the
issue.

### Deployment shape

Nothing new ships. The daemon gains three tables (created in
`initSchema`, same pattern as `tracker_connections`), RPCs on the existing
`TrackerService`, and one completion hook. The CLI gains subcommands. The
operator runs `containarium tracker dispatch <user> <conn> --interval 60s`
wherever they already run `runner reconcile`; a systemd unit example goes in
the runbook. Config enters via flags/env as today; the only credential is the
operator token the CLI already uses (`tracker:admin`).

## Language choices

| Component | Language | Why this one | Type gate in CI |
| --- | --- | --- | --- |
| Route/dispatch/policy/lineage (daemon) | Go | Lives beside the broker core it extends; needs `runlease`, Postgres pool, and the `Provider` adapters that are all Go | `go vet`, `go build`, golangci-lint |
| `CreateTrackerIssue` adapters | Go | Same adapter packages (`internal/tracker/github`, `/gitlab`) and conformance suite | same |
| CLI + platform MCP | Go | Existing cobra tree and MCP tool registry; generated client | same |
| In-box role skill (product-define) | — | Not a new component: an existing skill run by the existing agent runtime; no code in this design | n/a |

No Python, no TypeScript. One language, one build lane.

## Contracts

All additions go in `proto/containarium/v1/tracker.proto` and are
regenerated with `make proto` (`.pb.go`, `.pb.gw.go`, swagger). Generated
code is never edited.

### Messages

```proto
// Where a scope label sends work. Unique per (username, connection, scope).
message TrackerRoute {
  string username = 1;
  string connection = 2;
  string scope = 3;       // the label suffix: "product" matches "scope:product"
  string skill_id = 4;
}

// Connection-level guardrails. Zero values mean the documented defaults.
message TrackerPolicy {
  repeated string label_allow_list = 1;  // globs; default scope:*, model:*, agent:needs-approval
  bool auto_chain = 2;                   // default false: follow-ups wait for a human
  int32 max_depth = 3;                   // default 3
  int32 max_children_per_run = 4;        // default 5
  int64 run_timeout_seconds = 5;         // default 3600
}
// TrackerConnection gains: TrackerPolicy policy = 8;

enum TrackerDispatchState {
  TRACKER_DISPATCH_STATE_UNSPECIFIED = 0;
  TRACKER_DISPATCH_STATE_QUEUED = 1;
  TRACKER_DISPATCH_STATE_RUNNING = 2;
  TRACKER_DISPATCH_STATE_DONE = 3;
  TRACKER_DISPATCH_STATE_FAILED = 4;
}

message TrackerDispatch {
  string id = 1;
  string username = 2;
  string connection = 3;
  int64 issue_number = 4;
  string scope = 5;
  string skill_id = 6;
  string run_id = 7;
  int32 depth = 8;
  TrackerDispatchState state = 9;
  string failure_reason = 10;
  google.protobuf.Timestamp created_at = 11;
  google.protobuf.Timestamp started_at = 12;
  google.protobuf.Timestamp ended_at = 13;
}

// The run's input_json is exactly this, protojson-encoded. No issue body.
message TrackerDispatchInput {
  string connection = 1;
  int64 issue_number = 2;
  string scope = 3;
  string dispatch_id = 4;
  int32 depth = 5;
}

message CreateTrackerIssueRequest {
  string username = 1;
  string connection = 2;
  string title = 3;
  string body = 4;
  repeated string labels = 5;     // must pass the allow-list
  int64 parent_number = 6;        // 0 = none; a run token MUST set it (lineage)
}
message CreateTrackerIssueResponse { TrackerIssue issue = 1; }

message DispatchTrackerIssuesRequest  { string username = 1; string connection = 2; }
message DispatchTrackerIssuesResponse {
  repeated TrackerDispatch started = 1;
  repeated TrackerDispatch timed_out = 2;
  int32 skipped_needs_approval = 3;
  int32 skipped_active = 4;
  int32 skipped_unrouted = 5;
  repeated TrackerDispatch failed = 6;
  int32 skipped_over_depth = 7;   // lineage depth > policy.max_depth (#2025)
}
```

### RPCs (on `TrackerService`)

| RPC | Scope | REST (`google.api.http`) |
| --- | --- | --- |
| `SetTrackerRoute` / `ListTrackerRoutes` / `DeleteTrackerRoute` | `tracker:admin` | `PUT/GET/DELETE /v1/tracker/{username}/{connection}/routes[/{scope}]` |
| `DispatchTrackerIssues` | `tracker:admin` | `POST /v1/tracker/{username}/{connection}/dispatch` |
| `ListTrackerDispatches` | `tracker:admin` | `GET /v1/tracker/{username}/{connection}/dispatches` |
| `CreateTrackerIssue` | `tracker:write` (run or operator) | `POST /v1/tracker/{username}/{connection}/issues` |

`TrackerPolicy` is set through the existing `SetTrackerConnection`
(`tracker connect … --label-allow … --auto-chain --max-depth …`).

### Adapter interface (Go, `internal/tracker/provider.go`)

```go
type NewIssue struct {
    Title  string
    Body   string
    Labels []string
}
// Added to WriterProvider; both adapters implement it.
CreateIssue(ctx context.Context, c Conn, n NewIssue) (Issue, error)
```

The daemon, not the adapter, appends the parent link (`#N` on GitHub,
`#N` on GitLab — both providers resolve a bare `#N` to an issue in the same
project; `!N` is reserved for merge requests) and the identity stamp to
`Body` before calling the adapter.

### DB schema (Postgres, `initSchema`)

```sql
CREATE TABLE IF NOT EXISTS tracker_routes (
  username TEXT NOT NULL, connection TEXT NOT NULL, scope TEXT NOT NULL,
  skill_id TEXT NOT NULL,
  PRIMARY KEY (username, connection, scope),
  FOREIGN KEY (username, connection) REFERENCES tracker_connections(username, name) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS tracker_dispatches (
  id UUID PRIMARY KEY, username TEXT NOT NULL, connection TEXT NOT NULL,
  issue_number BIGINT NOT NULL, scope TEXT NOT NULL, skill_id TEXT NOT NULL,
  run_id TEXT, depth INT NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('queued','running','done','failed')),
  failure_reason TEXT, labels_pending BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), started_at TIMESTAMPTZ, ended_at TIMESTAMPTZ);
CREATE UNIQUE INDEX IF NOT EXISTS tracker_dispatches_active
  ON tracker_dispatches (username, connection, issue_number) WHERE state IN ('queued','running');

CREATE TABLE IF NOT EXISTS tracker_issue_lineage (
  username TEXT NOT NULL, connection TEXT NOT NULL,
  child_number BIGINT NOT NULL, parent_number BIGINT NOT NULL,
  created_by_run TEXT NOT NULL, depth INT NOT NULL,
  PRIMARY KEY (username, connection, child_number));
```

`tracker_connections` needs a `policy JSONB` column holding the protojson
of `TrackerPolicy` (same approach the manifest uses for typed-but-optional
sub-messages) — read back through the generated decoder, never
`map[string]interface{}`.

### CLI surface

```
containarium tracker route set <user> <conn> --scope product --skill <id>
containarium tracker route list <user> <conn>
containarium tracker route delete <user> <conn> --scope product
containarium tracker dispatch <user> <conn> [--once | --interval 60s]
containarium tracker dispatches <user> <conn> [--state running]
containarium tracker issue create <user> <conn> --title … --body … --label scope:architecture --parent 42
containarium tracker connect … --label-allow 'scope:*' --auto-chain=false --max-depth 3 --max-children 5 --run-timeout 1h
```

## Test strategy

Type gate for every component: `go vet` + `go build` + golangci-lint on the
pushed branch, as today. Named tests are the deliverable per issue.

### Route store (`internal/tracker/route_test.go`) — real Postgres (testcontainer, as `store_test.go`)
- `TestRouteStore_SetGetListDelete` — table-driven CRUD, idempotent `Set`.
- `TestRouteStore_CascadeOnConnectionDelete` — deleting the connection drops its routes.

### Policy (`internal/tracker/policy_test.go`) — pure, table-driven
- `TestPolicy_Defaults` — zero value yields the documented defaults.
- `TestPolicy_LabelAllowList` — cases: exact, glob `scope:*`, rejected state label `agent:done`, rejected arbitrary `deploy:prod`, empty list = defaults.
- `TestPolicy_DepthAndFanout` — boundary cases at `max_depth` and `max_children`.

### Dispatch store (`internal/tracker/dispatch_store_test.go`) — real Postgres
- `TestDispatchStore_ActiveUniqueRace` — 2 goroutines insert for the same issue; exactly one succeeds; the loser gets `ErrDispatchActive`. **This is #2022's exactly-once proof.**
- `TestDispatchStore_CompareAndSetTransitions` — `queued→running`, `running→done`, `running→failed`; a stale transition (`queued→done`) is a no-op.
- `TestDispatchStore_RerunAfterTerminal` — insert succeeds again once the prior row is `done`.
- `TestDispatchStore_TimedOut` — returns `running` rows past timeout under an injected clock.
- `TestLineage_DepthAndChildrenCount` — depth derivation, per-run child count.

### Dispatcher core (`internal/tracker/dispatch_test.go`) — fake `Provider` (in-memory issues), fake `RunStarter`, real Postgres store, injected clock
- `TestDispatch_LabeledIssueStartsRunOnce` — one issue, two ticks → one run, labels `agent:queued`.
- `TestDispatch_SkipsNeedsApproval`, `_SkipsActive`, `_SkipsUnroutedWithOneWarning`, `_SkipsOverDepth`.
- `TestDispatch_StartRunErrorFails` — `RunStarter` error → row `failed`, `agent:failed`, reason comment.
- `TestDispatch_TimeoutSweep` — advance clock past `run_timeout` → `runlease.End` called, row `failed`, comment.
- `TestDispatch_LabelWriteRetry` — provider fails `SetLabels` once → `labels_pending`, next tick clears it.
- `TestDispatch_InputIsReferenceOnly` — the `input_json` handed to `RunStarter` decodes to `TrackerDispatchInput` and contains no issue body.

### `CreateTrackerIssue` (`internal/server/tracker_server_test.go` + conformance)
- `TestProviderConformance/CreateIssue` — extends the existing suite: same `NewIssue` → both adapters normalize the created issue identically (fixtures for both wire shapes). **This is #2024's GitHub+GitLab parity proof.**
- `TestCreateTrackerIssue_AllowListRejectsBeforeUpstream` — `deploy:prod` → `InvalidArgument`, fake provider records zero calls. **This is #2025's injection assertion**: the "issue body" fixture literally instructs the agent to add the label.
- `TestCreateTrackerIssue_ForcesGateForRunToken` — run token → `agent:needs-approval` added; operator token → not; `auto_chain=true` → not.
- `TestCreateTrackerIssue_RunTokenRequiresParent`, `_DepthCap`, `_FanoutCap`.
- `TestCreateTrackerIssue_BodyHasParentLinkAndStamp` — stamp from JWT claims only (mirrors `TestStamp_FromClaimsOnly`); parent gets one back-link comment.
- `TestCreateTrackerIssue_Audited` — audit row `(tenant, skill, run, model, verb=create, project, issue)`.

### Completion hook (`internal/server/agent_server_test.go`)
- `TestRunEnd_MarksDispatchDone`, `_MarksDispatchFailedWithComment`, `_NoDispatchRowIsNoop` (a plain `RunAgentSkill` unaffected).

### CLI (`internal/cmd/tracker_dispatch_test.go`, `tracker_route_test.go`) — generated client against a fake gRPC server, as `tracker_test.go` does
- `TestTrackerDispatch_OnceAndInterval` — `--once` returns after one tick; `--interval` loops until ctx cancel.
- Table-driven flag validation for `route set` / `issue create`.

### Assembled flow (`internal/server/tracker_dispatch_e2e_test.go`) — real Postgres, fake provider, fake in-box agent that calls the real verbs with a real run JWT
1. Label `scope:product` → tick → `agent:queued` → run starts → `agent:running`.
2. Fake agent: `GetTrackerIssue`, `CommentOnTrackerIssue`, `CreateTrackerIssue{labels: scope:architecture}`.
3. Run ends → `agent:done`, `scope:product` removed; child exists with `agent:needs-approval`, lineage depth 1.
4. Tick → child skipped; remove gate label → tick → child dispatched.
5. Second tick with the parent re-labeled → new generation row.

This is the PRD's core journey and the happy path `/qa-e2e-test` replays
against a live forge later (the design deliberately keeps that to one
scenario).

### What runs real vs. fake
| Dependency | In tests | Why |
| --- | --- | --- |
| Postgres | real (testcontainer) | the unique index *is* the correctness |
| Forge API | fake `Provider` + recorded fixtures for conformance | no network in CI; parity is a normalization property, not a live one |
| Skill box / runtime | fake `RunStarter`; fake agent in the e2e slice | box provisioning is covered by existing e2e lanes |
| Clock | injected | timeouts and staleness without sleeps |

## Deviations from the default stack

None. No new language, no new deployable, no hand-rolled HTTP handler
(everything is proto → grpc-gateway).

## Build order (maps to the PRD's P0 issues)

| Step | Issue | Delivers | Depends on |
| --- | --- | --- | --- |
| 1 | #2021 | `TrackerRoute` proto + store + `route` CLI/MCP | — |
| 2 | #2024 | `TrackerPolicy` + allow-list; `CreateIssue` on both adapters + conformance; `CreateTrackerIssue` RPC + CLI/MCP; lineage table | — |
| 3 | #2022 | `TrackerDispatch` proto + dispatch store + dispatcher core + `DispatchTrackerIssues` + `tracker dispatch` CLI | 1 |
| 4 | #2023 | `TrackerDispatchInput` contract; completion hook `done`; the product skill's manifest gets `tracker:read`, `tracker:write` and its prompt uses the verbs | 3 |
| 5 | #2025 | Gate/depth/fan-out enforcement wired into create + dispatcher filter; injection test | 2, 3 |
| 6 | #2026 | Timeout sweep, boot sweep, `labels_pending` retry, failure comments, `ListTrackerDispatches` + counters | 3 |

Steps 1–2 are independent and can run in parallel worktrees.

## At 10×

- **Many connections, tight forge rate limits** → the tick's `ListIssues`
  per connection becomes the cost. Move to webhook ingest (the broker doc's
  open question 6): a `/v1/tracker/webhook` endpoint that *only* enqueues a
  tick for one connection — the tick logic is unchanged, so this is additive.
- **Runs/day beyond what box-per-run tolerates** → make the pull queue
  durable (Postgres) and mint a per-task run JWT at lease time with
  `tracker_conn` + `runlease` registration. `RunStarter` is the seam: the
  dispatcher core does not change.
- **Multiple daemon instances** → the dispatch rows are already
  cross-instance safe; the timeout sweep must be leader-elected (or use
  `SELECT … FOR UPDATE SKIP LOCKED`), since `runlease` is per-process.

## Rejected alternatives

1. **Pull-queue enqueue (the PRD's literal wording).** Rejected for v1: no
   per-task run identity for brokered writes, non-durable queue. Kept as
   the 10× path behind the `RunStarter` seam.
2. **Webhook-first trigger.** Needs a public endpoint, forge-side secret
   management, and replay handling before the first run happens; polling
   needs none and the broker already committed to pull. Additive later.
3. **Forge CI (GitHub Actions / GitLab CI) as the trigger, calling the
   Containarium API.** Puts a platform token in CI, per-repo YAML to
   maintain, and bypasses the tenant's tracker connection as the single
   place policy lives. Also unavailable on forges where CI minutes are the
   scarce resource.
4. **Agent owns state labels.** Simpler (no completion hook) but a
   crashed, timed-out, or injected run leaves the issue lying about its
   state. State must be written by code that runs whether or not the model
   cooperates.
5. **Daemon-internal poll loop instead of a CLI process.** Same tick code;
   rejected only as the *first* driver because the CLI form is scriptable,
   observable in a terminal, and matches `runner reconcile`. A daemon loop
   calling the same function is a one-flag addition when wanted.
