# Customer data: where it is stored and how long it is kept

This document lists every store in Containarium that can hold prompts,
model responses, logs, session transcripts or evidence. For each store it
gives how long the data is kept today and which retention class covers it.
It is the data-flow document that #2576 asks for.

> **Status (slice A, #2875).** The retention windows and legal holds below
> can be set and read, but **nothing enforces them yet**. No sweeper runs and
> nothing is deleted because of a window. The "Kept today" column is what
> actually happens. Later slices add enforcement:
>
> - #2876: a dry-run report of what would be removed.
> - #2877: enforced deletion for the stores outside the hash chain.
> - #2878: removing the oldest rows of the hash-chained audit log.
> - #2879: evidence bundles.
>
> This document is updated as each slice ships.

## Retention classes and their defaults

Retention is set per daemon, with one window per class. The window is a
**maximum**: a store that already deletes sooner keeps doing so.

| Class | Default window | `containarium retention policy set` flag |
|---|---|---|
| Prompts | 30 days | `--prompts` |
| Model and agent responses | 30 days | `--responses` |
| Gateway and API access logs | 90 days | `--gateway-logs` |
| Session transcripts and session records | 90 days | `--session-transcripts` |
| Evidence bundles | 365 days | `--evidence-bundles` |

These defaults were accepted on the sprint umbrella (#2727, Q6). Defaults
are not written to the database: `containarium retention policy get` marks
a class `(default)` until an admin sets it.

```bash
containarium retention policy get --server <host>:50051
containarium retention policy set --prompts 14 --server <host>:50051
```

## Legal holds

Legal holds are per org.

- **A hold has no expiry.** It stays until an admin runs
  `containarium retention hold release <org-id>`.
- **After release, no grace period.** The org's records that are past their
  window become eligible on the sweeper's next pass.
- **Unattributed records are held too.** Many stores have no org column (see
  the inventory). While *any* hold is active, a record with no org is
  treated as held and is never deleted.
- **One global hash chain.** On the hash-chained audit log (see below), the
  oldest held row also stops the purge of everything after it.

```bash
containarium retention hold set <org-id> --reason "<case reference>" --server <host>:50051
containarium retention hold list --server <host>:50051
containarium retention hold release <org-id> --server <host>:50051
```

## Who can change it, and the audit trail

Every retention command, reads included, needs the admin role.

Changes are audited:

- **What is logged.** A policy set, a hold and a release each write an
  audit entry naming the caller. The actions are `retention.policy.set`,
  `retention.hold.set` and `retention.hold.release`. The entry is written
  inside the same store transaction as the change.
- **A failed audit write fails the change.** The change is rolled back and
  the call returns `INTERNAL`.
- **With no audit store, changes go unrecorded.** On a daemon without one,
  a change succeeds and **no audit entry is kept**. That is the case when
  the daemon has no Postgres, REST is disabled, or the audit store failed
  to start. The guardrail baseline switch behaves the same way.

Where the policy and holds are stored:

- **With Postgres**, they are in the tables `retention_policy`,
  `retention_windows` and `retention_legal_holds`.
- **Without a database**, they are kept in memory and lost on restart; the
  daemon logs this at startup.
- **If Postgres is configured but the store cannot be created at startup**,
  every retention call fails `UNAVAILABLE` until the daemon is restarted
  with Postgres reachable.

## Inventory

**Hash chain** in the last column means the audit log's tamper-evident hash
chain.

| Class | Store | Org attribution | Kept today | Hash chain |
|---|---|---|---|---|
| Prompts | Agent task queue, `agent_tasks.input_json` (Postgres) | none | Deleted when the task completes; kept if it never completes | no |
| Responses | Agent task results, `agent_task_results.artifact_json` / `error` (Postgres) | none | No automatic deletion | no |
| Prompts and responses | Crew runs, `crew_runs.run` (Postgres; holds the run's input and output) | none | No automatic deletion; a standalone skill-run record is deleted with its journal | no |
| Session transcripts | Agent run journals inside the box, `/var/log/agent-runtime/runs/<run>/` | none | 7 days (`--run-journal-retention`), removed hourly | no |
| Gateway logs | Connection logs, `traffic_connections` / `traffic_aggregates` (Postgres) | none | 7 days / 28 days, cleaned daily | no |
| Gateway logs | Model-gateway detections and blocks, and the API access log, in `audit_logs` (Postgres). Metadata only: the model gateway never stores prompt or response bodies | `org_id`, often empty | No automatic deletion | **yes** |
| Session transcripts | In-box SSH logins (`ssh_login`) and front-door SSH session records (`ssh_session_open` / `ssh_session_close`) in `audit_logs` | `org_id`, empty on a single-tenant daemon | No automatic deletion | **yes** |
| Session transcripts | Front-door session log file on the sentinel VM | none | 90 days after rotation (configurable) | no |
| Evidence bundles | Proof Packs (`containarium proof-pack generate`, docs/PROOF-PACK.md), written to the file the operator names; the platform does not store them yet (#2798) | n/a | Kept as long as the operator keeps the file | n/a |
| (chain anchors) | `/var/lib/containarium/audit-anchors.jsonl` | n/a | No automatic deletion; required to verify the chain | anchors it |

The model gateway holds token counts in memory only, so they are gone after
a restart.

### The hash-chained audit log

Gateway logs and session transcripts in `audit_logs` share one hash chain
across every org. Deleting a row from the middle, such as one org's rows or
one class's rows, breaks verification for every later row. Retention there
can therefore only remove the **oldest** rows. Even those must be strictly
below the latest published anchor, with a stored chain base, so that
`containarium audit verify` and `audit verify-anchor` still pass. That is
slice #2878, which also closes #2420.

### Out of scope: documented, not swept

These stores are not covered by the retention classes:

- **Stores inside a box.** Code-run records under `/tmp/agent-box/` (their
  `command` field holds the prompt) and a coding tool's own session files
  live and die with the box.
- **Backups.**
  - Disk snapshots of a backend's data disk are opt-in and kept 30 days.
    They hold every Postgres table above and every box filesystem.
  - Tenant database dumps keep the newest N.
  - Box snapshots have no automatic expiry.
