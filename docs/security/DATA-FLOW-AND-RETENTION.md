# Customer data: where it is stored and how long it is kept

This document lists every store in Containarium that can hold prompts,
model responses, logs, session transcripts or evidence. For each store it
gives how long the data is kept today and which retention class covers it.
It is the data-flow document that #2576 asks for.

> **Status (slices A to C, #2875, #2876, #2877).** The retention windows and
> legal holds below can be set and read, and a sweeper reports what a window
> would remove. The daemon starts in **dry-run** mode, where nothing is
> deleted because of a window. An admin can switch it to **enforce** mode,
> and then the sweep deletes the eligible records of the stores *outside the
> hash chain*. The chained audit log and evidence bundles are never deleted
> yet. The "Kept today" column is what happens without enforce mode; the
> "Enforced default" column is what happens with it. Later slices:
>
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

A window must be between 1 and 36500 days (100 years). The upper bound
keeps the cutoff a sweeper computes from it far inside the range of a Go
`time.Duration`, which overflows past about 106,751 days. The Postgres
store enforces the same bound with a `CHECK` constraint.

```bash
containarium retention policy get --server <host>:50051
containarium retention policy set --prompts 14 --server <host>:50051
```

## Legal holds

Legal holds are per org.

- **A hold has no expiry.** It stays until an admin runs
  `containarium retention hold release <org-id>`.
- **After release, no grace period.** The org's records that are past their
  window become eligible on the sweeper's next pass; in enforce mode that
  pass deletes them.
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

## Dry-run and enforce mode

The daemon has one mode, set by an admin and stored with the policy:

- **`dry-run`** (the default, and what a daemon is in until someone sets
  it): the sweeper counts and reports; it deletes nothing.
- **`enforce`**: the same sweep, and then it deletes the eligible records of
  the stores listed under "The dry-run report" below.

```bash
containarium retention mode get --server <host>:50051
containarium retention mode set --mode enforce --server <host>:50051
containarium retention mode set --mode dry-run --server <host>:50051
```

Switching needs the admin role and writes a `retention.mode.set` audit entry
naming the caller and the mode it replaced; like a policy set, it is refused
(`INTERNAL`, nothing changes) if that entry cannot be written.

**Enforce needs an audit store.** On a daemon with no audit store (no
Postgres, REST disabled, or an audit store that failed to start), setting
`enforce` is refused with `FAILED_PRECONDITION` and the mode stays as it
was; `dry-run` is always allowed. The sweeper checks this too: if the mode is
`enforce` (stored before, or after a restart that lost the audit store) but
no audit store is wired, the sweep deletes nothing and logs the error every
hour. Deleting data is never done without a record of it. This is the one
exception to "with no audit store, changes go unrecorded" below.

The mode survives a restart on Postgres and resets to dry-run in memory.

What an enforced sweep does, once an hour:

1. It reads the policy, the mode and the legal holds, and counts every store
   (the same counts as the report).
2. If anything is eligible, it writes **one** `retention.sweep` audit entry,
   with the actor `retention-sweeper` (no admin runs the hourly sweep), the
   policy revision, the number of active holds and, per class and store, the
   window, the eligible count and the held count. The entry carries counts
   only, never the content of a record. If the entry cannot be written,
   **nothing is deleted** in that sweep. A sweep that finds nothing eligible
   writes no entry and deletes nothing, so an idle daemon does not add a row
   to the audit log every hour.
3. It deletes, store by store, the records older than the class cutoff that
   no hold keeps, in batches of 1000 rows and at most 100000 rows per store
   per sweep (a larger backlog is worked off over the next sweeps). Each
   batch is its own transaction. It first takes a `SHARE` lock on the holds
   table and then runs a `DELETE` that repeats the age test and has a
   `NOT EXISTS` on the holds table. Placing a hold inserts into that table,
   which the lock excludes: a hold that is being placed either committed
   before the batch looked, and stops it, or waits until the batch has
   committed. Placing a hold can therefore wait for one batch (at most a few
   seconds; the sweep gives up after 10 seconds of waiting), but no batch can
   delete a record a hold already covers. Records deleted by a batch that
   finished before the hold was committed are gone; a hold protects what is
   left. A `DELETE` can never touch a newer row.

A store the sweeper could not delete from, such as a table that does not
exist on this daemon, shows `not removed:` and the reason in the note of its
report entry, so a zero is not mistaken for "nothing was past the window".

`containarium retention report --refresh` is a read: it counts like a
dry run in either mode and never deletes. It does not replace the kept
report of an enforced sweep, so the evidence of what the last sweep removed
stays until the next sweep. A report from an enforced sweep has a `REMOVED`
column.

Existing shorter windows stay as they are (Q23 on #2727): the run-journal
reaper (7 days) and the traffic cleanup (7 and 28 days) keep running and
delete sooner than the class window; enforce mode only adds deletion where
none existed. A class that is not swept (below) is untouched by the mode.

A crew run keeps a prompt and a response in one row. In enforce mode a
`crew_runs` row is deleted once it is past the **longer** of the prompts and
responses windows, so neither class loses a record early. **The shorter
window is therefore not honored for these rows.** With a 90-day prompts window
and a 30-day responses window, a run's response is kept for 90 days, not 30.
This is the default proposed on #2877 and is still open for the owner to
confirm. The report still counts the row under each class against that
class's own window, and says so in the note of the shorter-window entry.

## The report

`containarium retention report` shows what a sweep would remove, or, for an
enforced sweep, what it removed. Run as a command it deletes nothing; the
report of a dry-run daemon says `mode: dry-run`.

```bash
containarium retention report --server <host>:50051            # the daemon's last report
containarium retention report --server <host>:50051 --refresh  # count now
```

The daemon counts at start and then hourly, and keeps the last report; the
report carries when it was counted and the policy revision it used, so a
window changed since then shows as a different revision. `--refresh` counts
now.

For each class and store the report gives the window, the cutoff (now minus
the window), and three counts:

- **Older**: records past the window.
- **Held**: the part of Older that a legal hold keeps. The stores below have
  no org column, so while *any* hold is active every record past the window
  counts as held.
- **Eligible**: Older minus Held, the records an enforcing sweep would
  remove.

Stores the sweeper counts today, by age column:

| Class | Store | Age column |
|---|---|---|
| Prompts | `agent_tasks` | `enqueued_at` |
| Responses | `agent_task_results` | `completed_at` |
| Prompts and responses | `crew_runs`, listed once per class | `created_at` |
| Gateway logs | `traffic_connections` | `created_at` |
| Gateway logs | `traffic_aggregates` | `interval_start` |

A crew run keeps a prompt and a response in one row, so it appears under
both classes, each against its own window. Counting it twice is a report
choice; its deletion is decided by the longer window (see above).

The window is a maximum (Q23): the daemon already deletes `traffic_*` rows
after 7 and 28 days, so those counts stay near zero until a window is set
below that. The report does not hide this.

Not counted, and listed as **not swept** with the slice that handles them:

- The hash-chained `audit_logs` classes (gateway logs and session
  transcripts): #2878.
- Evidence bundles: no bundle store exists yet; #2879.

On a daemon with no database every Postgres-backed store is listed as not
swept, because there is nothing to count. A store whose table does not exist
holds nothing and counts as zero. A store that fails to count is listed as
`error` with the reason, and the other stores are still counted.

## Who can change it, and the audit trail

Every retention command, reads and the report included, needs the admin
role.

Changes are audited:

- **What is logged.** A policy set, a hold and a release each write an
  audit entry naming the caller. The actions are `retention.policy.set`,
  `retention.hold.set` and `retention.hold.release`. A release entry names
  the admin who released the hold; its detail also keeps who set it.
- **The entry is written while the change is uncommitted.** The audit
  store writes the entry through its own connection, while the retention
  store holds the change in an open transaction (on Postgres) or under its
  lock (in memory).
- **A failed audit write fails the change.** The change is rolled back and
  the call returns `INTERNAL`, so a change never lands without its entry.
- **The reverse can happen in one rare case.** If the commit fails after
  the entry was written, the audit log keeps an entry for a change that
  never happened. `containarium retention policy get` then shows the lower
  revision, and `retention hold list` shows the hold state before the call.
- **With no audit store, changes go unrecorded.** On a daemon without one,
  a change succeeds and **no audit entry is kept**. That is the case when
  the daemon has no Postgres, REST is disabled, or the audit store failed
  to start. The guardrail baseline switch behaves the same way. The one
  exception is enforce mode, which is refused without an audit store (see
  "Dry-run and enforce mode").

Where the policy and holds are stored:

- **With Postgres**, they are in the tables `retention_policy`,
  `retention_windows`, `retention_mode` and `retention_legal_holds`.
- **Without a database**, they are kept in memory and lost on restart; the
  daemon logs this at startup.
- **If Postgres is configured but the store cannot be created at startup**,
  every retention call fails `UNAVAILABLE` until the daemon is restarted
  with Postgres reachable.

## Known limits

- **Any admin can hold or release any org.** Retention is per daemon (Q24
  on #2727), so a daemon-wide admin can place or release a hold on any
  org. There is no org-scoped role for holds.
- **Org ids are not checked against known orgs.** An org id is stored as
  given, after trimming whitespace. A mistyped id places a hold that
  protects nothing, and `hold list` shows it like any other. An id
  containing `/` is rejected, because the REST routes carry the org in one
  path segment.

## Inventory

**Enforced default** is what the sweeper does to that store in enforce mode,
with the class defaults above. **Hash chain** in the last column means the audit log's tamper-evident hash
chain.

| Class | Store | Org attribution | Kept today | Enforced default | Hash chain |
|---|---|---|---|---|---|
| Prompts | Agent task queue, `agent_tasks.input_json` (Postgres) | none | Deleted when the task completes; kept if it never completes | 30 days in enforce mode | no |
| Responses | Agent task results, `agent_task_results.artifact_json` / `error` (Postgres) | none | No automatic deletion | 30 days in enforce mode | no |
| Prompts and responses | Crew runs, `crew_runs.run` (Postgres; holds the run's input and output) | none | No automatic deletion; a standalone skill-run record is deleted with its journal | 30 days in enforce mode, the longer of the two class windows | no |
| Session transcripts | Agent run journals inside the box, `/var/log/agent-runtime/runs/<run>/` | none | 7 days (`--run-journal-retention`), removed hourly | none: inside the box, never swept (Q25) | no |
| Gateway logs | Connection logs, `traffic_connections` / `traffic_aggregates` (Postgres) | none | 7 days / 28 days, cleaned daily | 90 days in enforce mode, but the daily cleanup deletes sooner (7 / 28 days) | no |
| Gateway logs | Model-gateway detections and blocks, and the API access log, in `audit_logs` (Postgres). Metadata only: the model gateway never stores prompt or response bodies | `org_id`, often empty | No automatic deletion | not yet: hash-chained, slice #2878 | **yes** |
| Session transcripts | In-box SSH logins (`ssh_login`) and front-door SSH session records (`ssh_session_open` / `ssh_session_close`) in `audit_logs` | `org_id`, empty on a single-tenant daemon | No automatic deletion | not yet: hash-chained, slice #2878 | **yes** |
| Session transcripts | Front-door session log file on the sentinel VM | none | 90 days after rotation (configurable) | none: a file on the sentinel VM, rotated by logrotate | no |
| Evidence bundles | Proof Packs (`containarium proof-pack generate`, docs/PROOF-PACK.md), written to the file the operator names; the platform does not store them yet (#2798) | n/a | Kept as long as the operator keeps the file | not yet: no store, slice #2879 | n/a |
| (chain anchors) | `/var/lib/containarium/audit-anchors.jsonl` | n/a | No automatic deletion; required to verify the chain | none: required to verify the chain | anchors it |

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

- **Stores inside a box.** These include code-run records under
  `/tmp/agent-box/` (their `command` field holds the prompt) and a coding
  tool's own session files. They live and die with the box.
  - The agent run journals in the inventory are also inside the box. They
    are listed because the daemon already removes them after 7 days, but
    the session-transcripts window never sweeps them (Q25 on #2727).
- **Backups.**
  - Disk snapshots of a backend's data disk are opt-in and kept 30 days.
    They hold every Postgres table above and every box filesystem.
  - Tenant database dumps keep the newest N.
  - Box snapshots have no automatic expiry.
