# Design: container snapshots — which service owns them

**Date:** 2026-08-16 (revised same day; see History)
**Status:** **accepted** for ownership and the lifecycle (shipped in #1381, #1383) · **proposed** for clone (#1160c, revised below)
**Decides:** the open question on #1160; unblocked #1202, now closed
**Stack:** Go only — no new language, no new deployable, no new dependency

## Problem

There was **no snapshot primitive exposed anywhere**. The ZFS layer beneath one had existed and been tested against a real pool for some time — `zfscrypt` has `Snapshot`, `ListSnapshots`, `DestroySnapshot`, `RollbackToSnapshot`, `SnapshotUsage` and `EnsureInspectable` — but everything above it was missing, which blocked #1202.

The original open question was **which service owns container snapshots**, because answering it inside a feature PR would settle an architecture decision by implementation, quietly.

## Decision

**`ContainerService`.** Shipped in #1381 and #1383; #1202 closed on the result.

A container snapshot's subject is a container. The caller holds a username; the dataset is an implementation detail the daemon already resolves (`incus.ContainerDataset`). Three things follow:

1. **Authorization is already correct there.** Every `ContainerService` RPC runs `AuthorizeTenant(ctx, req.Username)`. On `VolumeService` the subject is a shared volume several tenants attach, so the tenant check means something different.
2. **The encryption interactions live there.** `encryptionHooks` is a `ContainerServer` field. Putting the RPCs elsewhere means a second server reaching into that state.
3. **It needs no new service to exist.** A `SnapshotService` would be justified by a second consumer; there is exactly one.

### What this is not

**Not `VolumeService`.** That service is **CephFS shared multi-writer volumes** (#384), capability-gated on a CephFS pool. Adding ZFS container-dataset snapshots there produces a service spanning two substrates with two capability gates, where every RPC must disambiguate *which kind of thing am I snapshotting*.

**Not `BackupService`**, despite the name. That is **logical database backup** — `pg_dump`-shaped, into GCS, restorable into a *different* container. A ZFS snapshot is physical, host-local and instantaneous. The two answer different questions ("can I get this data somewhere else?" vs "can I return this container to how it was ten minutes ago?").

**Not both.** If CephFS volume snapshots are wanted later they belong on `VolumeService`, over the same primitive underneath.

## Contracts

On `ContainerService`, tenant-scoped, over the existing grpc-gateway REST mapping.

| RPC | HTTP | Status |
|---|---|---|
| `CreateContainerSnapshot` | `POST /v1/containers/{username}/snapshots` | shipped #1381 — succeeds with the key unloaded |
| `ListContainerSnapshots` | `GET /v1/containers/{username}/snapshots` | shipped #1381 — carries per-snapshot space usage |
| `DeleteContainerSnapshot` | `DELETE /v1/containers/{username}/snapshots/{name}` | shipped #1381 — works with the key unloaded |
| `RollbackContainerSnapshot` | `POST /v1/containers/{username}/snapshots/{name}/rollback` | shipped #1383 — three guards, below |
| `CloneContainerFromSnapshot` | `POST /v1/containers/{username}/snapshots/{name}/clone` | **proposed** — #1160c, revised below |

CLI is **`containarium snapshot <verb>`**, not `containarium container snapshot`: there is no `container` parent command in this CLI — container verbs are top-level (`create`, `delete`, `list`, `info`, `move`, `label`, `backup`). The earlier wording in this doc described a command group that does not exist.

**Space usage is not optional.** A forgotten snapshot silently pins disk, so `ListContainerSnapshots` carries `used_bytes` (what deleting it frees) and `referenced_bytes` rather than making an operator shell out to `zfs list -t snapshot`.

## The encryption interaction (#1202, closed)

Resolved decision #3 of the encryption design allows snapshot creation when the key is unavailable and makes inspection fail predictably. Blocking creation on key-custody reachability would let a transient outage suppress the backup window.

- **Create and delete succeed with the key unloaded.** No key check. Proven on the Incus lane against a real pool.
- **Inspection fails with a specific error naming key custody.** This landed on **rollback**, not on the lifecycle slice: the lifecycle deliberately needs no key, so nothing in it inspects anything. Rollback is the first operation that depends on a snapshot's *contents* being readable — a rollback whose result cannot be opened is not a restore.
- **`encryption_state` reports `KEY_UNAVAILABLE`** on the container itself.

**A latent bug this surfaced.** `EnsureInspectable` propagated `KeyStatus`'s error verbatim, and `KeyStatus` errors on an *unencrypted* dataset. As written it would have refused inspection and rollback for essentially every container on the platform, while its own tests stayed green because they only ever supplied an encrypted one. "Not encrypted" is now the `zfscrypt.ErrNotEncrypted` sentinel — three distinguishable answers ("no key here" / "key missing" / "zfs did not answer") instead of one error string.

## What the lane established about clone — and what it disproved

This doc previously deferred clone saying *"a ZFS clone must stay within its origin's encryptionroot, so a clone across tenants is not expressible"*, and asked for that to be confirmed on the lane first. It was confirmed, and **the premise is wrong** (#1384, `pkg/core/zfscrypt/clone_constraints_integration_test.go`).

| # | Established on a real pool | Consequence |
|---|---|---|
| 1 | A clone of tenant A's snapshot **can** be created under tenant B's dataset. ZFS does not confine it. | A cross-tenant clone **is** expressible and must be refused by the **daemon** — the substrate will not refuse it |
| 2 | The clone keeps **A's** encryptionroot. With A's key unloaded and B's loaded, the clone under B reports `keystatus unavailable` | The isolation claim behind #1199 **holds**. B gains no readable copy |
| 3 | Cloning **requires** the origin's key loaded | Clone does not follow the lifecycle's no-key rule; it needs a key precondition like rollback |
| 4 | A clone **pins** its origin snapshot (`snapshot has dependent clones`) | Clone introduces a way for a previously-reliable `DeleteContainerSnapshot` to start failing |

This is the same rule #1335 found for Incus instance volumes: **a clone inherits encryption from its origin, not from its location.** The hazard is not the one the design feared — it is *placement*, not key isolation. Tenant A's data can come to rest inside tenant B's subtree, where B's lifecycle operations act on it. Filed as **#1385** (tenant offboarding walks a tenant's own subtree and would both miss and mis-report such a clone).

## The clone design (#1160c)

**Clone is `incus copy`, not `zfs clone`.**

#1160 proposes `CloneFromSnapshot` → "a new volume backed by a ZFS clone". Under the ownership decision above the subject is a container, and that changes the mechanism.

A raw `zfs clone` produces a **dataset Incus does not know about**: not an instance, no config, no devices, absent from `incus list` and from the daemon's own container listing, outside quota accounting, and with no encryption placement record. It is storage nobody can boot. Making it bootable means reconstructing everything Incus stores about an instance — which is a re-implementation of `incus copy` with a worse failure surface.

The daemon **already does this correctly elsewhere**: `MoveContainer` runs `incus snapshot <c> <snap>` then `incus copy <c>/<snap> <remote>:<c> --instance-only --storage <pool>` (`pkg/core/incus/migration.go`), and #1203 already threads the tenant pool through `--storage`. Clone is that same call with a local destination and a new instance name.

The four established facts land as follows:

- **Fact 1 → the daemon refuses cross-tenant.** `CloneContainerFromSnapshot` is tenant-scoped like every other `ContainerService` RPC; source and destination are both `{username}`'s. There is no cross-tenant form of the RPC, so the refusal is structural rather than a check that can be forgotten. Targeting `--storage <tenant-pool>` keeps the copy inside the tenant's encryptionroot by construction.
- **Fact 3 → clone requires the key**, and maps its absence to `FailedPrecondition` naming key custody, exactly as rollback does. This is a *deliberate asymmetry* with create/delete and must be stated in the RPC's own doc comment: an API where some verbs need custody and others do not is one an operator cannot reason about unless it says so.
- **Fact 4 → does not arise via `incus copy`**, which produces an independent instance rather than a dependent clone. This is the strongest argument for the mechanism: choosing `zfs clone` would import a permanent new failure mode into an already-shipped delete path, in exchange for speed.

**The honest cost.** `incus copy` is a full copy where `zfs clone` is instant and initially free. A clone of a 50 GB container costs 50 GB and minutes, not bytes and milliseconds. That is the trade: an instance that exists and can be booted, against a dataset that is cheap and inert. **Open question for the lane, not for review:** whether Incus optimises a same-pool copy into a CoW clone, which would remove most of the cost. Confirm before implementation and record the answer here — the last unverified assumption in this file cost a redesign.

If the CoW cost turns out to matter for a real workload, the follow-up is *`zfs clone` plus instance registration*, designed then against a measured need, not now against a guess.

## Two snapshot registries — a finding against merged code

The daemon now creates snapshots two ways on the same dataset:

- **`incus snapshot <container> <name>`** — Incus-managed, recorded in Incus's database, used by `MoveContainer` (`containarium-move-sync0`, …).
- **`zfs snapshot <dataset>@<name>`** — what #1160a ships.

`zfscrypt.ListSnapshots` runs `zfs list -t snapshot -r <dataset>` **unfiltered**, so it returns every snapshot on that dataset regardless of origin. Two consequences follow, both against already-merged code:

1. `ListContainerSnapshots` will report Incus's internal snapshots — including a migration's sync snapshots while a move is in flight — as though a tenant had taken them.
2. `DeleteContainerSnapshot` will `zfs destroy` one, leaving Incus's database referencing a snapshot that no longer exists. During a migration that is a destroyed sync point.

**Not yet confirmed:** the exact name Incus gives its ZFS snapshots (likely a `snapshot-` prefix, unverified — nothing in the repo records it). That detail decides whether the fix is a prefix filter, an Incus-side listing, or reconciling the two registries. It is one lane test to establish, and it should be established before the fix is designed.

Filed separately rather than folded into #1160c: it is a defect in shipped code, not a clone decision.

## Test strategy

| Component | Tests |
|---|---|
| Snapshot RPCs (shipped) | Table-driven units over a fake `zfscrypt` runner: dataset resolution through the **tenant** pool, name validation, tenant authorization, scope gating, error mapping. Mutation-tested — six mutations applied, all caught |
| Rollback guards (shipped) | One test per refusal, each asserting the destructive command **did not run**; a guard that errors after rolling back is not a guard. Eight mutations, all caught |
| Encryption behaviour (shipped) | Incus lane, real pool: create/list/delete with the key genuinely unloaded via `PostStop`; rollback restores real file content and is refused when the key is unavailable |
| **Clone (#1160c)** | Unit: cross-tenant is unexpressible in the request shape; key-unavailable maps to `FailedPrecondition` naming custody; destination-name collision refused. **Lane, before implementation:** does a same-pool `incus copy` produce a CoW clone or a full copy, and does the result land in the tenant's encryptionroot? |
| **Two registries** | Lane: create an Incus instance snapshot, then assert what `ListContainerSnapshots` reports — the naming question above |

The clone row deliberately puts a lane test **before** the implementation. That ordering is what turned this revision from a plausible constraint into a disproved one.

## Suggested split

1. ~~**#1160a — snapshot lifecycle**~~ — **shipped** (#1380 / PR #1381).
2. ~~**#1160b — rollback**~~ — **shipped** (#1382 / PR #1383).
3. **#1160c — clone**, revised above: `incus copy` with a local destination, gated on the lane answering the CoW question first.
4. **New — the two-registry defect**, against merged code, gated on the naming question.

## Deviations from the default stack

**None.** Go, existing protos, no new deployable, no new dependency.

## Rejected alternatives

**`zfs clone` for the clone verb** — the mechanism #1160 proposes. It produces a dataset Incus does not know about: unbootable without re-implementing instance registration, invisible to quota accounting and the encryption placement record, and it pins its origin snapshot, importing a new failure mode into the shipped delete path. Rejected in favour of `incus copy`, which the daemon already uses for migration. Revisit only if a measured CoW need appears.

**Add to `VolumeService`** (as #1160 proposes) — two substrates, two capability gates, one service; every RPC would need to disambiguate its subject.

**Add to `BackupService`** — logical, portable, off-host backups are a different operation from physical, host-local snapshots; the naming similarity is all they share.

**A new `SnapshotService`** — the right answer the day a second substrate needs snapshotting. Today it is a service, its registration, its client and its CLI namespace for one consumer.

**Expose nothing; let operators use `zfs` directly** — the status quo that blocked #1202. A snapshot taken outside the daemon is invisible to quota accounting and to the encryption state the daemon reports.

## History

| Date | Author | Change |
|---|---|---|
| 2026-08-16 | drafted with Claude (`agent-c9aced4b`) | Initial draft, answering #1160's service-ownership question so #1202 could be unblocked. Status: proposed. |
| 2026-08-16 | revised with Claude (`agent-c9aced4b`) | Ownership **accepted** — implemented and merged (#1381, #1383); #1202 closed. **Clone section rewritten**: the lane (#1384) disproved this doc's premise that ZFS confines a clone to its origin's encryptionroot, so clone moves from `zfs clone` to `incus copy` and the cross-tenant refusal moves to the daemon. Added the two-snapshot-registry finding against merged code. Corrected the CLI namespace to `containarium snapshot`. |
