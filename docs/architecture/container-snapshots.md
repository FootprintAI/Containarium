# Design: container snapshots — which service owns them

**Date:** 2026-08-16
**Status:** proposed
**Decides:** the open question on #1160, which blocks two of #1202's three criteria
**Stack:** Go only — no new language, no new deployable, no new dependency

## Problem

There is **no snapshot primitive exposed anywhere**. `grep -rn 'rpc.*Snapshot' proto/containarium/v1/` returns nothing.

The ZFS layer beneath one has existed and been tested against a real pool for some time — `zfscrypt` has `Snapshot`, `ListSnapshots`, `DestroySnapshot`, `RollbackToSnapshot`, `SnapshotUsage` and `EnsureInspectable`, all exercised on the `zfs-encryption` lane. What is missing is everything above it.

That gap blocks work: **#1202's AC2 and AC3 name snapshot behaviour that cannot be implemented against a surface that does not exist**, and #1202 is a sprint issue (#1333). #1160 proposes filling the gap by adding the RPCs to `VolumeService`.

**Before any of it is written, one question needs an answer: which service owns container snapshots?** Answering it inside a feature PR would settle an architecture decision by implementation, quietly.

## Decision

**`ContainerService`.**

A container snapshot's subject is a container. The caller holds a username; the dataset is an implementation detail the daemon already resolves for itself (`incus.ContainerDataset`). Three things follow, and together they decide it:

1. **Authorization is already correct there.** Every `ContainerService` RPC runs `AuthorizeTenant(ctx, req.Username)`. A snapshot is tenant-scoped in exactly the same way. On `VolumeService` the subject is a shared volume that several tenants attach, so the tenant check means something different.
2. **The encryption interactions live there.** #1202 is about snapshot behaviour *under encryption* — whether the key is loaded, what `EnsureInspectable` reports. `encryptionHooks` is a `ContainerServer` field. Putting the RPCs elsewhere means a second server reaching into that state.
3. **It needs no new service to exist.** A `SnapshotService` would be justified by a second consumer; there is exactly one today.

### What this is not

**Not `VolumeService`.** That service is **CephFS shared multi-writer volumes** (#384). `volume.Manager` shells out to `incus storage volume`, and the service is capability-gated on a CephFS pool being present — `ListVolumes` even reports `shared_volumes_supported` for the backend. Adding ZFS container-dataset snapshots there produces a service spanning two substrates with two different capability gates, where a host with no CephFS has half a service working and half not, and every RPC must disambiguate *which kind of thing am I snapshotting*.

**Not `BackupService`**, despite the name. That is **logical database backup** — `pg_dump`-shaped, into GCS, with `RestoreBackup` loading into a *different* target container. It leaves the host and is portable across them. A ZFS snapshot is physical, host-local, instantaneous, and is the substrate under rollback and clone. The two answer different questions ("can I get this data somewhere else?" vs "can I return this container to how it was ten minutes ago?"), and conflating them would make `RestoreBackup` and `RollbackToSnapshot` look like variants of one operation when their failure modes share nothing.

**Not both.** If CephFS volume snapshots are wanted later they belong on `VolumeService`, over the same `zfscrypt`-shaped primitive underneath. Two thin surfaces over one shared layer beats one surface spanning two substrates.

## Contracts

Added to `ContainerService`, all tenant-scoped, all over the existing grpc-gateway REST mapping:

| RPC | HTTP | Notes |
|---|---|---|
| `CreateContainerSnapshot` | `POST /v1/containers/{username}/snapshots` | Succeeds with the key unloaded — see below |
| `ListContainerSnapshots` | `GET /v1/containers/{username}/snapshots` | Carries per-snapshot space usage |
| `DeleteContainerSnapshot` | `DELETE /v1/containers/{username}/snapshots/{name}` | Also works with the key unloaded |
| `RollbackContainerSnapshot` | `POST /v1/containers/{username}/snapshots/{name}/rollback` | Destructive; refuses a running container unless forced |

Every one gets a `containarium container snapshot ...` CLI verb in the same PR that adds it. An RPC with no CLI counterpart is this repo's documented anti-pattern (CLAUDE.md, "CLI-first, MCP wraps it"), and the MCP tool then wraps the same function for free.

**Space usage is not optional.** #1160's third criterion exists because a forgotten snapshot silently pins disk; `SnapshotUsage` already reports it, so `ListContainerSnapshots` carries it rather than making an operator shell out to `zfs list -t snapshot`.

## The encryption interaction, which is the whole of #1202

Resolved decision #3 of the encryption design says snapshot creation is **allowed** when the key is unavailable, and inspection fails predictably. That asymmetry is deliberate: blocking creation on key-custody reachability would let a transient outage suppress the backup window. It is also already true of ZFS and proven on the lane (`TestIntegration_SnapshotsWorkWithTheKeyUnloaded`).

What the API must add on top:

- **Create and delete succeed with the key unloaded.** No key check on those paths.
- **Inspection fails with a specific error, not an opaque ZFS one.** `EnsureInspectable` exists for this; the RPC maps its failure to `FailedPrecondition` naming key custody, so a caller can tell "your key is not loaded" from "that snapshot does not exist".
- **The container's `encryption_state` already reports `KEY_UNAVAILABLE`** (#1202 AC1, merged). A caller listing snapshots on such a container has the explanation on the container itself.

With those three, #1202's AC2 and AC3 are satisfiable.

## Test strategy

| Component | Tests |
|---|---|
| `ContainerServer` snapshot RPCs | Table-driven unit tests over a fake `zfscrypt` runner: name validation, tenant authorization, the rollback refusal, and the error mapping for an unloadable key |
| Rollback guard | `TestRollbackContainerSnapshot_RefusesARunningContainerUnlessForced` — the destructive path, so the refusal is asserted rather than assumed |
| Encryption behaviour | On the **`zfs-encryption` lane**, against a real pool: create and delete a snapshot with the key unloaded, then confirm inspection fails with the mapped error. A fake cannot answer whether ZFS permits the operation |
| Space usage | Real pool: write, snapshot, delete the data, and assert the snapshot still reports non-zero usage — the property that makes a forgotten snapshot expensive |

Nothing here needs a real Incus, so the existing ZFS lane covers it; the Incus lane is not extended.

## Suggested split

Three PRs, each with its RPC, CLI verb and tests:

1. **#1160a — snapshot lifecycle** (create / list+usage / delete). Closes #1160's ACs 1, 3, 4 and **unblocks #1202's AC2 and AC3**, which is why it goes first.
2. **#1160b — rollback.** #1160's AC2. Destructive, so it earns its own review.
3. **#1160c — clone.** Needs a `zfscrypt` clone primitive that does not exist, and carries a real constraint: a ZFS clone must stay within its origin's encryptionroot, so a clone across tenants is not expressible. Worth confirming on the lane before designing the API.

## Deviations from the default stack

**None.** Go, existing protos, no new deployable, no new dependency.

## Rejected alternatives

**Add to `VolumeService`** (as #1160 proposes) — two substrates, two capability gates, one service; every RPC would need to disambiguate its subject. Rejected above.

**Add to `BackupService`** — logical, portable, off-host backups are a different operation from physical, host-local snapshots, and the naming similarity is the only thing they share.

**A new `SnapshotService`** — the cleanest separation, and the right answer the day a second substrate needs snapshotting. Today it would be a service, its registration, its client and its CLI namespace, all for one consumer. Reconsider when CephFS volume snapshots are actually wanted.

**Expose nothing; let operators use `zfs` directly** — the status quo. Rejected because it is what blocks #1202, and because a snapshot taken outside the daemon is invisible to quota accounting and to the encryption state the daemon reports.

## History

| Date | Author | Change |
|---|---|---|
| 2026-08-16 | drafted with Claude (`agent-c9aced4b`) | Initial draft, answering #1160's service-ownership question so #1202 can be unblocked. Status: proposed. |
