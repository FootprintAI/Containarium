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

**Not `BackupService`**, despite the name. `BackupService` answers "can I get this data somewhere else?": a durable, off-host copy, restorable into a *different* container. A ZFS snapshot answers "can I return this container to how it was ten minutes ago?": physical, host-local and instantaneous. Snapshot RPCs stay on `ContainerService`.

*Amended 2026-10-25 (#2800).* This paragraph used to describe `BackupService` as database-only. It now has two scopes: `DATABASE` (logical dump, `pg_dump` or a tenant hook) and `BOX` (the whole box, off-host). A BOX backup is the one place where the two meet: per the decision on #2801 it **takes** a snapshot as its consistent source, then copies it off-host. That reuse goes in one direction only. `BackupService` consumes the snapshot primitive, and snapshots do not move into `BackupService`. The split is still "where does the copy live?", not "how much of the box?". See [Whole-box backups](#whole-box-backups-backup_scope_box) below.

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

## Whole-box backups (`BACKUP_SCOPE_BOX`)

Slice 1 of #2372 (#2800) adds the contract. The data path is #2801, and verify-by-restore is #2802.

**Contract.** `CreateBackupRequest.scope` and `BackupRecord.scope` (`BackupScope`: `UNSPECIFIED` = `DATABASE`, `DATABASE`, `BOX`), both additive field numbers. The box is the request's `username`, the box `<username>-container`, so `AuthorizeTenant` keys on it as it does for every other backup. A BOX request is refused with `INVALID_ARGUMENT` when it sets `connection` (even an empty one), `hook` or `hook_format`, or names no `key_mode`. A valid BOX request runs the create path below (#2801 PR B). It runs no command inside the box.

**Decision: reuse the destination and the encryption.** A BOX backup uses `BackupDestination` (LOCAL / GCS, with `gcs_bucket`) and `BackupKeyMode` (the #2402 key-wrap seam: MANAGED KMS envelope, AGE_RECIPIENT, or BOTH) unchanged. There is no second destination or key machinery to keep in step. One difference is deliberate: **plaintext is forbidden for BOX** (decision of 2026-10-25). A database request may leave `key_mode` unset and take the daemon default, which can be plaintext. A BOX request must name the mode, and the daemon then checks it can honour it: MANAGED or BOTH without a key wrapper is `FAILED_PRECONDITION`, and AGE_RECIPIENT or BOTH without a recipient is `INVALID_ARGUMENT`.

| A BOX backup includes | A BOX backup excludes |
|---|---|
| The box's root filesystem | `/tmp`, `/var/tmp`, `/var/cache`, `/run` |
| Volumes attached to the box | Snapshot history (earlier ZFS / Incus snapshots of the box) |
| Container config and device metadata, in a manifest inside the encrypted backup (#2801) | Anything outside the box: host state, other tenants' boxes |

The size cap (256 GiB by default for BOX, configurable per daemon, with a pre-flight free-space check) and the file-digest manifest are #2801's. Verification against that manifest is #2802's.

**Overlap with #1157.** #1157 proposes replacing `CreateBackupRequest.connection` with an engine `oneof`. This slice does not touch `connection`. It adds `scope` alongside it, so either #1157 option still applies, and BOX simply requires the connection, whatever its shape, to be absent.

### Whole-box export (#2801, PR A)

**The seam.** `incus.Backend.ExportInstance(name) (io.ReadCloser, error)` and `ImportInstance(name, pool, r, ImportOptions)`. Both use the Incus Go client's instance-backup API and stream through an `io.Pipe`. The daemon writes no temp file of its own. A BOX record carries `BACKUP_ENGINE_BOX`.
- The export is **non-optimized**: a portable tarball, not a `zfs send` stream, so it restores onto any pool driver.
- It is **instance-only**, so snapshot history is excluded.
- It does not set root-only, so attached volumes are kept.
- The import requires a name, so Incus never takes the archived one (possibly the original box's). The imported box is left stopped.

**Two server paths.** A server with the `direct_backup` API extension streams the tarball as it produces it. The Incus 6.0 LTS package that Ubuntu 24.04 ships (and the lane runs) does not have that extension. There, the export creates a stored backup in Incus's own backups directory (`/var/lib/incus/backups` on a default install), with a 6-hour expiry in case the daemon dies mid-export. The export streams that backup and deletes it when the reader is closed. On 6.0 LTS, Incus stages one full compressed copy of the box on the host before the first byte arrives. The free-space pre-flight for the 256 GiB BOX cap has to count that staging area as well as our own.

**Is a live export consistent? Yes, on ZFS: it is point-in-time.** For a non-optimized backup of a filesystem volume, the Incus ZFS driver (`BackupVolume` in `driver_zfs_volumes.go`) takes a temporary read-only snapshot and reads the tarball from it. The source comment says this is "to ensure the backup taken is consistent". The lane observed it: while a RUNNING box was exported, a `<dataset>@temp_ro-<uuid>` snapshot appeared on the box's dataset. No snapshot was left afterwards, and the test asserts that. "Point-in-time" means crash-consistent: what a power cut would leave on disk. Application-level quiescing (flushing a database inside the box) is not part of it. The snapshot-then-copy decision of 2026-10-20 is therefore met by Incus itself; the daemon does not need its own snapshot step on ZFS.

**What the tarball contains** (lane, Incus 6.0.0, base Ubuntu 24.04 box: 189 MB gzip, exported in about 60 s):

| Entry | What it is |
|---|---|
| `backup/index.yaml` | Incus's backup index (name, backend, pool, snapshot list, which is empty with instance-only) |
| `backup/container/backup.yaml` | The instance's config and devices, plus its pool and volume definitions. Incus needs it to import |
| `backup/container/metadata.yaml`, `templates/` | The image metadata and templates the instance was created from |
| `backup/container/rootfs/...` | The root filesystem as read from the snapshot |

The compression is the server default (gzip unless the host sets `backups.compression_algorithm`).

**Excludes: Incus has none, so the daemon has to apply them.** The lane found probe files under `/tmp`, `/var/tmp` and `/var/cache` in the tarball (`rootfs/tmp/...` and so on). `/run` was not in it: inside a running box `/run` is a tmpfs mount, which a dataset snapshot cannot see, so it is excluded for free. Incus's backup API has no per-path exclude. The remaining excludes therefore have to be applied to the stream. The default for PR B (not decided here) is a streaming tar filter between `ExportInstance` and encryption:
- drop the *contents* of `backup/container/rootfs/{tmp,var/tmp,var/cache}/`;
- keep the directory entries themselves, so the restored box still has those directories with their modes;
- re-emit everything else unchanged.

The filter has to decompress and recompress the stream. The alternative, deleting the files inside the box before the export, would modify a tenant's running box and is rejected. The config and device manifest decided on #2800 can be taken from `backup.yaml`, which is already in the stream.

### Whole-box create (#2801, PR B)

`containarium backup create <username> --box --key-mode <mode>` sends a BOX-scope `CreateBackup`. The daemon calls `backup.Manager.CreateBox`, and `container.Manager` provides `BoxOps`: `ExportInstance` (the PR A seam) and `BoxDiskUsage` (the root disk usage from the instance's metrics).

**Order of operations.** Every refusal comes before the export starts and leaves nothing in the backup directory.
1. Validate. A key mode must be named, because plaintext is refused in the core as well as at the API. Then check the recipient, the key mode against the daemon's wrapper, and the destination. Derive the id `<username>-box-<UTC timestamp>`. A record with that id must not exist yet: two creates in one second fail instead of overwriting.
2. **Free-space pre-flight.** The box's disk usage is the estimate. Our staging (the backup directory) needs `min(usage, cap)`. Each Incus staging directory that exists needs `usage`; on 6.0 LTS Incus stages a compressed copy there before the stream starts. The default is `/var/lib/incus/backups`, overridable with `CONTAINARIUM_INCUS_BACKUPS_DIR`, and a missing directory is logged and not counted. Two directories on one filesystem (same device) are summed. Compressed sizes are not known up front, so the check is conservative. It fails with `ErrInsufficientSpace` (`RESOURCE_EXHAUSTED`). An unknown usage (zero, or a metrics error) also fails it: the pre-flight cannot pass without a figure.
3. Wrap the managed identity if the mode needs one. This is the database path's code, shared.
4. **Stream:** `ExportInstance` → gzip reader → tar filter → gzip writer (BestSpeed) → `io.Pipe` → age encryption → bounded writer → staging file plus SHA-256. The BOX cap, 256 GiB by default and set with `CONTAINARIUM_BACKUP_BOX_MAX_BYTES`, bounds the stored ciphertext and the uncompressed stream, as `maxDumpBytes` does for a dump. It is one limit with two uses: a box over 256 GiB of uncompressed content is refused even if its archive would be smaller. The second bound matters because a box of zeros or a sparse file compresses to almost nothing. Each entry is copied with `io.CopyN` up to its header size, and only zero padding (at most 1 MiB) may follow the tar end marker. A bad value stops the daemon at startup. Going over the cap is `ErrDumpTooLarge` (`RESOURCE_EXHAUSTED`).
5. Commit to LOCAL or GCS, sidecar included, with the database path's code. The object is `<id>.box.tar.gz.age`.

**The filter.**
- It drops entries under `backup/container/rootfs/{tmp,var/tmp,var/cache,run}/` and keeps the directory entries themselves.
- A hard link *inside* an excluded directory is dropped.
- A hard link at a kept path whose target is excluded keeps its content. In a tar the first name carries the content and later names are links, so when the excluded name comes first (as `/tmp` or `/run` do against `/usr` or `/var/lib`), dropping the link would lose the file.
  - The filter sets the content of every dropped regular file aside in a spill file in the backup directory. Each file is its own age segment, encrypted to an identity that exists only in memory for that one backup, so the host still holds ciphertext only.
  - The first kept name is re-emitted as a regular file from the spill and listed in the manifest's `files`. Later kept names link to it and are listed in `links`.
  - The spill is deleted when the filter returns. It holds at most the excluded content, which is part of the disk usage the pre-flight counts.
- Every other entry is re-emitted with its header, so modes, owners, symlinks and PAX xattrs (file capabilities) survive.
- An export that is not gzip is refused. Incus uses gzip unless the host sets `backups.compression_algorithm`.
- So is an export that already has an entry at the manifest path.
- A truncated stream, including a bad gzip trailer, fails the backup and never produces a short one.

**The manifest** is `backup/containarium-manifest.json`, the archive's last entry, inside the encryption.
- `files` holds the path, size and SHA-256 of every kept regular file in the rootfs.
- `links` holds the rootfs hard links.
- `config` holds the digests of the files outside the rootfs (`index.yaml`, and `backup.yaml`, which carries the box's config and devices).
- It also records the box name, the time and the excluded directories, and has a format version.

The digests are taken from the bytes as they stream, not in a second pass. The manifest stays in memory until the end, so memory grows with the number of files (about a hundred bytes each) and never with their size. The lane (`TestIntegrationIncusBoxBackup`) showed Incus 6.0.0 importing the filtered archive with the manifest entry still in it. The restore (PR C) may strip the entry anyway.

**BOX records on the database paths.** `Restore` and `Verify` refuse an `EngineBox` record before touching any container. Without that guard, a tarball would be handed to `pg_restore`.

## Test strategy

| Component | Tests |
|---|---|
| Snapshot RPCs (shipped) | Table-driven units over a fake `zfscrypt` runner: dataset resolution through the **tenant** pool, name validation, tenant authorization, scope gating, error mapping. Mutation-tested — six mutations applied, all caught |
| Rollback guards (shipped) | One test per refusal, each asserting the destructive command **did not run**; a guard that errors after rolling back is not a guard. Eight mutations, all caught |
| Encryption behaviour (shipped) | Incus lane, real pool: create/list/delete with the key genuinely unloaded via `PostStop`; rollback restores real file content and is refused when the key is unavailable |
| **Clone (#1160c)** | Unit: cross-tenant is unexpressible in the request shape; key-unavailable maps to `FailedPrecondition` naming custody; destination-name collision refused. **Lane, before implementation:** does a same-pool `incus copy` produce a CoW clone or a full copy, and does the result land in the tenant's encryptionroot? |
| **Two registries** | Lane: create an Incus instance snapshot, then assert what `ListContainerSnapshots` reports — the naming question above |
| Whole-box export seam (#2801 PR A) | Unit: both export paths and the import against a fake Incus server, plus the `incustest` mock's round trip (`TestExportImportRoundTripMock`); twelve mutations, all caught. Lane: `TestIntegrationIncusExportImport` exports a RUNNING ZFS-backed box, deletes it, imports it under a new name, compares file digests, and records the snapshot and tarball findings above |
| Whole-box create (#2801 PR B) | Unit: the filter (excludes, kept directory entries, look-alike paths, `./` names, hard links into an excluded dir, xattrs), the manifest (digests, links, config, last entry), refusals before the export (plaintext, key mode, destination, id, missing export, unknown size, free space), the same-filesystem sum, the cap, broken exports (truncated, bad trailer, stream error, not gzip, forged manifest), managed mode, GCS, no overwrite, restore and verify refusing a BOX record, and a 128 MiB incompressible box streamed with live heap under 48 MiB. Server: a BOX create returns a BOX record and runs no exec; error mapping; env parsing. CLI: `--box` request shape and flag refusals. Lane: `TestIntegrationIncusBoxBackup` backs up a RUNNING ZFS box through `CreateBox`, decrypts the result, checks the excludes and manifest digests, imports the filtered archive and compares files |

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

**Add to `BackupService`**: portable, off-host backups are a different operation from physical, host-local snapshots. A BOX backup (#2800) *uses* a snapshot as its source but does not expose snapshot RPCs, so this stays rejected.

**A new `SnapshotService`** — the right answer the day a second substrate needs snapshotting. Today it is a service, its registration, its client and its CLI namespace for one consumer.

**Expose nothing; let operators use `zfs` directly** — the status quo that blocked #1202. A snapshot taken outside the daemon is invisible to quota accounting and to the encryption state the daemon reports.

## History

| Date | Author | Change |
|---|---|---|
| 2026-08-16 | drafted with Claude (`agent-c9aced4b`) | Initial draft, answering #1160's service-ownership question so #1202 could be unblocked. Status: proposed. |
| 2026-08-16 | revised with Claude (`agent-c9aced4b`) | Ownership **accepted** — implemented and merged (#1381, #1383); #1202 closed. **Clone section rewritten**: the lane (#1384) disproved this doc's premise that ZFS confines a clone to its origin's encryptionroot, so clone moves from `zfs clone` to `incus copy` and the cross-tenant refusal moves to the daemon. Added the two-snapshot-registry finding against merged code. Corrected the CLI namespace to `containarium snapshot`. |
| 2026-10-25 | revised with Claude (`agent-48362e6a`) | #2800: `BackupService` is no longer database-only. Amended "Not `BackupService`" and added the whole-box section: the `BackupScope` contract, destination and key-mode reuse, plaintext forbidden for BOX, and what a BOX backup includes and excludes. |
| 2026-10-26 | revised with Claude (`agent-332dbdd5`) | #2801 PR A: added "Whole-box export". It covers the streamed export/import seam and the two server paths (`direct_backup` or a stored backup on Incus 6.0 LTS). It records the lane's findings that a live ZFS export is point-in-time (Incus takes a temporary read-only snapshot) and what the tarball contains, and why the excludes must be applied as a stream filter. |
| 2026-10-26 | revised with Claude (`agent-a881ffc8`) | #2801 PR B: added "Whole-box create". It covers the create path's order of operations, the free-space pre-flight (same-filesystem sum, Incus staging dir), the BOX cap and its setting, the stream filter, the manifest format, and the database restore and verify refusing BOX records. |
