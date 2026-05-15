# Per-container ZFS native encryption — design

**Status:** Draft
**Last updated:** 2026-05-15
**Related:**
- [`docs/SECURITY-ENCRYPTION-AT-REST.md`](SECURITY-ENCRYPTION-AT-REST.md) — current encryption posture and pool-level encryption (shipped 2026-05-15 in [PR #177](https://github.com/FootprintAI/Containarium/pull/177))
- [`Containarium-cloud/prd/cloud/multi-tenancy.md`](https://github.com/FootprintAI/Containarium-cloud) — multi-tenancy PRD this depends on
- [`Containarium-cloud/prd/cloud/at-rest-encryption.md`](https://github.com/FootprintAI/Containarium-cloud) — cloud-product encryption plan this design supports

## Context

The OSS daemon currently supports **pool-level** ZFS native encryption (PR #177): operators set one keyfile at install time and every container dataset inherits the same key. That ships the right defense for single-tenant self-hosters but does nothing for the multi-tenant case — a co-tenant on the same host has the same kernel-mounted decrypted view of every other tenant's dataset as the host root user does.

**Per-container** (really, **per-tenant**) ZFS native encryption is the cloud-product feature where each org's container data is encrypted with a distinct key, and the key is only loaded into the kernel when that org's container is running. Co-tenants get ciphertext at rest *and* in the host root's view when their containers are stopped.

This doc designs that path. It is OSS-scope only where the OSS daemon's hooks need to exist; the actual key-custody policy lives in the cloud control plane.

## Goals / non-goals

**Goals**

- Each container's ZFS dataset is encrypted with a key derived from a **per-tenant** master key (not pool-wide).
- Keys are loaded into the kernel **only while the container is running**. Stopped → `zfs unload-key` → ciphertext at rest *and* in `zfs list`.
- The OSS daemon exposes the hooks (pre-create, pre-start, post-stop, pre-snapshot, pre-move) that the cloud control plane drives. OSS-only operators can plug their own key custody (file-based, HashiCorp Vault, gpg-encrypted blob, etc.) into the same hooks.
- Compatible with the existing `MoveContainer` flow: the destination daemon can decrypt the migrated dataset using the same per-tenant key.
- No performance regression for `monitoring=false` non-encrypted containers — encryption is opt-in per container (mirroring the OTel `--monitoring` shape).

**Non-goals (for v1)**

- Multi-tenancy in OSS. OSS stays single-tenant; per-container encryption only adds value when there are co-tenants to isolate from each other. This doc designs the daemon hooks; the multi-tenant control plane lives in `Containarium-cloud`.
- KMS provider lock-in. The daemon's hook interface accepts a key from the control plane and doesn't care whether it came from GCP KMS, AWS KMS, HashiCorp Vault, or a file on disk.
- In-place rekeying of an existing pool. ZFS supports `zfs change-key` but the operational complexity (snapshot interactions, partial-rekey failure modes) is out of scope for v1. v1 is create-time only.
- Memory / swap encryption. At-rest scope; kernel decryption necessarily exposes plaintext in RAM.
- Cross-VM key federation. Each VM's daemon needs the per-tenant key locally at container-start time. How the cloud control plane gets it there is the control plane's problem — see [Cloud control plane integration](#cloud-control-plane-integration).

## Architecture

```
┌────────────────── one Containarium VM (multi-tenant cloud build) ───────────────┐
│                                                                                 │
│   ┌───────────────────────────────────┐                                         │
│   │  Cloud control plane              │  ① CreateContainer(org_id=org-alice,    │
│   │  (out of OSS scope)               │     monitoring=…, …, encrypted=true)    │
│   │                                   │                                         │
│   │  org_id → KMS key URI             │                                         │
│   │  GCP KMS / AWS KMS / Vault        │                                         │
│   └────────────┬──────────────────────┘                                         │
│                │ ② KeyProvider.Wrap(org_id) →                                   │
│                ▼   32-byte key + key_ref (e.g. "kms://…/cryptoKeys/org-alice")  │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │ containarium daemon                                                     │  │
│   │                                                                         │  │
│   │   ┌──────────────────┐   ③ pre-create hook:                             │  │
│   │   │ KeyProvider      │      zfs create -o encryption=on \               │  │
│   │   │ interface        │            -o keyformat=raw \                     │  │
│   │   │ (pluggable)      │            -o keylocation=file:///dev/stdin \    │  │
│   │   └──────────────────┘            incus-pool/containers/alice           │  │
│   │                                                                         │  │
│   │   ④ pre-start hook: zfs load-key from in-memory cache                   │  │
│   │   ⑤ post-stop hook: zfs unload-key (best-effort)                        │  │
│   │   ⑥ pre-snapshot hook: ensure key loaded                                │  │
│   │   ⑦ pre-move hook: stamp key_ref onto migration metadata               │  │
│   │                                                                         │  │
│   │   In-memory key cache (process-lifetime only; TTL'd by inactivity).    │  │
│   │   Never written to disk. Lost on daemon restart → re-fetch from         │  │
│   │   KeyProvider on next pre-start.                                        │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   ZFS pool (incus-pool/containers/...)                                          │
│     alice  — encryptionroot=incus-pool/containers/alice (per-tenant key)       │
│     bob    — encryptionroot=incus-pool/containers/bob   (per-tenant key)       │
│     carol  — encryption=off                              (legacy, opt-out)     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

Each tenant's containers share one ZFS encryptionroot (the per-tenant key), so two containers belonging to the same org can share datasets without a separate `load-key` per container. Different orgs always have distinct encryptionroots.

## Detailed design

### 1. The `encrypted` per-container flag

Mirroring `--monitoring` (PR #175): the proto, CLI, and MCP all grow an `encrypted bool` field on `CreateContainerRequest`. Default off (matches the "platform doesn't move data unless told to" principle).

```proto
// Encrypt the container's ZFS dataset with the tenant-scoped key
// resolved by the control plane. Requires the daemon to be wired
// with a KeyProvider; without one, the request fails with
// FAILED_PRECONDITION rather than silently falling back to
// plaintext. Default false (no ZFS-layer encryption — relies on
// pool / PD encryption only).
bool encrypted = N;
```

CLI: `containarium create alice --encrypted`.

### 2. The `KeyProvider` interface

```go
type KeyProvider interface {
    // Wrap resolves the per-tenant key material at create time.
    // The returned KeyRef is durable and stored on the container's
    // metadata so future Load calls can re-fetch the same key (e.g.
    // after daemon restart, or on an adopt-migration destination).
    Wrap(ctx context.Context, tenantID string) (key []byte, ref KeyRef, err error)

    // Load re-fetches the key bytes given a previously-stored ref.
    // Used on container start and on cross-VM adopt.
    Load(ctx context.Context, ref KeyRef) (key []byte, err error)
}

type KeyRef struct {
    Scheme   string // "kms", "vault", "file", "noop"
    URI      string // "projects/.../cryptoKeys/org-alice", "/etc/containarium/keys/alice", …
    Metadata map[string]string
}
```

**Default OSS implementation** is `FileKeyProvider`: tenant ID maps to a file path under a configurable root (`--zfs-keys-dir`, default `/etc/containarium/keys/`). Operators dropping files in there get OSS-scope per-tenant encryption with the trade-offs they already accept for `--zfs-encryption-keyfile`.

**Cloud implementations** live in `Containarium-cloud`: `GCPKMSKeyProvider`, `VaultKeyProvider`, etc. Selected via daemon flag `--key-provider=kms` and a provider-specific config block.

### 3. Hook points in the daemon

The daemon's container lifecycle already has well-defined entry points; we add five new hook calls:

| Hook | Where in code | What it does |
|---|---|---|
| `pre-create` | `pkg/core/container/manager.go` `Create()` before `incus launch` | Resolves the per-tenant key via `KeyProvider.Wrap`, pre-creates the ZFS dataset with `encryption=on`, then tells Incus to use that pre-existing dataset (Incus's "instance from an existing zvol" path). |
| `pre-start` | `internal/server/container_server.go` `StartContainer` | Reads the stored `KeyRef` from container metadata, calls `KeyProvider.Load`, pipes the key to `zfs load-key`. No-op if key already loaded. |
| `post-stop` | `internal/server/container_server.go` `StopContainer` | Best-effort `zfs unload-key` after the LXC stops. Tolerates "key still in use" if other containers under the same encryptionroot are still running. |
| `pre-snapshot` | `pkg/core/incus/client.go` snapshot path | Ensures the key is loaded so the snapshot's metadata is readable (ZFS allows snapshots without the key loaded but inspection requires it). |
| `pre-move` | `internal/server/container_server.go` `MoveContainer` → `AdoptMigratedContainer` | Source stamps `KeyRef` onto the migration metadata. Destination's adopt handler calls `KeyProvider.Load(ref)` with the destination daemon's same provider config — the assumption is the control plane configures both daemons with KeyProviders that can resolve the same `KeyRef`. Cross-cloud-provider migrations would need a re-wrap step, deferred. |

### 4. The "key in memory, never on disk" rule

The daemon caches loaded keys in process memory only (a `sync.Map[tenantID]keyBytes`), with TTL eviction on container stop. On daemon restart, the cache is empty; the next `pre-start` re-fetches from `KeyProvider.Load`.

Why not persist the cache? Two reasons:

- Operators expect that "wipe the daemon" wipes the keys. A disk cache violates that.
- Container restarts are infrequent enough that re-fetching from KMS/Vault on each start is cheap (single-digit ms). The cache only matters for "stop then start" cycles within one daemon lifetime.

### 5. Failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| KeyProvider down at container-create time | `CreateContainer` returns `Unavailable`. No dataset created, no partial state. | Operator retries; control plane surfaces the KMS error. |
| KeyProvider down at container-start time | `StartContainer` fails with `FailedPrecondition`. LXC stays stopped. | Container is unreadable until KMS recovers — by design. |
| Daemon restart mid-container-run | Kernel keeps the key in-memory through ZFS until reboot. Container keeps running. On next start, daemon re-fetches via `KeyProvider.Load`. | Kernel-resident key survives daemon crashes — desirable for liveness. |
| Host reboot | All keys unloaded by ZFS. Next `daemon start` does NOT auto-load (no on-disk cache); each container's start triggers a fresh `KeyProvider.Load`. | Auto-restart of containers waits for KMS reachability — surfaced via container state `WAITING_FOR_KEY`. |
| Cross-VM migration: destination's KeyProvider can't resolve source's KeyRef | `AdoptMigratedContainer` fails before starting the LXC. Source's container shell still exists at destination but is unstartable. | Pre-flight check at `MoveContainer` time: source asks destination "can you resolve this ref?" before initiating the copy. |
| Operator removes a tenant from the control plane while their container runs | Container keeps running (key in kernel). Next start fails. | Documented as expected — eviction is "stop the containers, then revoke." |
| Snapshot exists but tenant deleted | Snapshot is ciphertext forever. | Cloud product can backup-export snapshots before tenant deletion (Q2 2027). |

### 6. Backwards compatibility

The flag defaults off, so existing containers keep their current encryption posture (pool-level only or none at all). The hook interface is no-op-default: when `KeyProvider` is nil, `pre-create`/`pre-start`/etc. all skip.

Pool-level encryption (PR #177) and per-container encryption coexist: pool-level provides a baseline for *all* datasets (defense-in-depth); per-container's `encryptionroot` overrides pool-level for that tenant's tree. The cloud product will likely use both layers (pool-level CMEK + per-tenant KMS).

## Cloud control plane integration

The cloud control plane is responsible for:

- Mapping `org_id` → KMS key URI in its tenancy database.
- Configuring each daemon with the right `--key-provider` flag and provider-specific credentials (e.g. a GCP service account with `roles/cloudkms.cryptoKeyEncrypterDecrypter`).
- Pre-flighting cross-VM migrations (destination's KeyProvider must be able to resolve the source's KeyRef).
- Surfacing KMS errors to operators (not to tenants — KMS health is platform-owned).

None of this lives in OSS. OSS ships only:

- The `encrypted` flag on the proto / CLI / MCP.
- The `KeyProvider` interface.
- The `FileKeyProvider` reference impl.
- The five lifecycle hooks.

## Open questions

| # | Question | Why it matters | Proposed answer |
|---|---|---|---|
| 1 | Where does the daemon get the `tenantID` for the `KeyProvider.Wrap` call? | Multi-tenancy isn't in OSS proto. Cloud-only would add `tenant_id` to the proto, OSS would default to `"default"`. | Add `tenant_id string` to `CreateContainerRequest` proto. OSS daemon validates `tenant_id == ""` or `tenant_id == "default"` and rejects other values until multi-tenancy lands. Cloud daemon accepts any non-empty `tenant_id`. |
| 2 | What happens to a `monitoring=true encrypted=true` container's OTel? | OTel metrics ship from inside the container — out of scope for at-rest encryption, but the collector receives plaintext over the network from a "private" tenant. | Acceptable: OTel signals are tenant-scoped metadata (CPU, error counts), not the encrypted data itself. Document it. |
| 3 | Should `pre-snapshot` block on KMS reachability, or skip if KMS is down? | ZFS allows snapshots without the key loaded, but inspecting requires it. | Allow the snapshot creation, surface a `KEY_UNAVAILABLE` warning on the container's status. Reading the snapshot later fails predictably. |
| 4 | Cross-cloud-provider migration (GCP → AWS) needs a re-wrap step. | An AWS-side KeyProvider can't resolve a `kms://projects/.../...` ref. | Out of scope for v1. Document. Future work: a "rewrap" RPC on the source that produces a destination-provider-flavored KeyRef before MoveContainer kicks off. |
| 5 | Key rotation cadence — daemon-driven, or control-plane-driven? | KMS keys typically auto-rotate (GCP KMS: 90d); the daemon needs to either re-wrap container datasets on rotation or live with ciphertext-under-old-key. | Control-plane-driven. The cloud product schedules per-tenant rotation maintenance windows, stops containers, calls a new `RewrapContainer` RPC the daemon exposes, restarts containers. OSS doesn't need this in v1. |

## Phased rollout

| Phase | Scope | OSS/cloud | Effort |
|---|---|---|---|
| **0. RFC accepted** | this doc + decisions on the 5 open questions | OSS doc | (you) |
| **1. `KeyProvider` interface + FileKeyProvider** | go interface, file-based impl, unit tests | OSS | ~½ day |
| **2. Proto + CLI + MCP flag** | `encrypted` field, `tenant_id` field, plumbing | OSS | ~½ day |
| **3. Pre-create + pre-start hooks** | dataset creation with `encryption=on`, load-key on start | OSS | ~1 day |
| **4. Post-stop + pre-snapshot hooks** | unload-key + ensure-key-loaded | OSS | ~½ day |
| **5. MoveContainer integration** | KeyRef in migration metadata, destination key resolution, pre-flight check | OSS | ~1 day |
| **6. RewrapContainer RPC (rotation)** | stop / change-key / start flow | OSS | ~1 day |
| **7. `GCPKMSKeyProvider`** | KMS-backed implementation, IAM docs | cloud | ~1 day |
| **8. Control-plane wiring** | tenant DB → daemon config, rotation scheduler | cloud | ~3 days |
| **9. Tests** | unit + integration: encrypted lifecycle, KMS down, restart-while-encrypted, migration | both | ~2 days |

**Total: ~5 days OSS, ~5 days cloud.** Phases 1–6 (OSS) can land independently of the cloud control plane and still be useful for self-hosters who write their own KeyProvider plugin.

## History

| Date | Author | Change |
|---|---|---|
| 2026-05-15 | hsinhoyeh, drafted with Claude | Initial draft. Per-tenant ZFS native encryption design with pluggable KeyProvider, five lifecycle hooks, in-memory key cache, MoveContainer integration. Status: Draft. |
