# Image Digest Verification — Design Note

> Phase 3.1 deeper half (audit B-HIGH-1). Operator-enforced
> digest pinning landed earlier (`CONTAINARIUM_REQUIRE_IMAGE_DIGEST`
> in [`internal/server/image_digest.go`](../../internal/server/image_digest.go));
> this note designs the registry-side verification pass.

## Where we are today

`CreateContainer` does three image checks at the API
boundary, in order:

1. **Allowlist** — registry prefix must match
   `CONTAINARIUM_ALLOWED_IMAGE_REGISTRIES` if set. Catches
   "wrong registry" mistakes.
2. **Digest syntax** — when `CONTAINARIUM_REQUIRE_IMAGE_DIGEST=true`,
   the image reference must end with `@sha256:<64-lowercase-hex>`.
   Catches "no digest pinned" misconfigurations.
3. **No further verification.** The string is handed to
   Incus, which fetches the image from its configured
   simplestreams remote. **Whatever Incus pulls, we
   accept.**

That's enough to block accidental drift (an operator
forgetting to write a digest, a typo in the registry
host), but it does NOT defend against the actual supply-
chain threat: a compromised mirror that serves a
different image for the same `@sha256:` reference.

The reason: Incus's simplestreams remote keys images by
its own fingerprint (the SHA-256 of the unified rootfs
tarball as published by the remote). The `@sha256:<hex>`
operator-enforced syntax is treated by Incus as part of
the alias name — the digest is parsed, not verified, and
the create call goes ahead even if the remote serves a
different image.

## Threat model

| Threat                                                | Mitigated today? |
| ----------------------------------------------------- | ---------------- |
| Operator forgets to pin a digest                      | Yes (Phase 1 + 2) |
| Operator points at an attacker-controlled registry    | Yes (allowlist)  |
| Allowlisted registry MITM (TLS terminator compromise) | **No**           |
| Allowlisted registry account compromise (key leak)    | **No**           |
| Registry serves different bytes for the same digest   | **No**           |

The last three rows are the deeper half: an attacker who
controls (or has 'man-in-the-middled') a registry the
operator already trusts can publish bytes that *don't*
match the declared digest, and today we'd happily run
them.

## Goal

After `CreateContainer` finishes, the running container
MUST be cryptographically equivalent to the image whose
SHA-256 the operator named. Differently put: the SHA-256
of the rootfs Incus has on disk must equal the operator-
supplied digest, full stop.

## What Incus exposes

Incus's local image store is keyed by **fingerprint** —
the SHA-256 of the canonical exported form of the image
(rootfs squashfs + metadata.yaml + templates archive). The
HTTP API exposes:

```
GET /1.0/images/<fingerprint>
GET /1.0/images?recursion=1
```

Both return image metadata including the canonical
fingerprint. After a simplestreams pull, the image is
cached locally under its fingerprint, and we can read it
back from the local store without touching the remote
again.

The simplestreams remote also publishes the fingerprint
in its index JSON (`streams/v1/images.json`), keyed by
product + version + architecture. Operators (and we) can
fetch this index over HTTPS independent of Incus's pull
machinery.

## Proposed architecture

Verify **before** the pull, using the simplestreams index
as the source of truth:

```
   ┌─ CreateContainer (proto-first) ────────────────────┐
   │                                                    │
   │  1. allowlist check         (existing)             │
   │  2. digest syntax check     (existing)             │
   │  3. simplestreams resolve   (NEW — Phase deeper)   │
   │     ├── fetch streams/v1/images.json over HTTPS    │
   │     ├── find entry matching (product, version,     │
   │     │   architecture) from the image alias         │
   │     ├── read its `sha256` field                    │
   │     └── if != operator-supplied digest → REJECT    │
   │  4. handoff to Incus client (existing)             │
   │                                                    │
   └────────────────────────────────────────────────────┘
```

Reasons to verify before, not after, the pull:

- **No state cleanup on mismatch.** If the verifier runs
  post-pull, a rejected create has to roll back the
  partial container; that's a second failure mode to
  handle. Pre-pull check fails fast at the API boundary.
- **Bandwidth.** Multi-GB images don't need to land on
  disk just to be rejected.
- **Operator legibility.** Rejection message can name
  *both* the requested digest and the index-reported
  digest, making the discrepancy obvious.

The post-pull check is still worth doing as
defense-in-depth (the local store could be tampered
between pull and start), but the primary gate is
pre-pull.

## Phase rollout

### Phase A — simplestreams resolver

New `pkg/core/incus/streams.go`:

```go
// ResolveImageDigest fetches the simplestreams index at
// the given Server, parses the products/versions tree,
// and returns the published SHA-256 fingerprint for the
// requested (product, version, arch). Returns ErrNotFound
// if the alias doesn't resolve in the published index,
// ErrIndexUnreachable for network failure.
func ResolveImageDigest(ctx context.Context, server, alias, arch string) (digest string, err error)
```

Tests use a `httptest.Server` that serves a canned
images.json — mirrors how the Vault and GCP KMS backends
are tested. No live network from CI.

### Phase B — gate wired into CreateContainer

`internal/server/container_server.go`:

```go
if err := validateImageDigest(req.Image); err != nil {
    return nil, status.Error(codes.InvalidArgument, err.Error())
}
// NEW
if requested := extractDigest(req.Image); requested != "" {
    server, alias := splitImageRef(req.Image)
    published, err := incus.ResolveImageDigest(ctx, server, alias, runtime.GOARCH)
    if err != nil {
        return nil, status.Error(codes.FailedPrecondition,
            fmt.Sprintf("image digest verification: %v", err))
    }
    if !strings.EqualFold(published, requested) {
        return nil, status.Error(codes.FailedPrecondition,
            fmt.Sprintf("image digest mismatch: requested %s, registry published %s — refusing pull",
                requested, published))
    }
}
```

New env: `CONTAINARIUM_VERIFY_IMAGE_DIGEST=true|false`
(default false to keep the change opt-in for the first
release, then promoted to default-on once the
simplestreams resolver has soak time).

### Phase C — post-pull defense-in-depth

After `CreateContainer` returns from the Incus call,
read the local image's fingerprint via
`client.GetImage(fingerprint)` and assert it equals the
declared digest. Mismatch deletes the container and
returns an error.

This catches the cache-tampering threat and the
"verifier index out-of-sync with pull" race.

### Phase D — operator runbook + soak

Document the toggle, the verification semantics, the
remediation steps when verification fails, and a soak
window where operators run with `_VERIFY_IMAGE_DIGEST=true`
in a non-blocking warn-only mode (logs would-be
rejections) before flipping to blocking.

## Open questions

- **Simplestreams index TTL.** The index changes when the
  registry publishes new images. We don't want to fetch
  it on every CreateContainer call. Cache horizon: 5
  minutes? An LRU keyed by server URL?
- **Architecture detection.** `req.OsType` doesn't carry
  arch. We default to `runtime.GOARCH` of the daemon host,
  which is correct as long as the daemon and container
  share an arch (true for everything Containarium runs
  today).
- **Non-simplestreams remotes.** What if an operator
  adds a custom OCI-style remote in the future? Today the
  three supported remotes are all simplestreams; the
  resolver assumes this. A future OCI remote would need
  its own resolver impl (OCI manifest digest), routed
  through a remote-type switch.

## Decision log

- **Pre-pull verification.** Picked over post-pull for the
  reasons above; post-pull is added as Phase C
  defense-in-depth, not the primary gate.
- **Reuse simplestreams as the source of truth.** No need
  to invent a sidecar registry index. The image publisher
  already signs and serves it.
- **No new daemon dependency.** Resolver is raw HTTP +
  `encoding/json`, mirroring the Vault and GCP KMS impls.

## Implementation plan (single-PR-friendly chunks)

1. Phase A simplestreams resolver + tests (~300 LOC).
2. Phase B wire into CreateContainer + integration test
   (~100 LOC).
3. Phase C post-pull defense-in-depth (~80 LOC).
4. Phase D runbook update + soak guidance.

Each phase is independently shippable; mismatch detection
gets stronger with each one but B alone is the load-
bearing security gate.
