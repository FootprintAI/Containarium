# Cloud-Actuation Client — Design Note

> Status: **Drafted, awaiting review.** Filed in response to the gap
> between the cloud control plane (already built, deployed at
> `cloud.containarium.dev`) and the OSS host-daemon — the cloud's
> `ActuationService` has no client today, so registered hosts can't
> exist and customer containers in the cloud can't actually boot.

## Cross-repo context

This work pairs with [Containarium-cloud](https://github.com/FootprintAI/Containarium-cloud):

- [`prd/cloud/container-actuation.md`](https://github.com/FootprintAI/Containarium-cloud/blob/main/prd/cloud/container-actuation.md) — the cloud-side PRD defining the desired/observed-state split
- [`proto/containarium/cloud/v1/actuation_service.proto`](https://github.com/FootprintAI/Containarium-cloud/blob/main/proto/containarium/cloud/v1/actuation_service.proto) — the gRPC contract this client consumes
- [`proto/containarium/cloud/v1/host.proto`](https://github.com/FootprintAI/Containarium-cloud/blob/main/proto/containarium/cloud/v1/host.proto) — host CRUD (sysadmin-only, used at enrollment)
- [`internal/auth/host_bearer.go`](https://github.com/FootprintAI/Containarium-cloud/blob/main/internal/auth/host_bearer.go) — the bearer-token format every RPC carries

The OSS daemon today is single-tenant — it doesn't know about the
cloud control plane. This doc designs the client side that lets an
operator opt in: their OSS daemon registers with the cloud, accepts
assignments, and reports state back. Without it, a self-hosted
Containarium is unchanged.

## Where we are today

The cloud control plane is fully built:

- `hosts` table + admin RPCs (`CreateHost`, `ListHosts`, `RotateHostToken`)
- `container_assignments` table — scheduler writes desired state here
- `ActuationService` gRPC server — handles Heartbeat / WatchAssignments / ReportContainerState
- `HostBearerInterceptor` — auth gate for the three RPCs above

The schema is wired, the scheduler exists, the dashboard renders.
What's missing: nobody calls these RPCs from the host side. Today
`SELECT * FROM hosts` in the cloud-daemon's database returns zero
rows, and `container_assignments` would sit forever if a customer
clicked "create container" in the dashboard.

## Goal

A new mode of the OSS `containarium daemon`:

- Reads a one-time-issued host bearer token from local config
- Heartbeats to the configured cloud control plane every ~30s
- Opens a `WatchAssignments` server-streaming RPC and reconciles the
  resulting assignments against local Incus state (create, start,
  stop, delete containers as desired_state demands)
- Reports observed state back via `ReportContainerState` after each
  reconciliation cycle
- Survives transient control-plane unavailability — reconnects with
  exponential backoff, never loses local containers if the cloud
  is down

When the new flag is **not** set, the OSS daemon's behavior is
identical to today's — single-tenant, no outbound calls. This is
load-bearing for self-hosted users who don't want cloud coupling.

## Non-goals

- **Migrating existing OSS state into the cloud.** A host that was
  created via `containarium create alice ...` before enrollment
  stays purely local. The cloud only knows about containers it
  itself assigned. (A future `containarium cloud adopt` could pull
  existing local containers into the cloud's books — separate PRD.)
- **Bidirectional drift reconciliation.** v1 is one-way: cloud
  asserts desired_state, host enacts it. The host can refuse (e.g.
  capacity exhausted) by failing the assignment, but it doesn't
  push its own desired_state intentions.
- **Multi-cloud / federation.** One host registers with one cloud
  control plane. Multi-tenancy across two clouds is out of scope.
- **Auto-enrollment via the public web.** Enrollment is sysadmin-
  driven: someone with cloud admin credentials calls `CreateHost`,
  hands the resulting token to the host operator over an out-of-
  band channel (Vault, 1Password, secure DM). The OSS daemon never
  talks to the cloud's auth surface.

## CLI shape

Per the repo's CLI-first convention, every actuation surface lands as
a `containarium <verb>` subcommand before any non-CLI consumer
(MCP, web UI, etc.).

```
# One-time setup. Writes ~/.containarium/cloud.yaml with the
# enrolled host's ID + bearer token.
containarium cloud login \
    --control-plane cloud.containarium.dev:443 \
    --host-id   <uuid from sysadmin> \
    --token-file /path/to/host.token

# Inspect current registration. Last heartbeat timestamp, assignment
# count, stream connection status.
containarium cloud status

# Tear it down. The OSS daemon stops actuating; the cloud-side host
# row stays (sysadmin uses DeleteHost to tombstone).
containarium cloud logout
```

The daemon learns about cloud registration two ways:

1. **Implicit:** if `~/.containarium/cloud.yaml` exists, the daemon
   starts the actuation client automatically on launch.
2. **Explicit:** `containarium daemon --cloud-actuation=disable`
   overrides the config-file detection (operator wants to start the
   daemon without the cloud client for debugging).

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│ OSS containarium daemon (this process)                    │
│                                                           │
│  ┌─────────────────────┐    ┌───────────────────────┐    │
│  │ existing gRPC + REST │    │ cloud-actuation       │    │
│  │ API surface          │    │ background client     │    │
│  │ (single-tenant)      │    │                       │    │
│  │ - CLI calls          │    │  ┌─────────────────┐  │    │
│  │ - SSH key mgmt       │    │  │ Heartbeat ticker│  │    │
│  │ - app-hosting flows  │    │  └─────────────────┘  │    │
│  └─────────────────────┘    │  ┌─────────────────┐  │    │
│           │                  │  │ WatchAssign-    │  │    │
│           │ both share       │  │ ments stream    │  │    │
│           ▼                  │  │   consumer      │  │    │
│  ┌─────────────────────┐    │  └────────┬────────┘  │    │
│  │ Reconciler          │◄───┼───────────┘            │    │
│  │ (incus + ZFS shell) │    │  ┌─────────────────┐  │    │
│  │                     │────┼─►│ Report state    │  │    │
│  └─────────────────────┘    │  │  back to cloud  │  │    │
│                             │  └─────────────────┘  │    │
│                             └───────────────────────┘    │
└───────────────────────────────────────────────────────────┘
         │
         ▼ host-bearer over mTLS
┌───────────────────────────────────────────────────────────┐
│ cloud-daemon (Containarium-cloud repo)                    │
│ ActuationService: Heartbeat / WatchAssignments /          │
│                    ReportContainerState                   │
└───────────────────────────────────────────────────────────┘
```

The cloud-actuation client is a **single background goroutine** with
two child goroutines:

1. **Heartbeat ticker** — wakes every 30s, fires Heartbeat RPC. On
   any error logs + continues; consecutive failures bump a metric
   the operator can watch but don't crash the daemon.
2. **WatchAssignments consumer** — opens the stream, ranges over
   `AssignmentBatch` messages, hands each batch to the reconciler.
   On stream disconnect: exponential backoff retry (1s, 2s, 4s, 8s,
   capped at 60s; jittered ±20% so a herd of restarts doesn't
   stampede the control plane).

The reconciler is **idempotent**:

- For each Assignment, look up the local Incus container by name
- If `desired_state="running"` and container doesn't exist → create
- If `desired_state="running"` and container exists but stopped → start
- If `desired_state="stopped"` and container running → stop
- If `desired_state="deleted"` and container exists → delete (and ZFS-clean)
- After every state change, call ReportContainerState with the new observed state
- If a state change fails, ReportContainerState carries the failure;
  the cloud-side scheduler can react (slice 2 of cloud PRD)

## Proto consumption — Go module vs vendor

The cloud-daemon repo at `github.com/footprintai/containarium-cloud`
already publishes generated Go stubs at
`pkg/pb/containarium/cloud/v1`. Three ways to consume them here:

| Option | What it looks like                                         | Pro | Con |
|--------|------------------------------------------------------------|-----|-----|
| **A. Go module dep**       | `go get github.com/footprintai/containarium-cloud/pkg/pb/containarium/cloud/v1`  | Single source of truth, zero proto regen in OSS | Adds a private-module dependency; needs GOPRIVATE config for non-org users |
| **B. Vendor the protos**   | Copy `.proto` files into OSS `proto/containarium/cloud/v1/`, regenerate locally | OSS stays self-contained | Two copies of the same proto can drift; we'd need a CI check to enforce sync |
| **C. Git submodule of cloud repo** | `git submodule add` the cloud repo, `proto/` referenced from there | Source of truth preserved without the Go dep | Submodules are operationally painful; CI has to recurse-clone |

**Recommendation: A (Go module dep).** The pure-types nature of the
import (only `cloudv1.ActuationServiceClient`, request/response
messages — no business logic) makes the coupling minimal. The
cloud-daemon repo is already accessible inside the FootprintAI
org; non-org self-hosted users only ever exercise this code path
if they explicitly enable cloud registration, at which point they
already need network access to a cloud control plane anyway.

If the cloud-daemon repo is later made public, this constraint
disappears entirely. If it stays private and we want to ship a
public OSS binary that doesn't include cloud-actuation by default,
we put the client behind a build tag (`//go:build cloud_actuation`)
and ship two builds.

## Security model

- The host bearer token is **opaque, server-issued, single-host-scoped**.
  Format defined by `internal/auth/host_bearer.go` in the cloud
  repo. The OSS client treats it as a base64 string — it does not
  parse or validate the token, only includes it as the
  `host-bearer` gRPC metadata header on every actuation RPC.
- The token is **persisted at mode 0600** in
  `~/.containarium/cloud.yaml` (or `/etc/containarium/cloud.yaml`
  when the daemon runs as root via systemd). On Linux the token
  file inherits the daemon user's permissions; on macOS dev rigs
  the operator manages access via filesystem ACLs.
- The token **rotates via the cloud's** `RotateHostToken` **RPC**.
  After rotation the old token returns Unauthenticated on the next
  heartbeat; the OSS daemon logs the rotation event and surfaces
  it via `containarium cloud status`. v1 does not auto-fetch the
  rotated token — the operator must `containarium cloud login`
  again with the new token. Auto-rotation is a follow-up.
- mTLS is **strongly recommended** but not required for the gRPC
  channel. The cloud-daemon currently accepts plaintext + JWT
  cookies + host-bearer over either; deployment without mTLS is
  fine for a single-tenant org-cloud, dangerous for a public
  multi-tenant cloud control plane. Both ends are sysadmin-trusted
  for the v1 self-hosted-private-cloud use case.

## State machine

Each assignment is in one of five states from the host's view:

```
        ┌───────────┐
        │  pending  │   first time we see this assignment_id
        └─────┬─────┘
              │ desired_state = "running" arrives via stream
              ▼
        ┌───────────┐
        │ creating  │   `incus create + start` in flight
        └─────┬─────┘
              │
              ▼
        ┌───────────┐         desired_state = "stopped"
        │  active   │ ────────────────────────────┐
        └─────┬─────┘                              │
              │ desired_state = "deleted"          │
              ▼                                    ▼
        ┌───────────┐                       ┌───────────┐
        │ deleting  │                       │  stopped  │
        └─────┬─────┘                       └─────┬─────┘
              │                                    │
              ▼                                    │ desired_state = "running"
        ┌───────────┐                              │
        │  deleted  │                              ▼
        │  (tomb-   │                       (back to active)
        │   stone)  │
        └───────────┘
```

Every transition writes a `ReportContainerState` so the cloud
scheduler always knows where reality is. A failed transition (e.g.
incus errored out) writes `state = "active"` (whatever the host
actually observed) along with an `error` field — the scheduler can
choose to reassign, retry, or escalate.

## SLA + operational

- **Heartbeat interval**: 30s default, configurable via
  `--cloud-heartbeat-interval`. Cloud-side staleness threshold is
  defined by `repository.DefaultHostStalenessThreshold` (currently
  90s — 3 missed beats).
- **Stream reconnect**: exponential backoff with jitter, max 60s.
  When reconnecting, the host re-issues `WatchAssignments` from
  scratch; the cloud sends the full current set of assignments,
  not a delta. Idempotent reconciler handles the "have I already
  done this" check.
- **Crash recovery**: the OSS daemon's state of which Incus
  containers exist is in incus itself (not in our process memory).
  On daemon restart the reconciler queries the cloud once
  (WatchAssignments) and incus once (`incus list`), diffs the two,
  and converges. No persistent state needed in the OSS daemon.

## Open questions

- **mTLS by default?** v1 says no (operator can enable); the cloud's
  network exposure decides. If `cloud.containarium.dev:443` is the
  endpoint and ALPN-routed through Caddy, the gRPC channel is TLS
  to the sentinel but plaintext from sentinel to backend — same as
  every other RPC. Acceptable for now; revisit when the platform
  starts hosting customer workloads with PCI/HIPAA scope.
- **Per-tenant namespace mapping?** When the cloud assigns
  container `cloud-uuid-1234`, what does the OSS daemon name the
  Incus container locally? Proposal: `cld-<short-uuid>` so
  operator-managed containers (`alice-container`) and cloud-managed
  ones don't collide. The cloud's `Container.name` field becomes
  the human-readable label, not the Incus identifier.
- **Resource accounting back-channel.** The cloud's billing
  pipeline needs CPU/RAM/disk usage. v1 of this client doesn't
  surface that — the existing daemon's metrics emission stays as-is.
  Plumbing usage events into the cloud is a separate slice
  (cloud-side already has the `usage_rollups` table).

## Slice plan

Five PRs, each independently mergeable:

1. **Proto consumption + skeleton.** Add the Go-module dependency on
   `containarium-cloud/pkg/pb/...`. Wire an empty `internal/cloud/`
   package with a `Client` struct, no behavior yet. Compiles +
   `go test ./...` clean.
2. **CLI: `containarium cloud login / status / logout`.** Mints a
   local config file. No daemon integration — purely operator-side.
3. **Heartbeat ticker.** Daemon spawns the ticker on start if cloud
   config is present. End-to-end: register a host on the cloud
   side, run the OSS daemon, see `hosts.last_heartbeat_at` update.
4. **WatchAssignments + reconciler.** The meaty slice. Stream
   consumer, reconciler with the state machine above, incus shell-
   outs, ReportContainerState callbacks. Heavy unit tests; one
   integration test against a real Incus on the demo cluster.
5. **Smoke against `cloud.containarium.dev`.** Register a host on
   the deployed cloud-daemon, point the demo box's OSS daemon at
   it, create a container via the cloud dashboard, watch it boot.

## Test plan

- **Unit**: reconciler decision table (current state × desired
  state → action), state-machine transitions, idempotency
  guarantees (same assignment seen twice = no-op).
- **Integration**: a fake `cloud-daemon` test server (httptest +
  gRPC) plus a real Incus on a CI host. End-to-end: assign a
  container, observe it boot, change desired_state to stopped,
  observe it stop, change to deleted, observe ZFS cleanup.
- **Soak**: 24h continuous heartbeat against a staging cloud,
  measure reconnect rate + drift. Acceptance: zero reconnects on
  a clean network, ≤1 drift event per hour on a noisy one.
- **Acceptance criteria for v1 ship:**
  - Operator can register a host with one CLI command + one token
    from sysadmin.
  - Customer signs up on `cloud.containarium.dev`, creates a
    container in the dashboard, the container boots on the
    operator's host within 10 seconds.
  - Daemon restart doesn't lose containers or duplicate them.
  - Cloud control plane outage doesn't kill running containers
    (host keeps them up, just stops reconciling new assignments).

## References

- Cross-repo cloud PRDs:
  - [container-actuation.md](https://github.com/FootprintAI/Containarium-cloud/blob/main/prd/cloud/container-actuation.md)
  - [multi-tenancy.md](https://github.com/FootprintAI/Containarium-cloud/blob/main/prd/cloud/multi-tenancy.md)
- Proto contract:
  [actuation_service.proto](https://github.com/FootprintAI/Containarium-cloud/blob/main/proto/containarium/cloud/v1/actuation_service.proto)
- [ZFS per-container encryption design](ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md) — prior art for an OSS feature that hooks the cloud
- RFC: gRPC server-streaming + reconnect semantics (
  [grpc.io/docs/guides/retry](https://grpc.io/docs/guides/retry))
