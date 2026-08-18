# Design: container node pools for managed Kubernetes clusters

**Date:** 2026-08-18
**Status:** proposed
**Stack:** protobuf/gRPC (grpc-gateway) + the existing host daemon; Go 1.26 throughout (no new languages)
**Extends:** `docs/architecture/managed-k8s-clusters.md` (the VM-only design this
document adds a second isolation class to — everything not named here is
unchanged from that design)

## Problem

Managed clusters provision every node as an Incus **VM**, and the daemon
fails closed on hosts without KVM (`FailedPrecondition: this backend
cannot run virtual machines`). That is the right default for the
multi-tenant threat model — a tenant kubelet runs arbitrary root
workloads, and the VM keeps a kernel exploit inside the tenant's own
kernel — but it makes the entire cluster feature unusable on KVM-less
hosts: containarium-cloud boxes, cloud VMs without nested
virtualization, CI runners. Concretely: the sprint's dev rung (a cloud
box running the daemon @ `ca959d1`) can verify nothing in the cluster
verification queue, and the e2e journey can only run on a scarce
self-hosted KVM machine.

An Incus **system container** can run a k3s node on those hosts —
feasibility-probed on a containarium-cloud box: nested Incus launches
and runs `images:ubuntu/24.04` with `security.nesting=true` (shared
host kernel, no `/dev/kmsg` — the standard k3s-in-container shim
applies, see Contracts). What a container node cannot provide is the
kernel boundary. This design adds container node pools **as an
explicitly weaker, operator-gated isolation class**, never as a silent
fallback.

## Design

One new axis, decided at cluster create time and immutable after:

```
NodeIsolation:  VM (default)  |  CONTAINER (operator-gated)
```

- **Cluster-level, not per-group.** All node groups of a cluster share
  one isolation class. Mixing classes inside one cluster multiplies the
  bootstrap/capability matrix for no journey we have (deferred; see
  Rejected alternatives).
- **Fail closed in both directions.** A `CONTAINER` create on a host
  whose daemon does not carry the operator opt-in is refused with
  `FailedPrecondition`, exactly like a VM create on a KVM-less host. An
  `UNSPECIFIED` isolation resolves to `VM` — the safe default cannot be
  reached by omission of config.
- **Operator-gated, not tenant-selectable.** The tenant *requests*
  `CONTAINER`; the daemon *permits* it only when the operator set
  `CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES=true` on that host. The
  flag is a statement about the host's tenancy model ("everything on
  this host already shares a trust domain": a dev rung, a dedicated
  single-tenant machine, the operator's own CI). On a shared
  multi-tenant host the flag stays unset and container clusters are
  impossible, so a tenant can never *downgrade* the boundary between
  themselves and another tenant.
- **Visible everywhere.** The isolation class is stored on the cluster
  row, returned in `GetCluster`/`ListClusters`/`GetClusterStatus`, and
  printed by `cluster get`/`cluster status`/`cluster list` — an
  operator or auditor can always answer "which clusters share a
  kernel with this host".

### What changes per component (and what doesn't)

| Component | Change |
|---|---|
| `proto/containarium/v1/cluster.proto` | `NodeIsolation` enum; field on `CreateClusterRequest` + `Cluster` |
| `internal/cluster` (store) | persist `node_isolation` on the cluster row; default `vm` |
| `internal/server/cluster_server.go` | authz unchanged; create-path gate: `CONTAINER` requires the env opt-in, else `FailedPrecondition` |
| `internal/server/cluster_reconciler.go` | unchanged — it already talks to the manager through `NodeSpec`s |
| `pkg/core/cluster` (manager/incushost) | `VMHost.CreateVM` seam widens to `CreateNode(spec, isolation)`; `ContainerNodeCapable()` probe alongside `VMCapable()`; container profile applied on the container path |
| bootstrap renderers | identical k3s artifacts and units; container path prepends the `/dev/kmsg` shim line (golden-tested variant) |
| cluster-autoscaler / externalgrpc | **unchanged** — the provider deals in `NodeSpec`s and Incus instances; the CA sees Kubernetes Nodes either way |
| VPA (#1416) | **unchanged** — in-cluster, isolation-agnostic |
| caps (#1417) | **unchanged** — node counts and sizes cap identically; a container node's CPU/memory limits map to Incus container limits |
| CLI (`internal/cmd/cluster.go`) | `cluster create --isolation container` flag (enum-backed); status/list print the class |

### The container node profile

The knowledge of "what an Incus system container needs to run a k3s
node" lives in ONE place, `pkg/core/cluster/containerprofile.go`, as a
typed config set applied by `CreateNode` on the container path:

- `security.nesting=true` (containerd runs pods inside the node)
- cgroup v2 delegation (Incus default for system containers)
- boot-time `/dev/kmsg` shim: `ln -s /dev/console /dev/kmsg` before
  `k3s` starts (the k3d-proven workaround), rendered into the bootstrap
  unit rather than mounted from the host — the host's own `/dev/kmsg`
  may not exist (nested case)
- **no** `security.privileged` — if a future k8s feature turns out to
  need it, that is a new design conversation, not a config tweak

`ContainerNodeCapable()` probes the actual preconditions (nesting
permitted, cgroup v2, br_netfilter/overlay available on the shared
kernel) and refuses with the missing item named — the incusenv
"which step, which error" rule applied to this capability.

### Threat model, stated plainly

| | VM node (default) | Container node |
|---|---|---|
| Tenant kernel exploit contained by | hardware virtualization | **nothing — shared host kernel** |
| Suitable for | multi-tenant hosts | single-trust-domain hosts only |
| Who decides | — | operator (env opt-in) + tenant (explicit request) |
| Signal to auditors | isolation class on every cluster read | same |

A container-node cluster's tenants can, with a kernel exploit, reach
everything on the host. The opt-in flag is the operator asserting that
"everything on the host" is already one trust domain. The product
never asserts it for them.

## Language choices

| Component | Language | Why this one | Type gate in CI |
|-----------|----------|--------------|-----------------|
| all of the above | Go | extensions of existing Go components; no new deployable | `go vet` / `go build` on every PR |

## Contracts

- `NodeIsolation` enum in `proto/containarium/v1/cluster.proto`
  (`NODE_ISOLATION_UNSPECIFIED/VM/CONTAINER`), regenerated via
  `make proto` — never a string field (house rule). Gateway/OpenAPI and
  typed clients come for free.
- `CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES` — daemon env, parsed by
  the same fail-closed pattern as the caps envs (a typo'd value refuses
  container creates rather than allowing them).
- `VMHost` interface: `CreateVM(NodeSpec)` →
  `CreateNode(NodeSpec, NodeIsolation)`; the fake host in
  `manager_test.go` records the isolation it was called with.

## Test strategy

- **`pkg/core/cluster` (unit, table-driven, no infra):**
  `containerprofile_test.go` — golden pin of the applied Incus config
  set and the kmsg-shimmed bootstrap variant; `spec_test.go` gains
  isolation-validation rows (UNSPECIFIED→VM, unknown→error).
  `manager_test.go` — fake-host call sequence per isolation class.
- **`internal/server` (unit):** create-path gate table — container
  request × {flag unset, flag true, flag garbage} → {refuse, allow,
  refuse}; refusal message names the flag. Existing authz tests
  re-run unchanged (isolation adds no authz surface).
- **Store contract tests:** round-trip `node_isolation` in mem + Postgres
  (`store_integration_test.go` lane, existing harness).
- **e2e:** a **container-mode lane on a GitHub-hosted runner**
  (`ubuntu-latest` + Incus, the `incus-create.yml` precedent — no KVM
  needed) running the same six-step journey as #1418's
  `test/e2e/cluster` with `--isolation container`; reuses the suite via
  an isolation env knob. The KVM lane stays the gate for VM mode —
  the container lane is **not** a substitute for it (#1234: each lane
  tests only the mode it actually runs), but it moves scale-up/VPA/
  scale-down/delete behavior from "nightly on scarce hardware" to
  "cheap and frequent" for the shared 95% of the code path.

## Deviations from the default stack

None. No new language, no new deployable, no new dependency.

## Rejected alternatives

- **Tenant-selectable container mode on shared hosts** — a tenant must
  never be able to weaken the boundary that protects *other* tenants;
  the operator flag keeps the decision with the party that owns the
  blast radius.
- **Per-node-group isolation mixing** — doubles the capability and
  bootstrap matrix inside one cluster for no current journey; revisit
  only if a real workload needs a VM group and a container group in one
  cluster (deferred, not designed).
- **Silent fallback (VM unavailable → container)** — turns an isolation
  guarantee into a coin flip decided by host hardware; the whole point
  of the enum is that the weaker class is *chosen*, on the record.
- **kind/k3d-style nodes (k8s-in-podman) for dev** — a second node
  runtime that shares nothing with production's Incus path; the #1234
  lesson says don't test a stand-in where the real mechanism can run,
  and nested Incus *can* run on the hosts in question (probed).

## At 10x

If container-node clusters become a mainstream offering rather than a
dev/single-tenant rung, the pressure lands on (a) per-tenant host
scheduling — placing container clusters only on hosts whose flag is
set becomes a placement constraint in the multi-backend scheduler, and
(b) kernel hardening for the shared-kernel class (seccomp/AppArmor
profiles per node container). Neither changes the contract surface
designed here.
