# Design: container node pools for managed Kubernetes clusters

**Date:** 2026-08-18
**Status:** accepted
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

---

## Amendment 1 — what running it taught us (2026-08-19)

The first real run of the container-mode lane (#1430) produced two
findings that this design had assumed away. Both were then run down
empirically on a nested Incus host — an LXC box whose own Incus creates
the node containers, i.e. the harshest environment we intend to
support. Recorded here because the original text is now wrong without
them.

### 1. Pod sandboxes fail — and the no-privileged line SURVIVES

**Observed.** k3s starts fine in an unprivileged system container
(node reached `Ready`), but every pod sandbox failed:

```
runc create failed: unable to start container process: error during container init:
open sysctl net.ipv4.ip_unprivileged_port_start file: reopen fd 8: permission denied
```

containerd's CRI plugin sets `net.ipv4.ip_unprivileged_port_start=0`
for every sandbox (`enable_unprivileged_ports = true` in the generated
config); an unprivileged container may not write it.

**Proven fix — configuration, not privilege.** A containerd config
template on container-mode nodes setting

```toml
[plugins.'io.containerd.cri.v1.runtime']
  enable_unprivileged_ports = false
  enable_unprivileged_icmp  = false
```

was applied to a live probe: k3s restarted, the node came back
`Ready`, and `coredns`, `local-path-provisioner` and `metrics-server`
all reached `Running` with zero remaining sysctl errors. **No
`security.privileged`.** The design's hard line stands, and this
template joins the container profile as a required part of it.

**Cost, recorded honestly.** Container-class nodes therefore differ
from VM-class nodes in tenant-visible behaviour: pods cannot bind
ports below 1024 without `CAP_NET_BIND_SERVICE`, and unprivileged
ICMP is unavailable. That is a real capability difference between the
two isolation classes and belongs in the product docs, not just here.

### 2. Node capacity is fiction *on a nested host* — and lxcfs does not save us

> **Corrected 2026-08-20 (#1456).** As first written, this section
> claimed container nodes misreport capacity, full stop, and prescribed
> an unconditional reservation. Both are wrong. The measurement below
> was taken on a nested Incus host and holds only there; on a plain
> Incus host lxcfs works and the node sees its real limits. Applying
> the reservation unconditionally computed 12.8 GB of reserved memory
> for a 4 GB node, and kubelet refused to start:
>
> ```
> invalid Node Allocatable configuration. Resource "memory" has a
> reservation of {{12766414848 0}} but capacity of {{3999997952 0}}.
> ```
>
> The correction meant to make allocatable truthful stopped the node
> from running at all, on exactly the hosts where nothing needed
> correcting. The original text is kept below so the reasoning is
> auditable; read it as scoped to nested hosts.

**Observed (nested host only).** A node container created with
`limits.cpu=2`, `limits.memory=3GB` advertised to Kubernetes:

```
capacity: 8 cpu / 65841348Ki memory        (truth: 2 cpu / 3 GB)
```

`nproc` reports 2 correctly (it reads scheduler affinity), but
cadvisor derives node capacity from `/proc/cpuinfo` and
`/proc/meminfo`, which show the outer host's values.

**lxcfs is not the answer.** The probe host had lxcfs installed and
mounted, and the nested child instances still saw host values —
masking does not propagate to a nested Incus's own instances. A design
that says "require lxcfs" would be requiring something already present
and still broken.

**Why this is a correctness bug, not cosmetics.** The scheduler packs
pods against allocatable, and cluster-autoscaler's fit simulation
reads the same number. A node claiming four times its real CPU and
twenty times its real memory means pods are scheduled where they
cannot run and **scale-up is never triggered** — the autoscaling story
this whole feature exists for, silently disabled.

**Required fix — superseded.** This section originally called for
kubelet args pinning reserved resources to (observed capacity −
requested size), computed from the daemon host's `/proc`. That shipped
in #1452 and was removed in #1457 for the reason in the correction
above: the daemon host's capacity is not the node's capacity, and on a
plain host the two differ by enough to make kubelet reject the config.

What survives is the shape of the answer, not its trigger. A
reservation is correct **only when the node actually misreports**, and
that can only be established from the node itself after boot — never
inferred from the daemon host.

> **Settled 2026-08-22 (#1466).** The *when* now has an answer, and it
> is the only one that distinguishes the two environments: after
> `WaitReady` and before the bootstrap script is pushed, the daemon
> reads `/proc/cpuinfo` and `/proc/meminfo` **inside the node** and
> compares them with the size that node was asked for. Excess is
> reserved; no excess reserves nothing. A node whose `/proc` cannot be
> read fails the provision rather than proceeding uncorrected — an
> unmeasurable node is not a node known to be honest, and proceeding
> silently is the failure this whole section is about.
>
> One thing the implementation had to get right that the reasoning
> above misses: an honest node reports **slightly less** than its
> configured size, because the kernel's `MemTotal` excludes
> firmware-reserved and unavailable memory (a 4GB node reports about
> 3,999,993,856 bytes). `ReservedResources` treats observed-below-
> requested as an error, which is correct for the create-time sizing
> question it serves and wrong here — it would refuse every honest
> container node, i.e. #1456 with the sign flipped. The post-boot
> trigger is therefore a separate function, `NodeReservation`, with a
> one-way comparison: reserve the excess a node claims over its own
> size, per dimension, and nothing when it claims none.
>
> `ReservedResources` and `HostCapacity` keep their create-time role
> (`CheckNodeCapacity` — can this host fit a node of this size); they
> are no longer uncalled.

### Consequences for the stories as merged

- `pkg/core/cluster/containerprofile.go` (#1429, merged) is
  **incomplete**: it needs the containerd template and the
  allocatable-pinning kubelet args.
- `ContainerNodeCapable()` (#1429, merged) does not check capacity
  truthfulness. On a plain host it does not need to; on a nested host
  that gap is #1466.
- The container-mode lane (#1430) runs on a plain GitHub-hosted runner,
  so finding 2 does not gate it. Its journey should still assert
  scale-up actually triggers — the assertion that would have caught
  finding 2 on day one, and the one that would catch #1466 regressing.
