# K8s Agent-Box Runtime — SSH-Reachable Pod Design Note

> Status: **Approved / shipped.** Tracking: #840 (umbrella), #841–#845 (sub-issues).
> The Kubernetes backend is implemented and in CI. See [`pkg/core/box/k8s/`](../pkg/core/box/k8s/)
> and [`docs/KIND-QUICKSTART.md`](KIND-QUICKSTART.md) for the local bring-up guide.

## What this closes

Today the in-the-box surface (`cmd/agent-box` — shell + file ops over stdio,
SSH-wrapped) only exists on an **LXC/incus backend**. The transport is SSH:
an agent runs `ssh <user>@<gateway> -- agent-box` and gets a scoped MCP
session pinned into a single box. The gateway is `sshpiper` on the sentinel,
routing by SSH username.

There is no equivalent on Kubernetes. Operators who already run a cluster
have no way to host an agent box as a pod — they'd have to stand up a
separate incus host. This note designs a **K8s backend that preserves the
exact agent-facing contract** (SSH → `ForceCommand agent-box` → stdio MCP)
so an agent cannot tell which runtime it landed on.

This is a *backend behind the existing box vocabulary*, not a parallel
surface. Per the repo's CLI-first convention, the entry point is a
`--runtime=k8s` flag on the existing box-create path; the MCP tool wraps the
same Go function.

## The agent-facing contract (unchanged)

```
ssh <tenant>@<gateway-ip> -- agent-box
        │
        ▼  (sshpiper routes by username)
   ForceCommand /usr/local/bin/agent-box   →   stdio MCP loop
```

Everything below is implementation behind that line. The agent's MCP client,
its known_hosts pin, and its scoped key are identical to the LXC path.

## Decisions (locked for v1)

| Axis | Choice | Rationale |
| --- | --- | --- |
| Pod lifecycle | **Long-lived per tenant** | Mirrors the LXC box model; stable DNS, no cold-start. |
| SSH ingress | **In-cluster `sshpiper` Deployment** | Reuse the sentinel reverse-proxy pattern; per-user fan-out behind one IP. |
| Isolation | **Namespace-per-tenant + default-deny NetworkPolicy** | Soft multi-tenancy; the K8s expression of eBPF deny-by-default + egress allowlist. |

Hard isolation (gVisor/Kata `RuntimeClass`) and ephemeral/pooled lifecycles
are explicitly **out of scope for v1** — see "Deferred".

## Topology

```
                         ns: agent-gateway
                   ┌──────────────────────────────┐
   Agent  ──SSH──▶ │  Service(LB) :22             │
  (MCP cli)        │      │                        │
                   │  sshpiper Deployment          │
                   │  + upstream-controller        │
                   └──────┬───────────────┬────────┘
                          │ route by user │
              ┌───────────▼───┐     ┌─────▼─────────┐
   ns:tenant-a │ StatefulSet │     │ StatefulSet  │ ns:tenant-b
              │ box-0 (sshd + │     │ box-0 (...)  │
              │ agent-box)    │     │              │
              │ NetworkPolicy │     │ NetworkPolicy│
              │ default-deny  │     │ default-deny │
              └───────────────┘     └──────────────┘
```

## Components

### 1. The box (per-tenant StatefulSet)

StatefulSet (not Deployment) for the **stable per-pod DNS name** sshpiper
routes to: `box-0.boxes.<tenant>.svc.cluster.local`.

- One container: `sshd` + the `agent-box` binary on PATH.
- `automountServiceAccountToken: false` — the box is a **leaf**, never a
  kube-apiserver client. Its authz is the scoped JWT seeded inside, exactly
  as on LXC.
- `securityContext`: `runAsNonRoot`, `readOnlyRootFilesystem`,
  `capabilities: drop [ALL]`, seccomp `RuntimeDefault`.
- The tenant's authorized public key is mounted from a per-tenant Secret
  (`AuthorizedKeysFile`), or pulled via `AuthorizedKeysCommand` from the
  control plane — the analog of the sentinel `POST /authorized-keys/sentinel`
  push. **No keys are baked into the image.**

`sshd_config` (image-level):

```
ForceCommand        /usr/local/bin/agent-box   # every session → MCP stdio loop
AuthorizedKeysFile  /etc/agent-box/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
PermitTTY           no
AllowTcpForwarding  no                          # no pivoting out of the box
```

`ForceCommand` is the load-bearing line: even a misbehaving client cannot get
a shell — it gets `agent-box` and nothing else.

**Shipped image (`images/agent-box/`):** the config above is the contract; the
actual image realizes it with **dropbear** rather than OpenSSH — dropbear runs
cleanly rootless and takes a forced command (`-c agent-box`), so the box runs
**non-root on `:2222`** (an unprivileged port → no added capabilities) and the
pod satisfies the `restricted` Pod Security profile. The agent still reaches the
gateway on `:22`; `:2222` is only the internal sshpiper→pod hop. Built per
release as `ghcr.io/footprintai/containarium-agent-box`.

### 2. Gateway (`sshpiper` Deployment + upstream controller)

`sshpiper` itself is unchanged from the sentinel deployment — it terminates
`:22` (via a `Service type=LoadBalancer`) and routes by SSH username. It stays
a **dumb L4 reverse proxy**; routing state lives one layer up.

The new piece is a thin **upstream controller** replacing the sentinel's
`/authorized-keys`-poll-and-write-YAML loop:

- Watches tenant objects (CRD or labeled namespaces) + their box pods.
- Programs the sshpiper upstream map via the maintained sshpiper **Kubernetes
  plugin** CRD — the `Pipe` resource (`sshpiper.com/v1beta1`, plural `pipes`;
  earlier drafts of this note called it "PiperUpstream"): `spec.from[].username
  = <tenant>` → `spec.to.host = box-0.boxes.<tenant>.svc:2222` (the box's
  internal SSH port), upstream user `agent`, with the box's
  authorized keys inline as `authorized_keys_data`. The daemon manages Pipes via
  the dynamic client (no sshpiper Go types imported). CRD-driven removes the
  file-write race that bit the sentinel (the `#301`/`#404` class of bug).
- Reconciles each tenant's authorized key into the per-tenant Secret.

**Credential chain (two keypairs).** sshpiper terminates the client connection
and opens a *new* one to the box, so two hops authenticate independently:
client→sshpiper against the Pipe's `spec.from.authorized_keys_data` (the agent's
key), and sshpiper→box against `spec.to.private_key_secret` (sshpiper's
**upstream** key, whose public half the daemon authorizes on the box — the box
never authorizes the agent's key in gateway mode). Deployable manifests +
runbook live in [`deploy/k8s/sshpiper/`](../deploy/k8s/sshpiper/); the daemon is
wired via `CONTAINARIUM_K8S_GATEWAY_UPSTREAM_{PUBLIC_KEY,KEY_SECRET}`.

### 3. Isolation (NetworkPolicy)

Per tenant namespace:

- **Default-deny ingress**, single allow rule: TCP/22 *from the sshpiper pod
  only* (matched by `agent-gateway` namespace + pod label).
- **Default-deny egress**, allowlist: cluster DNS + the control-plane API
  endpoint. This is the K8s expression of the eBPF egress allowlist shipped
  on the LXC backend.

## Mapping to the existing (LXC) architecture

| Containarium (LXC) | This K8s backend |
| --- | --- |
| `agent-box` over stdio, SSH-wrapped | identical — same binary, same `ForceCommand` |
| sshpiper on sentinel :22 | sshpiper Deployment + LB Service :22 |
| sentinel key-sync → YAML | controller → `Pipe` CRD + Secret |
| LXC box per tenant | StatefulSet `box-0` per tenant namespace |
| eBPF deny-by-default + egress allowlist | default-deny NetworkPolicy + egress allowlist |
| sshd 2222 (mgmt) vs sshpiper 22 | mgmt via `kubectl`/RBAC; sshpiper owns 22 |

## CLI-first surface

Per the repo convention, the K8s-ness is a **backend behind the box
vocabulary**, not a new verb tree:

```
containarium box create --runtime=k8s --tenant=<t>
```

templates the namespace + StatefulSet + headless Service + NetworkPolicy +
`Pipe` CRD + per-tenant key Secret. The platform MCP tool wraps the
**same Go function** the CLI handler calls. The backend is selected behind a
runtime interface; LXC stays the default.

## The box-backend Go interface (sketch)

The seam is the thing that makes `--runtime=k8s` a backend swap rather than a
fork. Two facts about the current code shape where it goes:

1. There is already a `pkg/core/incus.Backend` interface, but it is a
   **leaky, LXC-shaped seam** — `Exec`, `WriteFile`, `ResolveGPUInputToPCI`,
   `GetRawInstance` (returns incus config maps), per-key `SetConfig` over the
   `user.containarium.*` namespace. Kubernetes cannot implement that cleanly,
   and shouldn't have to.
2. SSH addressing + key-sync currently live **above** the incus backend, in
   the `Manager`/`jump_server` layer (host user + `authorized_keys` consumed by
   the sentinel keysync). But those are **runtime-specific**: LXC uses a host
   jump-server account; K8s uses a per-tenant Secret + `Pipe`. So
   addressing and key-sync must move **below** the seam.

So the seam sits one altitude **above** `incus.Backend` (a coarse,
runtime-neutral lifecycle contract) and **absorbs** SSH identity + addressing.
The LXC implementation keeps using `incus.Backend` internally; the K8s
implementation talks to the kube-apiserver. `incus.Backend` is unchanged.

### Core interface

```go
// BoxBackend is the runtime-neutral seam. LXC/incus and Kubernetes both
// implement it. Coarse-grained on purpose — no Exec/WriteFile/config-key
// leakage. ctx is threaded (the K8s client needs it; LXC ignores it).
type BoxBackend interface {
    Kind() BackendKind // "lxc" | "k8s"

    // Lifecycle. Create is declarative: given a runtime-neutral spec, make
    // the box exist and return a handle. Idempotent on re-create (the #669
    // lesson from the agent-skills bring-up).
    Create(ctx context.Context, spec BoxSpec) (*BoxHandle, error)
    Start(ctx context.Context, ref BoxRef) error
    Stop(ctx context.Context, ref BoxRef, force bool) error
    Delete(ctx context.Context, ref BoxRef, force bool) error

    // Introspection.
    Get(ctx context.Context, ref BoxRef) (*BoxStatus, error)
    List(ctx context.Context) ([]BoxStatus, error)

    // Addressing — how an agent reaches this box over SSH. THE method that
    // makes the K8s value real. LXC returns sentinel-host|IP; K8s returns
    // the gateway LB host + the username sshpiper routes by.
    Resolve(ctx context.Context, ref BoxRef) (*BoxEndpoint, error)

    // SSH identity. Below the seam because the mechanism differs per runtime:
    // LXC writes the host jump-server authorized_keys; K8s reconciles the
    // per-tenant Secret + Pipe.
    SetAuthorizedKeys(ctx context.Context, ref BoxRef, keys []string) error

    // Mutation. Meta is the runtime-neutral replacement for raw incus config
    // keys: TTL, delete-policy, labels, monitoring-enabled. LXC maps it to
    // user.containarium.*; K8s maps it to pod annotations/labels.
    Resize(ctx context.Context, ref BoxRef, r ResourceLimits) error
    SetMeta(ctx context.Context, ref BoxRef, meta map[string]string) error
    GetMeta(ctx context.Context, ref BoxRef) (map[string]string, error)
}
```

### Runtime-neutral types

```go
type BoxRef struct {
    Tenant string // routing key / SSH username
    Name   string // box name (LXC: "<tenant>-container"; K8s: StatefulSet "box-0")
}

type BoxSpec struct {
    Ref        BoxRef
    Image      string
    OSType     pb.OSType
    Resources  ResourceLimits   // cpu / memory / disk
    GPUs       []string         // empty on K8s v1 (deferred)
    SSHKeys    []string
    Labels     map[string]string
    Monitoring bool
    // Provisioning intent — NOT an Exec script. The backend decides how to
    // realize it: LXC runs incus exec; K8s bakes it into the image / an
    // init container. Keeps stack-install runtime-specific, below the seam.
    Stack       string
    StackParams map[string]string
}

type BoxHandle struct {
    Ref      BoxRef
    Endpoint BoxEndpoint
    State    pb.ContainerState
}

type BoxEndpoint struct {
    // The server turns this into Container.ssh_host + the ssh command.
    SSHHost    string // gateway/sentinel public host ("" = direct IP mode)
    SSHPort    int    // 22 via sshpiper
    SSHUser    string // routing key for sshpiper (the tenant)
    DirectIP   string // fallback when no gateway is in front
    AccessType pb.AccessType
}

type BoxStatus struct {
    Ref       BoxRef
    State     pb.ContainerState
    Endpoint  BoxEndpoint
    Resources ResourceLimits
    Meta      map[string]string // TTL, delete-policy, labels, monitoring…
    BackendID string
}
```

### Capability interfaces (not every backend supports everything)

Optional surfaces stay off the core interface and are discovered by type
assertion, so a backend only implements what it can honor:

```go
// In-box exec/file seed. LXC implements it (incus exec / file push). The K8s
// agent-box uses ForceCommand, so v1 may NOT implement this — provisioning is
// image-baked. Callers must handle the unsupported case.
type ExecCapable interface {
    Exec(ctx context.Context, ref BoxRef, cmd []string) (stdout, stderr string, err error)
    WriteFile(ctx context.Context, ref BoxRef, path string, content []byte, mode string) error
}

type MetricsCapable interface {
    Metrics(ctx context.Context, ref BoxRef) (*BoxMetrics, error)
}

type GPUCapable interface { // LXC v1; K8s deferred
    ResolveGPU(ctx context.Context, input string) (deviceID string, err error)
}
```

### What stays ABOVE the seam (runtime-neutral, unchanged)

These keep living in `ContainerServer` / a slimmed `Manager` and call the
backend — they are not duplicated per runtime:

- **Auth** (JWT scope checks), **peer routing** (`PeerPool`, `backend_id`
  fan-out), **async create tracking** (`PendingCreation`), **event emission**.
- **Cascade cleanup orchestration** (routes, TLS subjects) — though the
  *teardown of SSH identity* now flows through `Delete` + `SetAuthorizedKeys`.
- **The proto ↔ domain mapping** (`toProtoContainer` reads `BoxStatus`, not
  incus config maps directly).

### Wiring

`ContainerServer` holds a `BoxBackend` instead of a concrete `Manager`. The
runtime is chosen at daemon start (flag/env) and per-request via
`--runtime` → `BoxSpec`; `incus.Backend` continues to back the LXC
implementation untouched. The first refactor PR introduces `BoxBackend` +
the LXC implementation as a pure wrapper over today's `Manager` (no behavior
change, golden test parity), and only then lands the K8s implementation
against the same contract.

## Packaging & repo strategy — one binary, runtime selection

The K8s backend is **always compiled into the daemon binary** (no build tag).
`client-go` is already in `go.mod`; the dependency cost is accepted in exchange
for a simpler build surface. The active backend is selected at daemon start:

```sh
CONTAINARIUM_RUNTIME=k8s containarium daemon start   # Kubernetes backend
CONTAINARIUM_RUNTIME=lxc containarium daemon start   # LXC/incus backend (default)
```

or via the flag: `containarium daemon start --runtime=k8s`.

See [`internal/server/boxbackend_factory.go`](../internal/server/boxbackend_factory.go)
for the factory. The interface lives in `pkg/core/box` (public, not `internal/`)
so a future out-of-process bridge can import it without promoting internals.

### Future: out-of-process bridge

The multi-backend-peer / `backend_id` routing already exists. The natural
end-state is a K8s bridge that registers *like a peer* — `client-go` then
leaves the core dependency graph entirely. That is a Phase 2 move, after the
`BoxBackend` interface stabilizes.

Per the OSS/Cloud convention, the bridge is a **generic mechanism → it ships in
OSS**, wherever it lives. BYO-cluster *support/packaging* may be a commercial
concern; the backend itself is not task-specific.

## Why a K8s operator would want this

The pitch is **not** "another way to run pods" — Kubernetes already runs pods.
It is: *give an AI agent a safe, SSH-native foothold in your cluster without
handing it `kubectl` or a kube-apiserver token.*

- **No kube-apiserver credential in the agent's hands.** The agent reaches a
  box over SSH and gets a `ForceCommand`-pinned `agent-box` stdio MCP — never a
  cluster client. The box runs with `automountServiceAccountToken: false`. The
  blast radius of a compromised agent is one hardened pod, not the cluster API.
  `kubectl exec`-based agent access, by contrast, requires RBAC that almost
  always over-grants.
- **Passes `restricted` PodSecurity as-is.** Non-root, drop-ALL, seccomp
  `RuntimeDefault`, read-only rootfs. It is a *better-behaved* tenant than most
  workloads — installs cleanly on locked-down clusters.
- **Auditable, namespaced RBAC footprint.** A reviewable Helm chart + a
  namespaced ServiceAccount. No cluster-admin at steady state (only a one-time
  CRD install). Security teams can reason about exactly what it can touch.
- **In-kernel egress isolation, the K8s-native way.** Default-deny
  NetworkPolicy + egress allowlist — the same deny-by-default posture shipped
  via eBPF on the LXC backend, expressed in primitives the cluster already
  enforces.
- **Bring your own cluster, your own nodes, your own GPUs.** No new control
  plane to run, no second scheduler. The agent foothold lives next to the data
  and the GPUs it needs, inside the network boundary the operator already
  trusts.
- **One agent contract across runtimes.** The same `agent-box` surface, the
  same scoped-JWT model, the same CLI (`containarium box create`) whether the
  box lands on LXC or K8s. Teams standardize the agent interface once and pick
  the substrate per environment.

In one line: **the safest blast-radius for an autonomous agent in your cluster —
SSH-native, RBAC-minimal, default-deny — with zero new control plane.**

## Adoption plan (platform engineers / installs)

Buy-in target: **platform / DevOps engineers**, success metric: **adoption
(installs/stars)**. That collapses the whole campaign onto one thing —
**time-to-wow on `kind`, then maximal discoverability.** Security depth and
CNCF credibility are *supporting* assets, not the lead.

### The governing number: time-to-wow

Platform engineers evaluate with `helm install` and a timer. The funnel is:

```
find it → kind up → helm install → ssh agent@localhost -- agent-box → "oh, nice"
```

Under ~5 minutes and copy-pasteable → installs. Needs a real cluster, a cloud
account, or hand-edited YAML → no installs. **Launch definition of done:**

- `kind create cluster` → `helm repo add` → `helm install` → working agent box,
  **zero manual YAML edits**.
- Ships a NetworkPolicy-enforcing CNI **in the kind config** — a kind default
  does not enforce NetworkPolicy, so the isolation demo would silently no-op.
- The "wow" beat is built into the quickstart, not buried: right after the
  agent does a task, three one-liners that *show* `no SA token` /
  `egress dropped` / `shell refused`. Safety is demonstrated, not asserted, in
  the same five minutes.

### Discoverability (where platform engineers find tools), in priority order

1. **Artifact Hub** — the Helm chart. The search surface for "is there a chart
   for X." Non-negotiable for an installs metric.
2. **README leads with the problem + a copy-paste install above the fold** — the
   install command visible without scrolling; the one-line problem statement
   directly above it.
3. **`awesome-kubernetes` / `awesome-mcp` / `awesome-kubernetes-security`** list
   PRs — the upstream-list traffic play, retargeted.
4. **asciinema/GIF of the 5-min demo** embedded in the README — proof-of-wow
   before they install.
5. **CNCF Landscape** entry — low urgency for raw installs, cheap, lends
   legitimacy that converts skeptics.

### Sequencing

1. **P0 — artifact:** Helm chart + `kind` quickstart hitting time-to-wow +
   above-the-fold README. *Nothing ships until this is real.*
2. **P0 — discoverability:** Artifact Hub + asciinema + awesome-list PRs, same
   week as the chart.
3. **P1 — trust backstop:** threat-model doc + Gateway API / NetworkPolicy / PSA
   conformance, linked from the README.
4. **P2 — compounding credibility:** problem-framed blog post, CNCF Landscape,
   public dogfood.

### The risk for an installs goal specifically

SSH-transport weirdness causes bounce *before* the threat model is read — "SSH?
in K8s?" → tab closed. For an adoption play the mitigation is **not a doc, it's
the demo doing the convincing**: the `no SA token` / `egress dropped` beat must
land in the same screen as the install, because for this audience
seeing-is-believing beats prose. The threat model is a backstop you *link to*,
not the front door.

## Integrating with an existing cluster (BYO)

The primary target is **not** a dedicated cluster — it is a cluster the
customer already owns, where Containarium's control plane manages boxes
through scoped access it is granted. This is the K8s analog of the
multi-backend-peer / remote-connector pattern: the control plane drives a
cluster it does not own, via a **namespaced operator** running under its own
ServiceAccount — never via the operator's personal credentials.

Design the operator for BYO and the own-cluster case falls out for free: BYO
is the strict superset of constraints.

### What the box demands of the host cluster (it's modest)

The box is a hardened **leaf**, not a cluster client: non-root,
`automountServiceAccountToken: false`, `readOnlyRootFilesystem`, `drop [ALL]`,
seccomp `RuntimeDefault`, no host mounts, no privileged caps. It satisfies the
PodSecurity `restricted` profile as-is, so it passes admission on locked-down
clusters cleanly. That is a feature: the RBAC ask is small and auditable.

### Controller RBAC footprint (namespaced, not cluster-wide)

| Verb scope | Resources | Boundary |
| --- | --- | --- |
| create/get/delete | StatefulSet, Service, Secret, NetworkPolicy | **label-selected tenant namespaces only** |
| CRUD | `Pipe` | gateway namespace only |
| create | Namespace | only if the controller owns tenant-namespace lifecycle |

Shipped as a **Helm chart / operator bundle** the customer reviews and installs.
Containarium then drives the cluster through the controller's ServiceAccount.

### Hard gates — absent these, the design changes (not just config)

| Requirement | Why | Fallback if missing |
| --- | --- | --- |
| **L4/TCP ingress** (LoadBalancer / NodePort / Gateway API `TCPRoute`) | SSH is TCP; K8s Ingress is HTTP-only | NodePort + external LB; `kubectl port-forward` for dev |
| **NetworkPolicy-enforcing CNI** (Calico, Cilium, …) | default-deny isolation is a **no-op** under a CNI that ignores it | degrade to namespace-only isolation — **must flag loudly** |
| **CRD install rights** (cluster-admin, once) for `Pipe` | the sshpiper Kubernetes plugin is CRD-driven | `yaml` plugin — re-inherits the sentinel file-write race |
| **Namespace-create rights** for the controller | namespace-per-tenant | pin to one shared namespace + label/pod-selector separation (weaker) |

### Degraded modes (named, not silent)

- **No LoadBalancer** (bare-metal, no MetalLB) → NodePort + documented external LB.
- **PodSecurity `restricted` enforced** → box already complies; no action.
- **Single shared namespace mandated** → drop namespace-per-tenant; rely on
  NetworkPolicy pod-selectors + per-box ServiceAccount. Weaker blast radius —
  call it out at create time.

### The make-or-break decision

Whether the customer grants a **one-time cluster-admin CRD install**. With it,
the CRD `kubernetes` plugin gives clean, race-free upstream programming. Without
it, the `yaml` plugin works but re-inherits the file-write race (`#301`/`#404`
class). Document **CRD-install as the happy path, `yaml` as the explicit
fallback** — and surface which mode is active in box status.

## Open questions

1. **sshpiper plugin** — CRD `kubernetes` plugin (eliminates the file-write
   race) vs. the `yaml` plugin run today. Leaning CRD; the daemon already
   manages `Pipe` objects via the dynamic client.
2. **Host-key trust** — pre-distribute the gateway host key (ConfigMap →
   agent known_hosts) so first-connect is not a TOFU prompt.
3. **`ExecCapable`** — K8s v1 does NOT implement it (provisioning is
   image-baked; `ForceCommand` pins the session). Callers discover support via
   type assertion.
4. **GPU node affinity** — the `gpu-spec` label → node affinity mapping
   (so the scheduler picks the right GPU node pool) is not yet wired.

## Shipped features

### Runtime selection (#842)

The daemon binary ships one factory that supports both backends:

```sh
# Default: LXC/incus (unchanged behaviour)
containarium daemon start

# Kubernetes backend
CONTAINARIUM_RUNTIME=k8s containarium daemon start --runtime=k8s \
  --skip-infra-init \
  --standalone
```

`--runtime` takes precedence over `CONTAINARIUM_RUNTIME`. On a K8s host with
no incus installed, the daemon starts cleanly; box lifecycle goes through the
kube-apiserver; incus-only RPCs (Exec, GPU resolve, core-container detection)
return clear errors.

Key env vars for the K8s backend. These are read once at daemon start through
the typed `internal/config` loader: `config.LoadK8s()` returns a `config.K8s`
(whose `Env*` constants are the single source of truth for the names below, and
which applies the defaults shown), and `config.K8s.Validate()` fails fast on a
bad gateway port. The server factory (`newK8sBackend`) maps the result onto the
env-agnostic `pkg/core/box/k8s.Config` — so `pkg/core` reads no environment.

| Env | Default | Purpose |
|---|---|---|
| `CONTAINARIUM_K8S_KUBECONFIG` | ambient rules | Path to kubeconfig; empty = in-cluster |
| `CONTAINARIUM_K8S_BOX_IMAGE` | _(required)_ | Agent-box image (`ghcr.io/footprintai/containarium-agent-box`) |
| `CONTAINARIUM_K8S_GATEWAY_HOST` | _(required)_ | Public SSH gateway host (sshpiper LB) |
| `CONTAINARIUM_K8S_GATEWAY_SSH_PORT` | `22` | Gateway SSH port surfaced on the box endpoint |
| `CONTAINARIUM_K8S_GATEWAY_NAMESPACE` | `agent-gateway` | Namespace sshpiper runs in |
| `CONTAINARIUM_K8S_TENANT_NS_PREFIX` | `tenant-` | Prefix for per-tenant namespaces |
| `CONTAINARIUM_K8S_STORAGE_CLASS` | _(empty = no PVC)_ | StorageClass for persistent data |
| `CONTAINARIUM_K8S_GATEWAY_UPSTREAM_PUBLIC_KEY` | _(empty)_ | Public key sshpiper→box authenticates with |
| `CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET` | _(empty)_ | Secret name holding the matching private key |
| `CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY` | `0` | `1` skips box host-key pinning (escape hatch, not recommended) |
| `CONTAINARIUM_K8S_DEFAULT_MEMORY_REQUEST` | `256Mi` | Default per-box memory request when the box sets none; invalid → built-in default |
| `CONTAINARIUM_K8S_DEFAULT_MEMORY_LIMIT` | `1Gi` | Default per-box memory limit (hard cap, noisy-neighbor guard); invalid → built-in default |
| `CONTAINARIUM_K8S_DISABLE_MEMORY_FLOOR` | `0` | `1` disables the floor — boxes with no explicit memory run unconstrained |

### CSI persistent storage (#841 / #844)

Each box optionally gets a `PersistentVolumeClaim` for its home directory
(`/home/agent`). Controlled by `CONTAINARIUM_K8S_STORAGE_CLASS`:

- **Empty (default):** no PVC; namespace is deleted on `Delete` (original
  behavior, backward-compatible).
- **Non-empty:** PVC named `data` is created before the StatefulSet;
  `Delete` removes compute objects (StatefulSet, Service, NetworkPolicy,
  Secrets) but **retains the namespace + PVC** so data survives a node
  reap. `Purge` removes both PVC and namespace when the tenant is gone.

This design lets autoscaled GCE VMs be reaped without data loss — the PV is
CSI-managed (GKE, EKS, or kind local-path) and outlives any compute node.

Disk size is read from `BoxSpec.Resources.Disk` (e.g., `"20Gi"`); defaults to
`10Gi` when unset.

### GPU resource requests (#845)

`BoxSpec.GPUs []string` maps to a `nvidia.com/gpu` extended-resource limit on
the box container:

```go
len(spec.GPUs) > 0  →  container.Resources.Limits["nvidia.com/gpu"] = N
```

The K8s cluster autoscaler uses this to scale up a GPU node pool when no
schedulable node is available — no Containarium-side autoscaler needed for the
K8s backend. The pod template carries a `containarium.dev/gpu-count: "N"`
annotation for observability.

The GPU *type* (L4, A100, etc.) is expressed via node affinity, driven by a
`gpu-spec` label on the box when set — otherwise K8s schedules to any GPU
node. This is deliberately different from the LXC/GCE path, where the daemon
selects the exact machine type; on K8s, the scheduler owns that decision.

## Deferred (not in v1)

- **Hard isolation** (gVisor/Kata `RuntimeClass`) — for tenants needing a
  VM/syscall boundary closer to the LXC trust boundary.
- **Ephemeral / pooled lifecycles** — spin-up-on-connect or warm-pool leasing.
- **Cross-cluster / multi-pool** fan-out (the K8s analog of multi-backend
  peers).
- **GPU node affinity by spec** — the `gpu-spec` label → node affinity mapping
  is not yet wired; scheduling to any GPU node is the v1 behavior.
