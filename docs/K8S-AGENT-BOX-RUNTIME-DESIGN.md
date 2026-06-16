# K8s Agent-Box Runtime — SSH-Reachable Pod Design Note

> Status: **Exploration / not yet approved.** Tracking: #700. This proposes a Kubernetes
> backend for the agent box: a per-tenant pod that an agent reaches over
> SSH, exposing the same `agent-box` stdio MCP surface served today from an
> LXC box. Nothing here is built yet.

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

### 2. Gateway (`sshpiper` Deployment + upstream controller)

`sshpiper` itself is unchanged from the sentinel deployment — it terminates
`:22` (via a `Service type=LoadBalancer`) and routes by SSH username. It stays
a **dumb L4 reverse proxy**; routing state lives one layer up.

The new piece is a thin **upstream controller** replacing the sentinel's
`/authorized-keys`-poll-and-write-YAML loop:

- Watches tenant objects (CRD or labeled namespaces) + their box pods.
- Programs the sshpiper upstream map via the maintained sshpiper **Kubernetes
  plugin** (`PiperUpstream` CRD): `username=<tenant>` →
  `box-0.boxes.<tenant>.svc:22`. CRD-driven removes the file-write race that
  bit the sentinel (the `#301`/`#404` class of bug) entirely.
- Reconciles each tenant's authorized key into the per-tenant Secret.

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
| sentinel key-sync → YAML | controller → `PiperUpstream` CRD + Secret |
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
`PiperUpstream` CRD + per-tenant key Secret. The platform MCP tool wraps the
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
   jump-server account; K8s uses a per-tenant Secret + `PiperUpstream`. So
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
    // per-tenant Secret + PiperUpstream.
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

## Packaging & repo strategy — one repo now, extract later

Should the K8s bridge be its own repository? **Not yet.** The decision is
dominated by one factor and gated by one future fork.

### The dominating factor: `client-go` dependency weight

The K8s backend pulls in `k8s.io/client-go` — a large transitive tree. As an
ordinary package in the main module, **every LXC-only daemon build carries that
weight** (slower builds, bigger binary, wider attack surface for users who never
touch K8s). The fix is a **Go build tag**, not a separate repo:

```go
//go:build k8s
```

The K8s implementation compiles only into a `containarium-k8s` build variant;
the default daemon never imports `client-go`. Dependency blast radius is
isolated while everything stays in one tree.

### Why same-repo wins now

- **The interface will churn.** `BoxBackend` is new and will change as the K8s
  impl teaches us what's wrong with it. In one repo, "change interface + update
  LXC + update K8s" is one atomic PR with compile-time enforcement. Split into
  two repos and every tweak becomes a version-bump-and-coordinate dance.
- **Go's `internal/` rule.** A separate repo *cannot* import `internal/server`.
  Splitting forces promoting the interface to `pkg/` anyway — doing that early
  freezes an unstable contract.

### Cheap insurance to lock in today

Put the interface where a future extraction is free: **`pkg/core/box`**
(public), not `internal/`. Domain types (`BoxSpec`, `BoxHandle`, `BoxEndpoint`)
live there too. Then "extract to its own repo" is a `git mv` + a `go.mod`, not a
redesign.

### The fork that gates a future split

| | Compiled-in (build tag) | Out-of-process bridge |
| --- | --- | --- |
| What it is | K8s impl linked into a daemon variant | separate binary the daemon calls over gRPC |
| `client-go` location | daemon-k8s variant only | fully outside core — no daemon binary |
| Fits existing pattern | a new backend | **the multi-backend-peer model already in the tree** |
| Release cadence | tied to daemon | independent |
| Cost | one binary | a process to deploy + a wire protocol |

The out-of-process bridge is the natural end state **because the PeerPool /
`backend_id` routing already exists** — a K8s bridge can register like a peer,
and `client-go` leaves the core dependency graph entirely. That is the version
where an independent repo clearly pays for itself. It is a **Phase 2** move,
after the interface stabilizes.

### Decided path

1. **Now:** one repo, K8s impl behind `//go:build k8s`, interface in
   `pkg/core/box`.
2. **Later (interface stable):** extract to its own repo as an **out-of-process
   bridge that registers like a peer**.

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
| CRUD | `PiperUpstream` | gateway namespace only |
| create | Namespace | only if the controller owns tenant-namespace lifecycle |

Shipped as a **Helm chart / operator bundle** the customer reviews and installs.
Containarium then drives the cluster through the controller's ServiceAccount.

### Hard gates — absent these, the design changes (not just config)

| Requirement | Why | Fallback if missing |
| --- | --- | --- |
| **L4/TCP ingress** (LoadBalancer / NodePort / Gateway API `TCPRoute`) | SSH is TCP; K8s Ingress is HTTP-only | NodePort + external LB; `kubectl port-forward` for dev |
| **NetworkPolicy-enforcing CNI** (Calico, Cilium, …) | default-deny isolation is a **no-op** under a CNI that ignores it | degrade to namespace-only isolation — **must flag loudly** |
| **CRD install rights** (cluster-admin, once) for `PiperUpstream` | the sshpiper Kubernetes plugin is CRD-driven | `yaml` plugin — re-inherits the sentinel file-write race |
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
   race) vs. the `yaml` plugin run today. Leaning CRD.
2. **Host-key trust** — pre-distribute the gateway host key (ConfigMap →
   agent known_hosts) so first-connect is not a TOFU prompt.
3. **Runtime interface shape** — sketched above ("The box-backend Go
   interface"). Open sub-questions: does K8s v1 implement `ExecCapable` at all
   (vs. fully image-baked provisioning), and does `SetMeta` need a typed struct
   rather than `map[string]string` per the repo's strong-typing convention.
4. **Packaging** — *decided* (see "Packaging & repo strategy"): one repo +
   `//go:build k8s` now, interface in `pkg/core/box`; extract to an
   out-of-process peer-registering bridge once the interface stabilizes.
   Remaining: confirm the build-tag split keeps `client-go` out of the default
   `go.sum`, and whether CI gains a `containarium-k8s` build target.

## Deferred (not in v1)

- **Hard isolation** (gVisor/Kata `RuntimeClass`) — for tenants needing a
  VM/syscall boundary closer to the LXC trust boundary.
- **Ephemeral / pooled lifecycles** — spin-up-on-connect or warm-pool leasing.
- **GPU passthrough** in pods (`nvidia.com/gpu` resource + device plugin).
- **Cross-cluster / multi-pool** fan-out (the K8s analog of multi-backend
  peers).
