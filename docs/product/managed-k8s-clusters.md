# PRD: Managed Kubernetes clusters on Containarium VMs

**Date:** 2026-11-11 (revised; first drafted 2026-08-17)
**Status:** draft — revised for namespace-scoped tenant access
**Owner:** devops (platform operator)

> **Naming note.** The word "serverless" is already taken inside this
> codebase: it names the shipped box scale-to-zero feature (auto-sleep →
> idle-stop → wake-on-request, `ToggleAutoSleep` et al.). This PRD is the
> *serverless experience of Kubernetes* — no control plane to run, no
> nodes to size — and is called **managed clusters** throughout to avoid
> colliding with that vocabulary.

> **Revision, 2026-11-11.** Tenants no longer receive a cluster-admin
> kubeconfig. A tenant gets a short-lived credential scoped to its own
> namespaces inside its own cluster, and the platform installs and owns
> everything cluster-wide. Tenants cannot install CRDs, ClusterRoles,
> operators or webhooks. The earlier wording ("a kubeconfig that just
> works", `kubectl get nodes` from outside, Knative as a tenant
> install) is withdrawn. See Story 1, Story 6 and Out of scope.

## Problem

A tenant who needs the Kubernetes API on Containarium today must build
and operate their own cluster inside a box. This is not hypothetical —
it is a shipped pattern: the `kubeflow` recipe
(`proto/containarium/v1/recipe.proto`, `docs/KUBEFLOW-SETUP.md`) stands
up k3s *inside a single LXC box* and the tenant owns everything above
the box from that point on:

- **Control-plane ops land on the tenant** — k3s upgrades, certificate
  rotation, etcd/sqlite health, kubeconfig management. The platform's
  own value (managed lifecycle, snapshots, auto-sleep, routing) stops at
  the box boundary and never reaches the workloads inside.
- **Capacity is fixed at box size** — the box is sized for peak at
  create time. A DIY cluster has exactly one node; when pods don't fit,
  the tenant must notice, run `containarium resize`, and hope the
  workload survives. Nothing scales on demand.
- **Pods are sized by guesswork** — requests/limits are hand-tuned once
  and drift; there is no vertical right-sizing, so the single node fills
  up with over-requested pods long before it is actually full.

**Who hurts:** any tenant whose workload is already expressed as
Kubernetes manifests / Helm charts (the entire cloud-native ecosystem's
packaging format), and the platform operator who fields the resize/debug
requests for DIY clusters. **Cost:** hours of cluster ops per tenant that
the platform was supposed to absorb, and workloads lost to platforms that
offer a Kubernetes API out of the box.

**Evidence status:** internal only — the kubeflow recipe's k3s-in-a-box
design, and open issue #857 (node-pool fleet autoscaling) approaching
the same gap from the fleet side. No external user tickets yet; see
Assumptions.

## Target user

A tenant team that runs Kubernetes-packaged workloads (Helm charts,
plain manifests) inside its own namespaces, on Containarium
infrastructure — including GPU hosts the hyperscalers don't offer
cheaply — **without becoming a cluster operator**. Job-to-be-done: "give
me a namespace I can deploy into; you own the cluster, its add-ons and
everything cluster-wide."

Explicitly *not* the target:
- the agent-box user. The existing K8s backend (`pkg/core/box/k8s/`) puts
  Containarium boxes **onto** a customer's cluster; this feature is the
  inverse — Containarium **hosting** clusters on its own substrate. The
  two lanes stay distinct.
- a tenant who needs to install operators, CRDs or cluster-wide
  components. Those are platform-curated (see Out of scope).

## Success metrics

| Metric | Baseline | Target |
|--------|----------|--------|
| Time from `cluster create` to first tenant pod `Running` in its namespace | N/A (feature absent; DIY k3s ≈ hours) | ≤ 10 min |
| Human actions (tenant or operator) needed for a pending-pods load spike to schedule | all manual (`resize` by hand) | 0 — node joins and pod schedules unattended |
| Managed clusters created (adoption; first external demand signal) | 0 | instrument first; any external cluster in the first release window validates demand |
| Tenant credentials that grant cluster-scoped rights | all (today: cluster-admin) | 0 |

## MVP scope — the core journey

> A tenant runs `containarium cluster create demo`, gets a namespace-scoped
> kubeconfig in under 10 minutes, and `kubectl apply`s a Helm-rendered app
> into its namespace. When the app's pods no longer fit, a new worker node —
> a Containarium VM — provisions and joins within minutes and the pods
> schedule, with no action from the tenant or the operator. When load
> drops, the extra node drains and is deleted. The tenant never sees the
> control plane, never SSHes a node, never sees other tenants' namespaces,
> and never files a resize request.

Nodes are **Containarium VMs** (Incus `virtual-machine` instances, the
substrate the `containariumd node` scaffold already targets), not LXC
containers: a kubelet wants its own kernel, and the VM boundary keeps a
tenant's cluster kernel-isolated from the host and from other tenants.
The distribution is assumed to be **k3s** (single binary, conformant,
already proven in-tree by the kubeflow recipe) — validate in
`/architect:design`.

Autoscaling is **inherited, not invented** — per the standing roadmap
position (`docs/product/agent-substrate-roadmap-position.md`): upstream
cluster-autoscaler and VPA are the brains; Containarium implements only
the thin provider seams they are designed to call.

**Story 1 — managed cluster lifecycle.**
As a tenant, I want `containarium cluster {create,list,get,delete}` and
`cluster kubeconfig`, so I get a working namespace in a cluster without
operating one.
**Acceptance criteria:**
- [ ] `cluster create <name>` provisions a platform-managed k3s control
  plane and the tenant's namespace(s); `cluster kubeconfig <name>` emits a
  kubeconfig whose credential is **namespace-scoped and short-lived**
  (minted on demand, never the k3s admin file).
- [ ] With that kubeconfig, `kubectl` can create and manage workloads in
  the tenant's namespace(s) and is denied on every cluster-scoped resource
  (nodes, namespaces, CRDs, ClusterRoles, webhooks, PersistentVolumes).
- [ ] Revoking a tenant's access removes its binding; a new kubeconfig
  must be minted to regain access.
- [ ] The control plane is not tenant-reachable except via the K8s API:
  no SSH route, no box listed in the tenant's `containarium list`.
- [ ] `cluster delete` removes control plane and all worker VMs; a
  re-created cluster of the same name is empty (no state leakage).
- [ ] Proto-first: `ClusterService` RPCs + typed messages land in
  `proto/containarium/v1/`, CLI is a cobra subcommand, MCP tool thin-wraps
  the same client function (per CLAUDE.md conventions).
**Priority:** P0

**Story 2 — worker nodes are Containarium VMs.**
As a tenant, I want my cluster to start with a configured node pool of
Containarium VMs that join automatically, so there is capacity to
schedule onto from minute one. (Tenants do not see node objects; node
health is reported through `cluster status`.)
**Acceptance criteria:**
- [ ] `cluster create --nodes-min N --nodes-max M` provisions N worker
  VMs — drawn from typed node size classes (platform presets, e.g.
  small/medium/large) — that join and become schedulable without manual
  steps, as shown by `cluster status`.
- [ ] Node size classes are typed proto messages (no magic-string
  sizes); the autoscaler may pick among them so a pod larger than the
  small class still schedules (see design doc).
- [ ] A deleted/failed worker VM is detected and replaced (converges
  back to at least `nodes-min`).
- [ ] Worker VMs are internal to the cluster: not SSH-routable as tenant
  boxes, not listed in `containarium list`.
- [ ] Tenant pods never schedule onto the control-plane node.
**Priority:** P0

**Story 3 — node autoscaling (scale up and down).**
As a tenant, I want nodes added when pods are Pending for lack of
resources and removed when idle, so I never size the cluster by hand.
**Acceptance criteria:**
- [ ] Implemented as upstream cluster-autoscaler with a Containarium
  external cloud-provider shim (the `externalgrpc` seam) backed by the
  same VM create/delete used by Story 2 — no bespoke scaling loop. The
  autoscaler authenticates with its own scoped mTLS client credential
  (`clusters:scale`), not a tenant credential.
- [ ] E2E: a deployment scaled beyond current capacity goes from Pending
  to Running via a new node, unattended, within a documented time bound.
- [ ] E2E: after the deployment scales back down, the surplus node is
  cordoned, drained, and its VM deleted within the configured window.
- [ ] Scale-up respects `nodes-max` and the host's existing capacity /
  CPU-admission gates — a full backend rejects the node rather than
  overcommitting silently.
**Priority:** P0

**Story 4 — pod vertical auto-scaling.**
As a tenant, I want per-pod resources to grow automatically when a
workload needs more than it requested, so hand-tuned limits stop being a
ceiling.
**Acceptance criteria:**
- [ ] Implemented as upstream Vertical Pod Autoscaler installed by the
  platform with the cluster; the tenant may create VPA objects in its own
  namespace. In-place pod resize is used where the workload allows it — no
  bespoke resizing loop.
- [ ] E2E: a workload opted in (`cluster` default or per-workload VPA
  object) that sustains load above its request gets its request raised
  without tenant action; the pod is not stuck OOM-killing in a loop.
- [ ] Pod growth beyond node capacity composes with Story 3: the
  resized pod that no longer fits triggers node scale-up, not a
  scheduling deadlock.
**Priority:** P0

**Story 5 — cluster visibility and bounded spend.**
As a tenant (and as the operator), I want `cluster status` to show what
the automation is doing, and hard caps on what it may consume.
**Acceptance criteria:**
- [ ] `cluster status <name>` shows control-plane health, node count vs
  min/max, per-node VM size, and the last scale event with its reason.
- [ ] `nodes-max` and max node VM size are enforced server-side; an
  autoscaler request beyond them is refused and surfaced in `status`,
  not silently clamped.
- [ ] Cluster VMs are labeled/attributed to the owning tenant so the
  operator can answer "what is this VM and why does it exist" from
  `containarium list`-level tooling (operator view, not tenant view).
**Priority:** P0

**Story 6 — namespace isolation and per-namespace limits.**
As a tenant, I want my namespaces to be mine alone and bounded, and as
the operator I want a tenant's workloads unable to affect the cluster or
other tenants.
**Acceptance criteria:**
- [ ] Each tenant namespace gets a platform-applied default-deny
  NetworkPolicy (DNS allowed); the tenant cannot edit it.
- [ ] Each tenant namespace is enforced at Pod Security `restricted`; the
  tenant cannot relax the level.
- [ ] Each tenant namespace has a platform-set ResourceQuota and
  LimitRange (CPU, memory, ephemeral storage, pods, services, PVCs, and
  no LoadBalancer or NodePort services by default). The tenant cannot
  change them.
- [ ] A tenant cannot create namespaces, or Roles and RoleBindings that
  widen its own access.
- [ ] Tenant workloads cannot tolerate or be placed on the control-plane
  node.
**Priority:** P0

## Later phases

- **P1 — managed ingress:** a K8s `Service`/`Ingress` maps onto the
  existing subdomain + TLS routing (`route`, `hosting`) so cluster
  workloads get public URLs the same way apps do. Deferred: the MVP
  journey is provable with `kubectl port-forward`/NodePort, and ingress
  doubles the routing surface to design.
- **P1 — cluster auto-sleep:** an idle cluster's worker pool scales to
  `nodes-min=0` and the control-plane VM sleeps via the existing
  auto-sleep machinery, waking on API/traffic. This is where the two
  "serverless" stories meet; needs the wake path to understand the K8s
  API port.
- **P1 — GPU node pools:** the `containariumd node` GPU/VFIO path is
  partial today; GPU nodes ride on finishing it, plus device-plugin
  install by the platform. High-value (it is the substrate's
  differentiator) but not needed to prove the managed-cluster loop.
- **P2 — in-place node grow:** live-growing an existing node VM
  instead of adding one. Mechanically feasible (VM CPU hotplug +
  grow-only memory; a k3s-agent restart re-registers capacity without
  disturbing running pods), but deferred until the MVP's node size
  classes prove insufficient. Trigger is scheduling pressure bounded by
  the host overcommit gate — never measured VM utilization (see the
  design doc's "Who decides what").
- **P2 — HA control plane, PV/CSI beyond k3s local-path, multi-host
  node placement across pools.**

## Deployment model

- **Managed clusters run on the backend hosts of the owning customer's
  account** (for BYOC, the customer's own hosts), never on the
  box-runtime Kubernetes cluster. Each tenant cluster is a separate k3s
  instance on Incus VMs with its own control plane.
- **One cluster per tenant organisation.** Tenant teams are namespaces
  inside that cluster. Namespace-scoped access applies only within one
  organisation's cluster; it does not make a shared cluster across
  organisations.
- **Container-class nodes are not offered to tenants.** Shared-kernel
  container nodes exist only as an operator-gated option for development
  or single-trust-domain hosts.

## Out of scope

- **A bespoke autoscaler or resizer** — upstream cluster-autoscaler and
  VPA only; Containarium ships provider seams. Contradicting the
  "inherit, don't invent" position note requires re-litigating that
  note, not this PRD.
- **Tenant-installed operators, CRDs, ClusterRoles, webhooks or other
  cluster-wide components.** The platform curates cluster-wide add-ons
  (VPA is the first). A CRD plus a webhook is cluster-admin by another
  route, so tenants do not get either.
- **Cluster-admin access for tenants,** including a kubeconfig carrying
  the k3s admin credential.
- **Shared multi-tenant clusters across organisations** (many
  organisations, one control plane) — one cluster per organisation.
  Hard multi-tenancy inside one K8s control plane is its own security
  product; the per-tenant-VM boundary is exactly what we already know how
  to isolate.
- **Replacing or merging with the K8s box backend** (`pkg/core/box/k8s/`)
  — that lane puts boxes on a customer's cluster; this one hosts
  clusters. Different directions, both stay.
- **Request-driven scale (Knative-style per-request activation)** — not
  offered to tenants, since it needs cluster-wide components. A later
  product decision once real clusters exist, delivered as a platform
  add-on.
- **Per-request metering / billing** — no billing machinery exists to
  hook into; bounded spend is handled by Story 5's hard caps.
- **Windows nodes, service meshes, cluster marketplace/add-ons
  installed by tenants.**

## Open questions & assumptions

- **Assumption (evidence gap):** demand is inferred from the kubeflow
  recipe's DIY-k3s design and issue #857, not from external user asks.
  The adoption metric above is deliberately the validation instrument;
  if the first release window shows zero external clusters, later
  phases don't get scheduled.
- **Assumption:** k3s as the distribution. Validate in
  `/architect:design` (vs. k0s/kubeadm) — the deciding criteria are
  single-binary node images, upgrade story, and conformance.
- **Assumption:** in-place pod resize + VPA in-place mode are mature
  enough on the chosen K8s version for Story 4; if not, Story 4's
  fallback is VPA recreate-mode (pods restart on resize) — degraded but
  still "no hand-tuning".
- **Decided:** VM capability is a hard requirement to create a tenant
  cluster. Container-class nodes are operator-only (see Deployment model).
- **Open:** node VM provisioning path — extend the `containariumd node`
  scaffold (whose CPU path exists, deliberately CLI-only/no-proto) or a
  new internal provisioner behind `ClusterService`? The node scaffold's
  no-proto stance conflicts with cluster nodes being API-managed
  objects. For `/architect:design`.
- **Open:** where control-plane VMs live — same backend host as the
  node pool (simple, fate-shares) or platform-core placement (survives
  node-host loss)? Affects the HA story's starting point.
- **Open:** relationship to #857's fleet autoscaler — that issue scales
  Containarium's *own* fleet using someone's K8s; this PRD scales a
  *tenant's* K8s using Containarium VMs. The cluster-autoscaler provider
  shim may be shareable machinery; confirm before scheduling either.
- **Open:** existing clusters that were issued cluster-admin kubeconfigs —
  rotate them when this ships, or leave them until they expire. Blocks the
  rollout plan, not the design.
- **Open (for design):** tenant credential lifetime (proposed 1–24 h,
  re-minted through the CLI); whether a tenant may request more than the
  default namespace; and the default quota values per namespace.
