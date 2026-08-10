# Roadmap position — the agent substrate is consolidating on Kubernetes

**Date:** 2026-08-06
**Status:** thinking-out-loud / not a commitment
**Context:** written off the back of [`docs/AX-COMPARISON.md`](../AX-COMPARISON.md)

This is a roadmap *position* note, not a PRD. It argues one thing: the
open-source agent-infrastructure field is consolidating on Kubernetes
as the orchestration layer, we are the only serious project that is
substrate-agnostic by construction, and that is currently an unpriced
asset — we pay the tax of two backends without collecting the premium.

## The observation, sharpened

The loose version — "everyone is building on K8s" — is directionally
right but blurs two different layers that are moving independently.

**Orchestration is consolidating on K8s.** The
`kubernetes-sigs/agent-sandbox` CRD has become the de-facto object for
"isolated, stateful, singleton agent workload." Google's whole
three-layer stack (Agent Sandbox → Agent Substrate → AX) sits on it.
Beam and Daytona deploy into K8s. We do too — `pkg/core/box/k8s/sandbox.go`
imports `sigs.k8s.io/agent-sandbox/api/v1beta1`. Four independent
projects, one object model.

**Isolation is *not* consolidating — it's bifurcating.** The real
competitive axis underneath is the strength of the boundary:

| Tier | Boundary | Who |
|---|---|---|
| Shared kernel | namespaces + LSM | **Containarium (LXC default)**, Daytona (Docker) |
| Userspace kernel | gVisor / `runsc` | Modal; Agent Sandbox native; **our K8s path, opt-in** |
| Guest kernel, VM | Kata | Agent Sandbox pluggable |
| Guest kernel, microVM | Firecracker | E2B, CubeSandbox |

E2B — the category's mindshare leader — is Firecracker on
Nomad/Consul, not K8s at all. So the honest read is: **K8s is winning
the scheduling argument, not the isolation argument.** Those are
separable bets and we should stop treating them as one.

## Where that leaves us

We are the only project in that table that runs the *same box
vocabulary* over two substrates: unprivileged LXC on bare hosts, and
the agent-sandbox CRD on K8s, behind one `--runtime` flag. Nobody else
has that seam. Today we treat it as an implementation detail. It is
closer to being the product.

But it cuts both ways, and the roadmap has to pick:

**The cost of *not* leaning into K8s.** Everything the ecosystem builds
— pod snapshots, warm pools, gVisor-by-default, Substrate's actor
density, and AX's event log — lands on the K8s path for free. Every
quarter we treat K8s as the secondary backend, we hand-build on LXC
what the CRD gives away, and the two paths' capability sets diverge
further. `docs/EPHEMERAL-SANDBOX-DESIGN.md` is exactly this: a design
for warm pools and fast-start sandboxes that is *unbuilt on LXC* and
largely *already solved upstream on K8s*.

**The cost of chasing K8s.** All of it requires the customer to have a
cluster. Our actual installed base — BYOC bare metal, a GPU node under
someone's desk, an SSH-native dev box a human lives in for a month —
mostly doesn't, and won't. AX is simply not an option for them, and
that is a real, defensible market that the whole field has walked away
from. If we make K8s primary, we become a worse-funded Agent Substrate.

## The position I'd argue for: an explicit barbell, with the box as the contract

Not a hedge — a deliberate split with different jobs and, importantly,
an explicit list of things we stop building.

**K8s track — inherit, don't invent.** Treat the ecosystem as our R&D
department. When agent-sandbox ships snapshotting, warm pools, or
Kata, we consume it rather than reimplement it. Concretely: make
gVisor the *default* RuntimeClass on the K8s path rather than opt-in
(`podOptions.RuntimeClass` already carries it, unset by default), and
wire suspend/resume through `SandboxOperatingMode` — which
`sandbox.go:125` already uses for autostart — instead of the cold
stop/start `auto_sleep` does today.

**LXC track — own the substrate nobody else serves.** Bare host, no
cluster, GPU passthrough, SSH-native, BYOC. Stop trying to reach
feature parity with the K8s path on things K8s gives away for free.
Specifically: I would *not* build MicroVM-grade isolation or
RAM-snapshot fast resume on the LXC path. That is a losing race against
Firecracker and against the CRD simultaneously.

**The seam is the moat.** The value we alone can claim: one control
plane, one tenancy model, one identity surface, across both. A customer
with a cluster *and* a GPU box under a desk gets one platform. Nobody
else in that table can say it. (Note "one audit trail" is deliberately
absent from that list — see below.)

## The formerly-open question: does the trust fabric port to K8s?

> **Answered 2026-08-07** by reading `internal/netbpf`, `internal/audit`,
> `internal/auth`, the secrets path, and `pkg/core/box/k8s/` side by side.
> This section previously said the answer was unknown and was the
> highest-value thing to find out. It is now known.

**Partially — and the split is clean: control plane ports, data plane
does not.**

### Ports (backend-agnostic by construction)

| Primitive | Why it ports |
| --- | --- |
| Scope-gated JWTs | 101 `RequireScope` call sites; `internal/auth` has no backend import. Enforced before dispatch. |
| API-level audit | Invoked at the gRPC handler layer (`container_server.go`, `agent_server.go`); `internal/audit` core is backend-neutral. |
| Secrets / KMS **at rest** | `pkg/core/secrets` imports no incus. Envelope encryption, KMS, audit-on-read all portable. |

### Does not port (incus-typed, not config-gated)

| Gap | Evidence |
| --- | --- |
| **eBPF network policy** | `NetworkPolicyEnforcer`'s inspector is `ListContainers() ([]incus.ContainerInfo, error)`; it resolves container-name → host veth ifindex and attaches TCX. Constructed with `networkIncusClient` (`dual_server.go:1303`). No K8s branch exists. |
| **Tenant secret delivery** | `incus config set environment.<NAME>=…`, reconciler holds `*incus.Client`. The K8s backend mounts Secrets only for authorized_keys and host keys. |

These are **type-level** dependencies on `pkg/core/incus`, not feature
flags. They cannot be switched on for K8s; they'd have to be rebuilt
against a K8s-native mechanism.

### What K8s has instead

Not nothing: `objects.go:221` creates a per-tenant-namespace
`default-deny` NetworkPolicy — ingress SSH-only, egress DNS-only. That's
a credible floor. But it is **static**, written once at box-create and
never driven by `NetworkPolicyService`. So the per-tenant egress
allowlist, virtual-patch deny rules (#660), and traffic-flow accounting
(#627) have no K8s expression at all.

### What this means for the barbell

The barbell holds, but the claim needs narrowing: **one product with two
backends at the control plane; two products at the data plane.** "One
control plane, one tenancy model, one identity surface" is accurate.
"One audit trail" is not — it is true for API calls and false for
in-box sessions. Marketing and the sales pitch should say the narrower
thing.

The asymmetry favours us more than expected: the *hard* part — identity,
authz, secrets-at-rest — is already portable. What doesn't port is
enforcement *mechanism*, which is exactly where K8s has its own native
idiom to bind to rather than reimplement. That is the "inherit, don't
invent" posture this note already argues for, so the gaps are consistent
with the strategy rather than a refutation of it.

Gaps tracked as #1188 (policy-driven K8s NetworkPolicy) and #1190 (tenant
secret delivery on K8s).

#1189 (in-box session audit on K8s) is addressed: the collector now reads
sessions through a backend-neutral source — OpenSSH `auth.log` on LXC,
box pod logs on Kubernetes — and both land in the same store under the
same action. It is listed here as the worked example of what porting one
of these gaps costs: a parser for the other backend's log format, a
source interface, and the wiring to choose between them. The type-level
dependency was the whole of the problem, and it was three PRs of work,
not a redesign.

## What this note deliberately does not say

- It doesn't propose we adopt AX. We'd be handing our Layer 3 to a
  project in "active early development" with breaking changes promised,
  in exchange for an event log we could build ourselves. **Settled
  2026-08-07:** a spike ([`AX-HARNESS-ADAPTER-SPIKE.md`](../AX-HARNESS-ADAPTER-SPIKE.md))
  returned NO-GO — AX never replays history to a harness, and resuming an
  interrupted execution is a TODO upstream, so adopting it would add state to
  our side rather than remove it.
- It doesn't propose we drop LXC. That's where the customers are.
- It doesn't resolve durability. That gap (`crew_run_store.go`,
  `agent_task_queue.go` — both in-memory, both flagged in their own
  comments) is a defect on its own terms and should be fixed regardless
  of which substrate wins. It is not a strategic question.

## Sources

- [`docs/AX-COMPARISON.md`](../AX-COMPARISON.md) — the underlying comparison
- [Agent Sandbox on GKE + Agent Substrate](https://cloud.google.com/blog/products/containers-kubernetes/bringing-you-agent-sandbox-on-gke-and-agent-substrate) (2026-05-21)
- [Comparing AI agent sandbox platforms](https://blog.logrocket.com/comparing-ai-agent-sandbox-platforms-e2b-modal-daytona-and-more/) — LogRocket
- [awesome-sandbox](https://github.com/restyler/awesome-sandbox) — field survey
