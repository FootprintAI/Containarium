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
plane, one tenancy model, one audit trail, one identity surface, across
both. A customer with a cluster *and* a GPU box under a desk gets one
platform. Nobody else in that table can say it.

## The uncomfortable open question

Our stated differentiators — per-tenant eBPF egress policy
(`internal/netbpf`), audit-to-Postgres, scope-gated JWTs, KMS — are
described in `docs/AGENT-SKILLS-CREWS-DESIGN.md` as "the trust fabric,
and that is the moat." Almost all of it is **LXC-path-native**. On the
K8s path, eBPF policy becomes NetworkPolicy, which agent-sandbox
already does default-deny.

So the barbell only holds if the trust fabric genuinely ports to K8s.
If it doesn't, the two tracks aren't one product with two backends —
they're two products, and the "one control plane" claim is marketing
rather than architecture. **I don't currently know which it is, and I
think that's the highest-value thing to find out before committing the
roadmap.** It's a day or two of reading `internal/netbpf` and the K8s
box path side by side, not a quarter of work.

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
