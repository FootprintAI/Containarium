# Security FAQ

Straight answers to the questions security-conscious operators ask
before adopting Containarium. If a claim here turns out to be wrong
or stale, please open an issue — this doc is meant to be checked
against, not just read.

## Does Containarium isolate tenants with a hypervisor, like a microVM
## platform (Firecracker/KVM) or Xen?

No. Containarium runs tenant workloads as Incus/LXC **system
containers** — namespaces and cgroups on a shared host kernel, not
hardware-virtualized guests. There is no VT-x/AMD-V ring transition
between a tenant workload and the host, and no separate guest kernel.

This is a real, structural difference from KVM- or Xen-based
isolation, not a matter of degree. Be skeptical of any vendor
(including us) who describes container isolation as "hypervisor-grade"
— it isn't, and claiming otherwise misstates where your trust
boundary actually sits.

## So what stops one tenant from reaching another, or from reaching
## the host?

Defense-in-depth on top of the shared kernel, not a hardware
boundary:

- **Linux namespaces/cgroups** (via Incus) — process, mount, network,
  and user-ID isolation per container.
- **eBPF network policy** — a `TC_INGRESS` program on each container's
  host-side veth enforcing deny-by-default egress (CIDR + domain
  allowlists), with denied flows audit-logged. See
  [`NETWORK-ISOLATION-DESIGN.md`](NETWORK-ISOLATION-DESIGN.md).
- **Per-RPC RBAC + OAuth2-style scopes**, short-lived tokens with
  single-use refresh rotation, and a JWT revocation list at the
  control-plane layer (see [`SECURITY.md`](../../SECURITY.md) audit
  history).
- **Per-tenant secrets** encrypted at rest with an operator-held
  master key.

Each of these narrows the blast radius of a compromised tenant. None
of them stop a host-kernel local-privilege-escalation exploit from
reaching every other tenant on the same backend — that's the honest
cost of the shared-kernel model.

## What's the actual threat model this is good for?

Trusted-to-semi-trusted multi-tenancy: your own team's dev/agent
sandboxes, internal multi-project environments, customers you have a
support relationship with (not fully anonymous adversarial signup).
It is a good fit when tenants are expected to misbehave accidentally
(bad code, runaway processes, misconfigured egress) but are not
actively trying to break out of the box.

It is **not** the right architecture for hostile multi-tenant SaaS
where any anonymous signup could be running a kernel 0-day, or for
workloads whose compliance regime specifically mandates
hardware-enforced isolation between tenants. If that's your
requirement, a KVM- or Xen-based platform is the honest answer, not
Containarium — see our published policy on this trade-off in
[`SECURITY.md`](../../SECURITY.md#out-of-scope): shell access to a
daemon host is explicitly out of scope for our vulnerability program,
because root on the host owns everything.

## Does this apply to the Containarium Cloud offering too?

Yes. Cloud's compute plane actuates onto this same OSS Incus/LXC
substrate — it doesn't run on a different, more isolated backend.
Everything above about the shared-kernel trust boundary applies to
Cloud exactly as it applies to a self-hosted deployment.

Today, Cloud's free / self-serve tier accepts signup via email or
OAuth with no card or identity verification. That is precisely the
"anonymous signup" case called out above as a bad fit for
shared-kernel isolation with no further compensating control. The
defense-in-depth layers described earlier (eBPF deny-by-default
egress, per-tenant RBAC, encrypted secrets, security scanning) reduce
blast radius and east-west exposure, but none of them stop a
host-kernel privilege-escalation exploit from a signed-up tenant who
is actively trying to break out.

We're calling this out as an open gap rather than papering over it.
Directions being weighed: gating free-tier signup (card/identity
verification), capping free-tier capability (compute limits, shorter
TTL, tighter default egress), and/or a stronger per-tenant isolation
option (e.g. a VM-backed instance type) reserved for unvetted,
capability-bearing compute. Until one of those lands, the free tier
should be treated as carrying the same "not hardened against a
determined anonymous tenant" caveat as the OSS answer above — not a
weaker one, and not a stronger one.

## Why not just add a VM-backed instance type?

Incus supports QEMU/KVM VMs alongside containers, so it's
architecturally reachable — it isn't built today. If your workload
needs hardware-enforced isolation, treat that as a real gap to raise
with us (or track upstream), not something the current eBPF/RBAC
layering papers over.

## If isolation is weaker than a hypervisor, why choose Containarium?

Because isolation strength is one axis among several, and the
shared-kernel model buys back real things a hypervisor boundary
costs you:

- **Native GPU passthrough** without a vendor-validated hypervisor
  GPU driver stack.
- **Persistent, long-lived boxes** instead of ephemeral microVM
  sandboxes that reset state on every run.
- **Self-host under Apache 2.0** — you own the isolation boundary and
  its operational cost, rather than trusting it to a vendor's
  hypervisor fleet.
- Lower operational and cost overhead than running a per-tenant
  hypervisor at density.

Pick Containarium because those trade-offs match your workload, not
because a sales page told you the isolation is stronger than it is.

## Where do I go for the operational detail?

- [`SECURITY.md`](../../SECURITY.md) — vulnerability reporting,
  supported versions, out-of-scope items, audit history.
- [`OPERATOR-SECURITY-RUNBOOK.md`](OPERATOR-SECURITY-RUNBOOK.md) —
  day-to-day operator procedures (token rotation, leak response,
  per-tenant network policy).
- [`NETWORK-ISOLATION-DESIGN.md`](NETWORK-ISOLATION-DESIGN.md) — the
  eBPF network policy design, including its own "Honest tradeoffs"
  and "What this is NOT" sections.
- [`ZERO-TRUST-AUDIT.md`](ZERO-TRUST-AUDIT.md) — the original
  zero-trust audit and remediation tracking.
