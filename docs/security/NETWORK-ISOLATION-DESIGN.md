# Network Isolation — Design Note

> Status: **Exploration / not yet approved.** Filed in response to
> the CubeSandbox comparison ([readme](https://github.com/TencentCloud/CubeSandbox))
> — their CubeVS (eBPF-based virtual switch) closes a gap
> Containarium's zero-trust audit didn't flag: container-to-container
> reachability on a shared bridge.

## Where we are today

Containarium creates containers on an Incus-managed bridge
(default: `incusbr0`), one bridge per backend VM. Every container
on a backend has an IP on that subnet (typically `10.0.3.0/24`).

The egress path:

- Outbound from a container goes through the bridge, through the
  host's iptables NAT, out the host's default route. No
  per-container egress policy.
- Inbound from outside the backend lands on Caddy / sshpiper on the
  sentinel and is reverse-proxied to the right container by hostname
  / port. Caddy is the only inbound path from the public internet.

The container-to-container path:

- **Any container on the same backend can reach any other container
  on the same backend.** `ping bob-container.lxd` works from
  `alice-container` if both share the bridge.
- **Cross-backend** container-to-container is currently blocked
  because backend VMs don't gossip — each backend's bridge is an
  island.

This is **adequate for the current "trusted dev box" workload**
(alice and bob are colleagues, both run their own code, neither has
incentive to scan the other). It is **inadequate** for any threat
model that includes a malicious tenant or a tenant whose container
is compromised — there's no kernel-level fence stopping
`alice-container` from scanning `bob-container:5432` for an open
Postgres port.

## Threat model

| Threat | Mitigated today? |
| --- | --- |
| Cross-tenant network probe / port scan | **No.** Same-backend bridge is wide open. |
| Cross-tenant connection (e.g. alice → bob's Postgres) | **No.** |
| Container-to-internet exfil to attacker-controlled domain | **No.** No egress allowlist; ClamAV catches files-at-rest, not network exfil. |
| Container-to-host metadata-service abuse (cloud) | **Partial.** Cloud metadata server filtering is host-firewall-dependent; Containarium doesn't enforce. |
| Container forging source IP / MAC | Partial. Incus default profile restricts MAC; no IP-source-spoof check on the bridge. |
| Inbound from outside the backend | **Mitigated.** Caddy + sshpiper are the only ingress; everything else is dropped at the cloud firewall. |

The first three rows are the gap eBPF closes.

## Goal

Per-tenant network policy enforced at the **bridge data path**, not
at the application:

1. **Deny-by-default** container-to-container reachability on a
   backend. Cross-container traffic only flows through explicitly
   allowed routes.
2. **Operator-defined egress allowlist** per tenant — DNS-resolvable
   domain or CIDR-style IP allowlist; default is "no outbound except
   to the platform's own DNS + apt mirrors + the operator's
   declared list."
3. **Cloud metadata-service block** by default. Containers shouldn't
   reach `169.254.169.254` unless the operator explicitly opts in.
4. **Observable** — every denied flow logs a structured event so
   operators can investigate either a misconfigured allowlist or an
   actual exfil attempt.

## Prior art

- **Cilium** — production-grade eBPF networking for k8s. Far more
  than we need (full CNI, BPF dataplane replacing iptables); not
  designed for non-k8s use.
- **Tetragon** — Cilium's observability sibling. eBPF-attached
  process / network event tracing. Useful for the "log denied flow"
  half.
- **bpfilter / nftables-bpf** — kernel-level packet filtering with
  BPF. Less ecosystem, more raw control.
- **CubeSandbox CubeVS** — purpose-built for sandbox-to-sandbox
  isolation. Their architecture doc would be the right reference.

Containarium isn't k8s and shouldn't pull Cilium. The right shape is
**a small set of tc-bpf programs attached at each container's
host-side veth in `TC_INGRESS`** that implement the policy from a
per-tenant rule set the daemon maintains.

## Phase 0 validation findings — the attach point (#315)

Phase 0 ran on a real backend (Ubuntu 24.04, kernel 6.8, Incus 6.23) and
**ruled out the obvious `incusbr0` attach point.** Two on-hardware runs:

- **Bridge master (`incusbr0`), `TC_INGRESS` + `TC_EGRESS`** — on an A→B ping
  the ingress counter incremented but **egress stayed 0**: a Linux bridge
  forwards frames between ports without them traversing the bridge device's
  tc-egress hook.
- **Per-container host veth, `TC_INGRESS` + `TC_EGRESS`** — A's veth *ingress*
  saw A's outbound; A's veth *egress* stayed 0 even though B's **5/5** replies
  flowed (they were counted at **B's** veth ingress). So bridge-forwarded
  *inbound* bypasses the destination veth's tc-egress too.

**Conclusion:** `TC_EGRESS` on bridge / bridge-slave devices is not a reliable
hook for inter-container traffic. The reliable, sufficient point is
**`TC_INGRESS` on each container's host veth** — it sees that container's
*entire* outbound, which is the **sender side of every flow**. Therefore:

- **Observation** = the union of every container's veth-ingress hook (each flow
  counted once, at its sender).
- **Enforcement** = a container's egress policy is enforced at *its* veth
  ingress; to block Y→X you drop at **Y's** veth ingress. All enforcement lives
  at the sender's veth ingress — no egress hook needed.

The Phase 0 / 0.5 harnesses (`experimental/ebpf-phase0/validate.sh`,
`validate-veth.sh`) reproduce both results.

## Architecture sketch

```
                  Tenant config (CONTAINARIUM_*_POLICY env / DB)
                            │
                            v
                  ┌──────────────────────────────┐
                  │  containarium daemon         │
                  │   policy compiler            │
                  │   (rules → BPF maps)         │
                  └──────────────────────────────┘
                            │
                            │ bpf(MAP_UPDATE_ELEM)
                            v
                  ┌──────────────────────────────┐
                  │  BPF maps in kernel          │
                  │   ├── allow_egress_cidr      │
                  │   ├── allow_egress_domain    │
                  │   └── allow_intra_tenant     │
                  └──────────────────────────────┘
                            ▲
                            │ tc-bpf (TC_INGRESS) on each
                            │ container's host veth
         container veths ───┴──── tenant containers (enslaved to incusbr0)
                            │
                            v
                  ┌──────────────────────────────┐
                  │  bpf_perf_event_output       │
                  │   denied-flow log            │  ──> daemon collects
                  └──────────────────────────────┘     ──> audit log row
```

### Pieces to build

1. **Policy data model** — `NetworkPolicy { tenant, allow_intra_tenant: bool, egress_cidrs: [CIDR], egress_domains: [string] }`. Proto-first per the
   project convention.
2. **BPF programs** — small tc-bpf programs (~200-400 LOC C or Rust)
   attached to **each container's host-side veth in TC_INGRESS** (the
   point where the container's outbound packets enter the host stack;
   see the Phase 0 findings — bridge/veth TC_EGRESS doesn't observe
   bridge-forwarded traffic, so all enforcement is at the sender's veth
   ingress). Lookup src/dst against BPF maps; pass on allow, drop +
   perf_event on deny.
2a. **Veth discovery + lifecycle** — resolve each container's host veth
   (Incus exposes it as `volatile.eth0.host_name`; fall back to mapping
   the container's `eth0` `iflink` to a host interface) and (de)attach
   the program as containers come and go. New attach point vs. a single
   bridge program: one program instance per container veth.
3. **Map-update plumbing in the daemon** — Go side uses
   `github.com/cilium/ebpf` (popular, well-maintained, no Cilium
   runtime dependency) to load programs and update maps.
4. **DNS resolver hook** — for `egress_domains`, periodically resolve
   to current IPs and populate the CIDR map. Short TTL respect.
5. **Denied-flow consumer** — daemon reads BPF perf_event ring,
   writes structured rows to the audit log (`action=net_deny`,
   `detail={src, dst, proto}`).
6. **CLI / MCP surface** — `containarium network policy {get, set,
   list}`; MCP `set_network_policy` scoped `network:write`.
7. **Operator runbook section** — how to author a policy, how to
   audit denied flows, how to test in dry-run.

## Phased rollout

| Phase | Scope | Bound |
| --- | --- | --- |
| **0 — discovery** | ✅ **Done.** Threw a tc-bpf counter at a real backend (kernel 6.8 / Incus 6.23). Outcome: the bridge is the *wrong* attach point (TC_EGRESS on bridge/veth doesn't see forwarded traffic) — corrected to **per-container veth TC_INGRESS** (see "Phase 0 validation findings" above). | done |
| **A — observation only** | ✅ **Done.** BPF program + map-update plumbing landed in `log_only` mode; every would-deny flow generates an audit row (`network_policy.deny`) but no packets are dropped. Control plane: `NetworkPolicyService` CRUD + CLI + Postgres persistence. Data plane: per-veth `TC_INGRESS` program, the `cilium/ebpf` loader, a stable tenant→u32 ID registry, and a daemon enforcer that reconciles stored policies + live containers into the BPF maps and audits denied flows. **OFF by default** — the daemon only starts the enforcer when `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` points at a compiled `netpolicy.bpf.o`; the loader was hardware-validated on a Linux backend (kernel 6.8). | 2 weeks |
| **B — policy enforcement** | Flip from log-only to drop on a per-tenant `CONTAINARIUM_ENFORCE_NETWORK_POLICY=true`. Default off until ≥1 production tenant has soaked it. | 1 week |
| **C — egress allowlist** | Domain → CIDR resolver + DNS-TTL refresh loop. Egress now constrainable to a list. | 1 week |
| **D — cloud metadata block** | Default-deny on `169.254.169.254/32` unless the tenant opts in. | 2 days |
| **E — CLI / MCP / runbook** | Operator surface + docs. | 1 week |

Total bounded estimate: **5-6 weeks** of focused work. Phase 0 was
the load-bearing risk and it paid off: the bridge attach point the
design originally assumed does **not** work for inter-container
traffic, so Phase A starts from the corrected per-container-veth
`TC_INGRESS` model above rather than discovering that mid-build.

## Honest tradeoffs

- **Kernel-version sensitivity.** tc-bpf with the features we want
  (BPF_MAP_TYPE_LPM_TRIE for CIDR matching, perf_event output) needs
  Linux ≥ 5.4. Ubuntu 24.04 is fine; the production-runbook needs
  to call out the floor.
- **Debuggability cost.** "Why doesn't my container reach X" becomes
  a multi-layer question (cloud firewall, host iptables, BPF
  policy). The denied-flow audit log is the load-bearing
  investigation tool; if it's not good enough operators will just
  flip enforcement off.
- **Performance.** tc-bpf adds per-packet latency. On a single-NIC
  small instance the overhead is <5%; on a high-throughput
  workload it's more. Phase 0 should measure rather than guess.
- **Doesn't help cross-backend.** The BPF programs are
  per-bridge / per-backend. Cross-backend isolation is already
  there (separate VMs, no inter-backend gossip), so this is mostly
  fine; the daemon's RPC-over-mTLS path is the cross-backend
  connection and stays as-is.
- **Doesn't replace Caddy / sshpiper.** Inbound from the public
  internet stays through the sentinel; this design is purely about
  what happens once a packet is inside a backend.

## Open questions

- **Per-container vs per-tenant policy.** Probably per-tenant
  (matches the existing authz model: tenant owns N containers, all
  on the same backend). Per-container would be more flexible but
  adds a level of nesting operators wouldn't use.
- **Dry-run mode in production.** "Log but don't drop" should
  probably stay available indefinitely — operators rolling out a
  new allowlist want to see what would break before flipping
  enforce. CONTAINARIUM_NETWORK_POLICY_MODE = `off | log | enforce`.
- **Service discovery within a tenant.** If alice has a webapp
  container and a postgres container, she wants webapp → postgres
  to work. The `allow_intra_tenant` flag covers the broad case;
  per-port allowlist within tenant is a v2.
- **eBPF program signing.** Future kernel hardening may require
  signed BPF programs. Land the build-pipeline scaffold now even if
  signing isn't yet enforced.

## Decision log

- **tc-bpf on the bridge, not on container veth.** Bridge attach is
  one program per backend, not one per container. Scales with
  number of backends, not number of containers.
- **`github.com/cilium/ebpf` for the Go side, not bpf2go from
  scratch.** Mature library, no Cilium-runtime dependency, common
  in production Go projects.
- **Audit log is the policy-decision sink.** Reuses the SHA-256
  hash-chained audit log shipped in Phase 4.5; no separate event
  pipeline.
- **Default OFF.** Same opt-in stance as the rest of the zero-trust
  rollouts (KMS, image digest verify). No upgrade can degrade an
  existing deployment.

## What this is NOT

- A k8s NetworkPolicy implementation. Different threat model
  (multi-tenant SaaS, not multi-namespace inside one trust
  boundary).
- A CNI plugin. Incus owns the network; we attach to the bridge.
- A firewall replacement for the cloud-edge filter. The cloud
  firewall stays the perimeter; this is the per-tenant interior.

## Related

- [`security/OPERATOR-SECURITY-RUNBOOK.md`](OPERATOR-SECURITY-RUNBOOK.md) — operator-facing security ops; will get a "Pinning per-tenant network policy" section when this lands.
- [`security/ZERO-TRUST-AUDIT.md`](ZERO-TRUST-AUDIT.md) — original audit; didn't flag this gap, would be amended on landing.
- [`../EPHEMERAL-SANDBOX-DESIGN.md`](../EPHEMERAL-SANDBOX-DESIGN.md) — answers "what network does a sandbox get" (probably: tenant netns; this design covers what that netns can reach).
