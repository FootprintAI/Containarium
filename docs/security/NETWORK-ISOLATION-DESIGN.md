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
| **B — policy enforcement** | ✅ **Done.** A tenant's `--mode enforce` policy now drops denied flows (`TC_ACT_SHOT`). Gated by a daemon-wide second opt-in `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` — without it, even a stored enforce policy stays observation-only (soak in log_only first). No-policy containers are never enforced, so the blast radius is exactly the tenants with an explicit enforce policy; the reconcile loop converges the egress allow-list (removed CIDRs are deleted, not just added). Hardware-validated: allow-listed dst passes, denied dst sees 100% loss, other tenants stay log_only. | 1 week |
| **C — egress allowlist (domains)** | ✅ **Done.** `egress_domains` (e.g. `api.github.com`) are resolved to IPv4 and folded into the egress allow-list as /32 entries, refreshed on a loop; the reconcile's `diffEgress` prunes IPs a domain stops resolving to. A failed lookup keeps the prior IPs (no allow-list thrash on a DNS blip). Fixed refresh interval for now; per-record DNS-TTL refresh is a noted follow-up. Hardware-validated: with only `--allow-domain one.one.one.one` under enforce, `ping 1.1.1.1` (resolved) passes and `ping 8.8.8.8` is dropped. | 1 week |
| **D — cloud metadata block** | ✅ **Done.** `169.254.169.254` is denied by default — checked *before* the egress allow-list so even a broad `0.0.0.0/0` allow can't expose it (deny-beats-allow for the credential-bearing metadata IP). A per-tenant `allow_metadata` opt-in (proto + CLI `--allow-metadata`) lets a tenant that legitimately needs it through. Hardware-validated: under enforce + `--allow-cidr 0.0.0.0/0`, metadata is dropped while `8.8.8.8` passes; with `--allow-metadata` it passes. | 2 days |
| **E — CLI / MCP / runbook** | ✅ **Done.** `containarium network-policy set/get/list/delete` (the MCP server wraps the same REST endpoints for free); operator runbook section "[Pinning per-tenant network policy](OPERATOR-SECURITY-RUNBOOK.md#pinning-per-tenant-network-policy)" covers the two opt-ins, the soak→arm workflow, the DNS footgun, reading deny audit rows, and metadata opt-in. | 1 week |

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

## Cloud extension

> Status: **Forward-looking.** The single-tenant feature (Phases 0–E) is
> implemented and hardware-validated. This section records how it extends to the
> multi-tenant cloud once the cloud-actuation client lands. It is the integration
> contract, not yet built.

The companion `CLOUD-ACTUATION-CLIENT-DESIGN.md` (in review) adds a daemon mode
where a cloud control plane pushes *desired-state* container assignments to a
registered host; the host reconciles them into Incus and reports observed state
back. Multiple **customers' (orgs')** containers then run on one host fleet.

### Reconciliation with the cloud's existing isolation model

The cloud already has a network-isolation design, and it is **not** this one.
`Containarium-cloud`'s `prd/cloud/data-isolation.md` defines a seven-layer
defense-in-depth model; **Layer 4 (network isolation) is per-org Linux bridges** —
each org gets its own bridge, per-container veths land only on the owning org's
bridge, and there is no cross-bridge routing inside the host. Cross-org L2/L3
lateral movement is therefore owned by **bridge topology** (designed + a CI
breach sentry built, `cmd/isolation-sentry`, cloud #191), not by eBPF. This
design's `allow_intra_tenant` / `ip_tenant` cross-tenant machinery is redundant
there — on a per-org bridge every peer is already same-org by construction.

What per-org bridges do **not** provide — and what `data-isolation.md` explicitly
scopes *out* ("egress filtering … belongs elsewhere") — is the rest of this
design: an **egress allow-list (CIDR + domain), cloud-metadata default-deny, and
per-flow deny observability**. No cloud mechanism owns that today. **That is
eBPF's role on the cloud:** the per-veth egress + metadata + audit layer that
sits *on top of* per-org bridges, not a replacement for them. On a real cloud
instance the metadata block is load-bearing — `169.254.169.254` hands out the
host's cloud credentials.

So the cloud posture is: **bridges for cross-org, eBPF for egress.** A
multi-customer host runs the enforcer armed (`enforce` mode) with each org's
egress policy; cross-org isolation continues to come from Layer 4.

### The blocker: tenant identity is name-derived

The enforcer derives a container's tenant from its **name** — `tenantOf()` strips
the `<tenant>-container` suffix, and a name that doesn't match is **skipped
entirely** (no policy, no veth attach). The cloud-actuation design proposes
naming cloud-assigned containers `cld-<short-uuid>` so they don't collide with
operator-managed `alice-container` names.

Consequence: **cloud-assigned containers would get no egress policy** —
`tenantOf("cld-1a2b3c")` returns `""`, the enforcer skips them, so they reach the
internet (and the metadata service) unrestricted. (Cross-org reachability is
still blocked by the per-org bridge — that's Layer 4 — but egress is wide open.)
Closing this is a prerequisite for applying egress policy to any cloud container.

### Integration points

1. **Decouple tenant identity from the container name.** ✅ **Done** (the
   enforcer's `gather()` reads `incus.ContainerInfo.Tenant` from the
   `user.containarium.tenant` label, falling back to the `<tenant>-container`
   name). What's still missing is the **writer**: the actuation `Assignment`
   proto carries no `org_id` today (only `container_id`, `name`, `image`,
   resources, `desired_state`), so the reconciler has nothing to stamp the label
   *from* yet. Cloud-side prerequisite: add `org_id` to `Assignment`, then the
   reconciler sets `user.containarium.tenant=<org_id>` on each `cld-<uuid>`
   container at create.

2. **NetworkPolicy becomes cloud desired-state, not just local CLI.** Today a
   policy is authored via `containarium network-policy set` into the host's
   Postgres. In the cloud the egress policy is the control plane's concern, so it
   should ride the actuation channel — but the `Assignment` message has **no
   network-policy field today** (it's container-spec only). Cloud-side
   prerequisite: a `NetworkPolicy` (or egress-allowlist) message on the
   assignment/desired-state contract; the OSS reconciler then writes it into the
   local `NetworkPolicyStore` and the existing enforcer reconcile loop applies it
   unchanged — same desired/observed split the actuation client already uses for
   containers. Proto-first, lands in `Containarium-cloud` before the OSS client
   consumes it.

3. **Default to enforce, deny-by-default, on cloud hosts.** The two opt-ins
   (`CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` to observe, then
   `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` to drop) exist so this rollout is safe.
   A cloud host arms both; the control plane ships every customer an enforce-mode
   policy whose allow-list is bootstrapped from what the customer declares, and
   `allow_metadata` stays default-deny — load-bearing on real cloud instances,
   which actually have a credential-bearing `169.254.169.254`.

4. **Report denied flows back to the control plane.** The enforcer already emits
   `network_policy.deny_dropped` / `deny_logged` audit rows + logs. Those security
   events should ride the same back-channel the cloud uses for observed
   container state (and the planned resource-accounting feed), so the dashboard
   shows customers what is being blocked — the observability half of the design,
   at cloud scale.

### Cross-repo dependency

The tenant model lives in `Containarium-cloud`: one **org** is the tenant
(`org_id` on every control-plane row), and network isolation is
[`prd/cloud/data-isolation.md`](https://github.com/FootprintAI/Containarium-cloud/blob/main/prd/cloud/data-isolation.md)
Layer 4 (per-org bridges) + [`prd/cloud/multi-tenancy.md`](https://github.com/FootprintAI/Containarium-cloud/blob/main/prd/cloud/multi-tenancy.md).
The two cloud-side prerequisites for points 1–2 are both proto additions to
[`actuation_service.proto`](https://github.com/FootprintAI/Containarium-cloud/blob/main/proto/containarium/cloud/v1/actuation_service.proto):
an `org_id` on `Assignment` (so the reconciler can stamp the tenant label) and a
network-policy / egress-allowlist message (so egress policy rides desired-state).
Both land in `Containarium-cloud` first; this section plus
`CLOUD-ACTUATION-CLIENT-DESIGN.md` are the OSS-side contract they plug into.

## Per-flow accounting → the traffic view (#627)

The same per-veth `TC_INGRESS` program doubles as the traffic
view's data source. The view (`TrafficService` → webui) was
wired to the host conntrack collector, which on real backends
comes up mostly empty: tenants run docker-compose *inside* an
LXC, so host conntrack sees the LXC/bridge address (post-
masquerade) rather than the per-tenant container IP the
collector's IP→name cache is keyed on — the flow is then
dropped — and byte counts need `nf_conntrack_acct=1`.

The eBPF hook has neither problem. It already parses the flow's
src/dst IP, and it is keyed by veth ifindex, so **attribution is
exact** (the ifindex maps 1:1 to a container — no IP cache). The
program keeps a `flows` map (`BPF_MAP_TYPE_LRU_HASH`, 5-tuple →
`{packets, bytes, first_ns, last_ns}`) updated for **every**
observed flow — allowed and would-deny alike, since this is
usage accounting, not a policy decision. The daemon's enforcer
polls the map (default 15s), attributes each entry via its
`attached` ifindex→container map, and feeds the batch to the
traffic collector, which merges them into
`GetConnections`/`GetConnectionSummary` alongside any conntrack
rows.

Properties / limits:

- **Both directions (#631).** The veth ingress hook tallies the
  container's egress (`bytes_sent`/`packets_sent`); a second
  program on the veth's TC_EGRESS hook tallies the reply
  direction into `rx_bytes`/`rx_packets` of the same flow entry
  (it rebuilds the request-oriented key by swapping the reply's
  tuple), surfaced as `bytes_received`/`packets_received`. An
  object built before #631 omits the egress program — received
  counters then stay 0.
- **Cumulative, LRU-bounded.** Counters are monotonic per flow;
  the map self-evicts under a short-lived-flow burst rather than
  filling. The poll snapshots (does not drain), so the active-
  connection view stays stable; evicted flows simply drop out on
  the next full-replace ingest.
- **Opt-in, backward-compatible.** Gated behind the existing
  `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT`. An older object built
  before the `flows` map still loads and enforces; the daemon
  logs that flow accounting is unavailable and leaves the poll
  off until the operator rebuilds `netpolicy.bpf.o`.
- **Historical persistence (#632).** When a flow disappears
  between polls (LRU-evicted or aged out = effectively closed),
  its final counters are written to `traffic_history` via the
  same `SaveConnection` path conntrack uses, so the historical
  view + aggregates light up on eBPF-only backends. Caveat: on a
  backend where conntrack attribution also works, the same
  logical flow may be persisted once per source (distinct IDs) —
  cross-source 5-tuple dedup is a follow-up.

## What this is NOT

- A k8s NetworkPolicy implementation. Different threat model
  (multi-tenant SaaS, not multi-namespace inside one trust
  boundary).
- A CNI plugin. Incus owns the network; we attach to the bridge.
- A firewall replacement for the cloud-edge filter. The cloud
  firewall stays the perimeter; this is the per-tenant interior.

## Related

- [`security/OPERATOR-SECURITY-RUNBOOK.md`](OPERATOR-SECURITY-RUNBOOK.md) — operator-facing security ops; see "[Pinning per-tenant network policy](OPERATOR-SECURITY-RUNBOOK.md#pinning-per-tenant-network-policy)".
- [`security/ZERO-TRUST-AUDIT.md`](ZERO-TRUST-AUDIT.md) — original audit; didn't flag this gap, would be amended on landing.
- [`../EPHEMERAL-SANDBOX-DESIGN.md`](../EPHEMERAL-SANDBOX-DESIGN.md) — answers "what network does a sandbox get" (probably: tenant netns; this design covers what that netns can reach).
