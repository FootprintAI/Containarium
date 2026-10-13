# Multi-tenant isolation assessment: tenant ↔ core-infra network boundary

**Scope:** this page records two network-layer assessments of the shared
bridge on a backend host:

1. **Tenant ↔ core-infra** (2026-09-27): can an ordinary tenant container
   reach the platform's own core-role infrastructure
   (`containarium-core-postgres`, `containarium-core-victoriametrics`, and
   friends), independent of any application-level credential?
2. **Tenant ↔ tenant** (2026-10-06, see
   [below](#tenant--tenant-the-second-assessment)): can one tenant's
   container reach another tenant's container on the same backend?

The first assessment originally stated that tenant-to-tenant isolation was
"covered separately by the existing `NetworkPolicy`/eBPF enforcement
system". The second assessment exercised that claim and found it is only
true on a backend whose operator has armed the enforcer *and* authored an
enforce-mode policy for every tenant — neither of which is the default.

**Trigger:** a live incident in which `containarium-core-postgres` was
found running with its compiled-in default password, with `pg_hba.conf`
open to the entire tenant bridge subnet. The credential and `pg_hba`
rule have since been fixed on every backend where the pattern was found
(see the operator's private incident record — not reproduced here per
this repo's anonymization convention). Fixing the credential answers
"could a tenant authenticate with the known default password" but not
the more fundamental question this doc addresses: **could a tenant even
attempt a connection at all, regardless of what the credential is?**

## Tenancy model — what is actually shared

| Layer | Shared or dedicated | Boundary mechanism |
|-------|---------------------|---------------------|
| Control plane / API | shared | authz on derived tenant id |
| Compute (tenant containers) | shared backend host | Incus LXC + cgroups |
| **Network (tenant ↔ tenant)** | **shared bridge** | **none by default** — eBPF enforcer is opt-in twice over and per-tenant (second assessment) |
| **Network (tenant ↔ core-infra)** | **shared bridge** | **none — this is the finding** |
| Core Postgres (`core-postgres`) | shared platform DB | `pg_hba.conf` allow-list + role credential (app layer only) |
| Core Grafana (`core-victoriametrics`) | shared platform dashboard | `auth.anonymous` Viewer role (app layer only) |

Every row marked "none" or "app layer only" in the boundary-mechanism
column is a network-layer gap: the only thing standing between a
tenant container and platform infrastructure today is whatever the
application happens to enforce at its own listener, not the network
fabric itself.

## What already exists — and its actual scope

The platform has a real, working per-organization network isolation
system (`NetworkPolicy` reconciler + eBPF enforcement) that prevents one
tenant's containers from reaching another tenant's containers on the
same bridge. It is enforced, arms correctly, and has caught at least one
real cross-tenant breach in the past.

That system was designed, and remains scoped, to **tenant-to-tenant**
isolation only. It has never treated the platform's own core-role
containers (`core-postgres`, `core-victoriametrics`/Grafana, `core-caddy`,
etc.) as a subject at all — there is no policy rule, default-deny or
otherwise, governing traffic from a tenant container toward a core-role
container. A tenant container is, today, just as free to reach
`core-postgres:5432` as it would be to reach any address on the shared
bridge that isn't covered by an explicit deny.

## The test

`scripts/tenant-core-infra-network-isolation-e2e.sh` proves this
directly and reproducibly:

1. Takes a real, already-existing, ordinary tenant container name as
   its argument (refuses anything named like a core/platform container).
2. Discovers every `containarium-core-*` container on the same backend
   host.
3. For each one, resolves its bridge IP and attempts a bare TCP connect
   from *inside the tenant container's own network namespace* (via
   `incus exec ... /dev/tcp/...`) to the ports that role would
   legitimately listen on (`postgres`: 5432; `victoriametrics`: 5432 +
   3000).
4. Reports `FAIL` on any successful connect — a successful TCP connect
   from a tenant namespace to a core-role listener means there is no
   network-layer isolation for that path at all, regardless of whatever
   credential gates the application behind it.

Run against a real tenant container on a real backend, it reproduced:

```
<tenant-container> -> containarium-core-postgres (<core-ip>:5432): TCP connect succeeded
  FAIL: tenant container reached platform infra at the network layer — no isolation boundary exists for containarium-core-postgres:5432
<tenant-container> -> containarium-core-victoriametrics (<core-ip>:3000): TCP connect succeeded
  FAIL: tenant container reached platform infra at the network layer — no isolation boundary exists for containarium-core-victoriametrics:3000
FAILED: 2 tenant->core-infra network path(s) exist with no isolation boundary
```

(`containarium-core-victoriametrics:5432` was also reachable, same root
cause as `core-postgres:5432` — both listeners live behind the same
missing boundary.)

## Findings

### Finding 1 — no network isolation between tenant containers and `core-postgres` (P0)

A tenant container can open a raw TCP connection to `core-postgres:5432`
on the shared bridge. The only thing currently preventing a tenant from
attempting authentication against the platform's own database — which
holds, among other things, secrets, audit logs, JWT revocations, and
tenant KMS key material — is the database's own credential and
`pg_hba.conf` allow-list, both application-layer controls with no
network-layer backstop. A single future credential-hygiene mistake (a
weak/default/leaked password, an overly broad `pg_hba` rule) is
directly exploitable by any tenant on the bridge, with no network
control to fall back on.

### Finding 2 — `core-victoriametrics` (Grafana) web port reachable + anonymous Viewer enabled (P0, likely higher severity than Finding 1)

The same missing boundary also exposes Grafana's own web UI
(`core-victoriametrics:3000`) to every tenant container. Combined with
that Grafana instance's `auth.anonymous enabled = true` /
`org_role = Viewer` configuration (confirmed separately during the
credential-rotation incident), this means **any tenant can view
platform dashboards today with zero credential of any kind** — no
password to rotate, no allow-list to narrow. This is a strictly easier
exploit path than Finding 1 and should be treated as the higher
priority of the two.

## What is explicitly NOT isolated

- Tenant containers ↔ core-role containers, at the network layer, in
  general — not just Postgres and Grafana. This assessment only
  exercised the two roles known to exist on the swept backends; any
  other `core-*` role container on any backend should be assumed
  reachable the same way until proven otherwise with this same script.
- The control plane / API layer was not in scope for this assessment
  and is not covered by this doc.

## Recommended remediation (not implemented by this assessment)

Per this project's own guardrail, a boundary this systemic is an
architecture change, not an ad-hoc patch mid-assessment. Two viable
directions, either scoped through `/architect-design` and implemented
via `/engineer-implement`:

1. **Extend the existing `NetworkPolicy`/eBPF reconciler** to treat
   core-role containers as a subject: default-deny tenant → core-* by
   default, with an explicit allow-list of the specific core services a
   tenant workload is actually meant to reach (if any).
2. **Incus Network ACLs** as a simpler, lower-lift alternative: a
   host-level ACL denying tenant-bridge sources from reaching core-role
   container IPs on their listener ports, independent of the
   per-org reconciler.

Either direction should be proven with this same test script (or its
descendants) turning green as the acceptance criterion, not a config
review.

## Status since this assessment

This page records what was found at the time; the follow-up work is:

- **Network layer.** The core-infra network guard
  ([`docs/architecture/core-infra-network-guard.md`](../architecture/core-infra-network-guard.md))
  denies tenant sources to core-role listener ports with Incus network ACLs. It
  shipped off by default; since #2347 it is on unless `CONTAINARIUM_CORE_GUARD=off`. This
  is the stronger control for Finding 1, because it does not depend on the
  database's own configuration being right.
- **Application layer, new installs.** A freshly installed core Postgres no
  longer admits the whole bridge subnet. `pg_hba.conf` is written with one
  `scram-sha-256` rule for the daemon and one for the metrics container's
  Grafana database, each a single address, and connection logging is on. The
  core Postgres and metrics containers are pinned to fixed addresses so the rule
  can name Grafana before it exists. After applying the rules the daemon logs in
  the way it will in production; if that fails, the scoped rules are removed and
  the old subnet rule is written, with an `ERROR` in the log, so a wrong rule
  cannot leave an install without a working database.
- **Existing hosts are not changed automatically.** Their `pg_hba.conf` keeps
  whatever it has. Narrow it by hand (see the operator security runbook) or rely
  on the network guard.
- **Credentials.** Using the operator's configured Postgres password for the
  role and for Grafana, and removing Grafana's literal admin login, is tracked
  in #2091.

---

## Tenant ↔ tenant: the second assessment

**Question:** on a shared backend, can tenant A's container observe or
reach tenant B's container over the bridge, with no credential involved?

**Short answer:** yes, on a default-configured backend. Nothing on the
data path distinguishes tenants unless the operator has opted in twice
*and* authored a per-tenant enforce policy.

### What the code does today

| Layer | Mechanism | Default state | Covers tenant → tenant? |
|-------|-----------|---------------|-------------------------|
| Incus bridge (`incusbr0`) | one bridge per backend, `ipv4.nat` only (`pkg/core/incus/client.go` `EnsureNetwork`) | always | no isolation keys set |
| Tenant NIC (`eth0`, profile-inherited) | plain `nic` on `incusbr0` (`pkg/core/container/manager.go`, `pkg/core/incus/nic_device.go`) | always | no `security.port_isolation`, `security.mac_filtering`, `security.ipv4_filtering`, no `security.acls` |
| Per-user Incus ACL (`NetworkServer.UpdateContainerACL`, `pkg/core/incus/acl.go`) | opt-in RPC, never applied at create | off | partially — and `AttachACLToContainer` fails on a profile-inherited `eth0`, which is what every tenant box has; custom rules are discarded and mapped to the `full-isolation` preset |
| Core-infra guard (`internal/coreguard`) | Incus ACL on **core-role** NICs only | off unless `CONTAINARIUM_CORE_GUARD=enforce` | no, by design |
| Host firewall (`internal/hostharden/imds.go`) | one `FORWARD` drop for `169.254.169.254` | applied by the `hostharden` CLI, not the daemon | no |
| eBPF `NetworkPolicy` enforcer (`internal/server/network_policy_enforcer.go`, `network_policy_plan.go`, `experimental/ebpf-phaseA/netpolicy.bpf.c`) | tc program at each container's host-veth `TC_INGRESS`; drops a flow to another tenant's IP when the **sender's** policy is `enforce` | off unless `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` is set; drops only with `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1`; a tenant with no stored policy is compiled as `log_only` | only for senders with an enforce policy; IPv4 only (IPv6 and ARP return `TC_ACT_OK`); sender-side only, so a protected tenant is still reachable *from* an unprotected one |
| Threat detection (`internal/threatdetect/rule_crosstenant.go`) | CRITICAL finding on an observed cross-tenant flow | needs the eBPF object | detection only, never drops |

Three consequences follow directly from `network_policy_plan.go`:

- A tenant that never had `containarium network-policy set --mode enforce`
  run for it is `log_only` forever. On a backend where nobody authored
  policies, every tenant is `log_only`.
- Even with a stored enforce policy, the daemon downgrades it to
  `log_only` unless `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` is in the
  daemon's environment.
- Enforcement is evaluated at the sender's veth. Tenant B opting in does
  not stop tenant A (no policy) from connecting to B.

The hosted control plane does not expose the network-policy endpoints at
all (`containarium network-policy list --server <cloud> --http` returns
`404`), so a cloud-managed tenant has no path to request isolation; it is
entirely an operator-side daemon setting on each backend.

### Existing test coverage

- `.github/workflows/fence-probe-e2e.yml` creates two tenants and
  **expects** alice → bob ping to succeed; it asserts only that the
  CRITICAL finding fires. There is no automated test anywhere asserting
  that tenant → tenant traffic is *denied*.
- `scripts/tenant-core-infra-network-isolation-e2e.sh` and
  `scripts/core-guard-legit-flows-e2e.sh` cover tenant → core only.

### The test

`scripts/tenant-tenant-network-isolation-e2e.sh <tenant-a> <tenant-b>` is
the tenant ↔ tenant counterpart of the core-infra script. Run on the
backend host, it resolves both fixtures' bridge addresses, prints the
isolation keys on each tenant NIC, then from inside A's network namespace
sends one ICMP echo and one bare TCP connect to B's sshd, and repeats the
probe B → A (enforcement is sender-side, so both directions must hold).
Any success is a `FAIL`. The script refuses core-role containers and
refuses two fixtures that resolve to the same tenant unless
`EXPECT_SAME_TENANT=1` is set.

It is **expected to be red** on every default-configured backend today.
Turning it green is the acceptance criterion for the remediation.

### Live result (2026-10-06)

Two fixture boxes were created under one org on a non-production lab
backend (Incus 7.4, daemon 0.99.3, default configuration, no network
policy stored for the org, hosted control plane returning `404` for the
network-policy endpoints). From inside each box, a bare TCP connect to the
other box's bridge address on port 22 **succeeded in both directions** and
returned the peer's `SSH-2.0-OpenSSH` banner; a connect to a closed port
got `Connection refused` (a RST from the peer, so L3 reachability is
confirmed, not just filtered); and the neighbour table showed the peer's
MAC as `REACHABLE` (L2 visibility). The cloud metadata address was
unreachable. ICMP could not be exercised because the box's unprivileged
user lacks `cap_net_raw` for `ping`; that is a limitation of the probe,
not evidence of a boundary.

The two fixtures share an org, so this run exercises the mechanism rather
than two distinct tenants. That is sufficient here: with no stored policy
the enforcer compiles every container as `log_only` regardless of tenant,
so the data path for a co-tenant and a foreign tenant is identical. A run
with two orgs on a backend host via the script above is the next step for
anyone who wants the stricter proof. Concrete container names and
addresses are withheld per this repository's anonymization convention.

| Probe | Result |
|-------|--------|
| A → B TCP/22 | connected, banner received (**FAIL**) |
| B → A TCP/22 | connected (**FAIL**) |
| A → B TCP/closed port | `Connection refused` from B (L3 reachable) |
| A neighbour table for B | `REACHABLE` (L2 visible) |
| A → `169.254.169.254:80` | unreachable |
| ICMP | not exercised (no `cap_net_raw` in the box) |

### Findings

#### Finding 3 — tenant → tenant traffic on the shared bridge is allowed by default (P0, #2347)

On a backend running the shipped defaults, any tenant container can ping,
port-scan and open TCP connections to any other tenant's container on the
same bridge. Every tenant workload listening on its bridge address
(a dev Postgres, a Redis, a docker-compose service bound to `0.0.0.0`) is
reachable by every co-tenant. The only control that can drop this traffic
is opt-in at two levels plus per-tenant, is IPv4-only, and protects only
senders that opted in.

#### Finding 4 — the per-user Incus ACL path cannot attach to a tenant NIC (P2, #2348)

`AttachACLToContainer` expects an instance-local `eth0` device and fails
with "device not found" on the profile-inherited NIC every tenant box
gets, so even an operator who calls `UpdateContainerACL` gets no
isolation. Custom rules are also silently replaced with the
`full-isolation` preset.

#### Finding 5 — no automated test asserts tenant → tenant denial (P2, #2349)

The only cross-tenant lane in CI expects the packet to get through. A
regression in whatever remediation lands would not be caught.

### What is explicitly NOT isolated (tenant ↔ tenant)

- L2: ARP and IPv6 neighbour discovery between tenant NICs on the same
  bridge. No `security.port_isolation` or MAC/IP filtering is set.
- L3/L4 IPv4: everything, unless the sender's tenant has an enforce policy
  on an armed daemon.
- IPv6: everything, even with an armed enforcer (the BPF program passes
  non-IPv4 frames).

### Recommended remediation (not implemented by this assessment)

Architecture change, routed through `/architect-design`, with the e2e
script above as the acceptance test:

1. **Default-deny on the data path, independent of per-tenant policy.**
   Set `security.port_isolation=true` on every tenant NIC (the bridge
   `isolated` port flag; L2 and L3 between isolated ports is dropped by
   the kernel, IPv4 and IPv6 alike), which turns "no policy" into "no
   reachability". Intra-tenant flows that must work (webapp → its own
   Postgres) are then re-allowed explicitly, either by placing a tenant's
   boxes on a per-tenant bridge (the cloud repo's Layer 4 model) or by
   routing them through the host with an allow rule.
2. **Make the eBPF enforcer default-deny for unlabelled tenants** so a
   tenant with no stored policy is compiled as `enforce` with
   `allow_intra_tenant` and an empty egress list, instead of `log_only`,
   once the daemon is armed. This closes the sender-side gap but still
   leaves IPv6 open; option 1 is the stronger control.
3. **Hoist the two opt-ins** so cloud-managed backends arm them at
   enrolment, and surface the posture in `containarium doctor`.
