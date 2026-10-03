# Multi-tenant isolation assessment: tenant ↔ core-infra network boundary

**Scope:** this assessment covers one specific boundary — whether an
ordinary tenant container can reach the platform's own core-role
infrastructure (`containarium-core-postgres`, `containarium-core-victoriametrics`,
and friends) at the network layer, independent of any application-level
credential. It does not re-assess tenant-to-tenant isolation, which is
covered separately by the existing `NetworkPolicy`/eBPF enforcement system.

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
| Network (tenant ↔ tenant) | shared bridge | per-org `NetworkPolicy` / eBPF enforcer |
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
  ships off by default; turn it on with `CONTAINARIUM_CORE_GUARD=enforce`. This
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
