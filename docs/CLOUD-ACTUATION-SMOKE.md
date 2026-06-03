# Cloud-Actuation Smoke — End-to-End Network-Policy Loop

> Operator runbook for validating the full cloud → host network-policy path
> (#354 cloud-actuation client × #315 per-tenant network isolation, "Cloud
> extension" in [`security/NETWORK-ISOLATION-DESIGN.md`](security/NETWORK-ISOLATION-DESIGN.md)).
> This is the slice-5 smoke: it proves a policy **authored on the cloud** is
> **enforced on a registered host**.

## What this proves

```
cloud NetworkPolicyService (author)  →  network_policies table  →  AssignmentBatch.network_policies (WatchAssignments)
   →  host: cloud-actuation client  →  NetworkPolicyStore  →  eBPF enforcer  →  packet dropped
```

Each leg is unit-tested in isolation; this runbook is the one place they're
exercised together against a live control plane + a real backend.

## Prerequisites

- A running **cloud control plane** (the `cloud-daemon`) reachable over gRPC, and
  cloud **sysadmin** access to it (to mint a host token).
- A **backend host** running the OSS `containarium daemon` (the actuation client
  ships in the default build — no special build flag). Incus present.
- For the *enforcement* half: the eBPF object built on the backend and the daemon
  armed, per [`security/OPERATOR-SECURITY-RUNBOOK.md` → Pinning per-tenant network
  policy](security/OPERATOR-SECURITY-RUNBOOK.md#pinning-per-tenant-network-policy):
  ```sh
  CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=/etc/containarium/netpolicy.bpf.o
  CONTAINARIUM_NETWORK_POLICY_ENFORCE=1
  ```
  Omit these to smoke only the *observe* path (the policy still syncs; flows are
  logged, not dropped).

## Step 1 — mint a host token (cloud sysadmin)

On the cloud side, register the host and capture the one-time bearer + host ID
(exact command per the cloud repo; conceptually `CreateHost`). Hand the
`host-id` and `token` to the host operator over a secure channel — never in shell
history or a ticket.

## Step 2 — enroll the host

On the backend, write the token to a file (so it stays out of history), then:

```sh
printf '%s' '<host-bearer-token>' > /tmp/host.token
containarium cloud login \
    --control-plane <cloud-control-plane-host>:443 \
    --host-id       <host-uuid> \
    --token-file    /tmp/host.token
shred -u /tmp/host.token
containarium cloud status      # → enrolled, token redacted
```

This writes `~/.containarium/cloud.yaml` (0600). Restart the daemon so it picks
up the enrollment (or point the daemon at the config with
`CONTAINARIUM_CLOUD_CONFIG=/etc/containarium/cloud.yaml`).

## Step 3 — confirm the heartbeat

- **Host**: the daemon log shows `[cloud] actuation client started: host=… control-plane=… (heartbeat 30s, watch=true)`.
- **Cloud**: the host's `last_heartbeat_at` advances (dashboard or the hosts
  table). A stale host is 3 missed beats (~90s).

A control-plane outage here must NOT affect local containers — the daemon logs
`[cloud] heartbeat failed (N consecutive)` and keeps serving.

## Step 4 — author an egress policy on the cloud

For the org whose containers run on this host, set an egress policy via the cloud
`NetworkPolicyService` (REST shown; dashboard/CLI equivalent):

```sh
PUT /v1/orgs/<org-id>/network-policy
{ "egress_cidrs": ["8.8.8.8/32"], "mode": "NETWORK_POLICY_MODE_ENFORCE" }
```

## Step 5 — confirm the policy reached the host

The actuation client syncs it into the host's policy store within one
`WatchAssignments` batch. Verify on the host:

```sh
containarium network-policy get <org-id>     # tenant == org-id, egress 8.8.8.8/32, mode enforce
```

(If the host runs without Postgres the store is in-memory; the policy still shows
until daemon restart.)

## Step 6 — observe enforcement

The enforcer matches a container to its tenant by the
`user.containarium.tenant` label. The cloud **container reconcile** stamps this
label automatically: a container the cloud assigns to this host (desired_state
`running`) is created locally as `cld-<short-uuid>` with
`user.containarium.tenant=<org-id>` set, then started. So the clean path is to
create a container for the org **in the cloud dashboard** and watch it appear:

```sh
incus list                                   # a cld-<short-uuid> instance appears, owned by <org-id>
incus config get cld-<short-uuid> user.containarium.tenant   # == <org-id>
```

To exercise just the policy/enforcer path **without** a cloud assignment, you can
still hand-label a local container (what the reconcile does for you):

```sh
incus launch images:ubuntu/24.04 smoke-box
incus config set smoke-box user.containarium.tenant <org-id>
```

Within one enforcer reconcile (≤ a few seconds) the policy applies. From inside
the container:

```sh
incus exec smoke-box -- ping -c3 8.8.8.8     # allow-listed  → succeeds
incus exec smoke-box -- ping -c3 1.1.1.1     # not allowed   → 100% loss (enforce) ; observed-only (log_only)
```

On the host, the daemon logs the denied flow, and (with an audit store) writes an
audit row:

```
[netpolicy] deny: tenant="<org-id>" src=… dst=1.1.1.1 … DROPPED (enforce)
# audit: action=network_policy.deny_dropped (or .deny_logged in observe mode)
```

## Pass criteria

1. Host enrolls + heartbeats; cloud shows it live.
2. A policy authored on the cloud appears in `containarium network-policy get`
   on the host without operator action there.
3. With enforce armed + the test container labelled, the non-allow-listed
   destination is **dropped** and the allow-listed one **passes**.
4. `containarium cloud logout` + a control-plane outage leave running containers
   untouched.

## Teardown

```sh
incus delete -f smoke-box
containarium cloud logout            # removes ~/.containarium/cloud.yaml
# cloud sysadmin: tombstone the host (DeleteHost)
```

## Known gaps

- **Policy sync is upsert-only** — a policy *removed* on the cloud is not yet
  cleared on the host (distinguishing cloud- from CLI-authored policies needs a
  source marker). Re-authoring with an empty allow-list is the current workaround.
- **Container reconcile** wires the resource options the actuation contract
  carries — memory, root-disk size, and GPU passthrough — plus the tenant label.
  It does not set routes, secrets, or CPU limits (not in the `Assignment`
  contract); those remain a follow-up if cloud workloads need them.
