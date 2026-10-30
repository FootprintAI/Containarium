# Debian 13 Host Migration Plan (Cloud Backends)

> Status: **PLAN — not started.** No production change has been made.
> Owner: platform operations. Approvals are listed in the gates below.
>
> Names are generic on purpose (this repository is public). Map
> `<prod-backend>`, `<spot-backend>`, `<sentinel>` and `<project>` to the
> real resources in the private operator runbook.

## Why

Two host-kernel CVEs are open on the Ubuntu 24.04 Cloud backends:

| CVE | Class | Score | Ubuntu 24.04 fix state (2026-10-30) | Debian 13 fix state |
|---|---|---|---|---|
| CVE-2026-98432 | Remote, IPv4 TCP use-after-free | 9.8 | Not released; fix in progress in 6.8.0-149 and for the GCP line | Fixed in `linux` 6.12.113-1 (DSA-6568-1) |
| CVE-2026-46300 | Local, XFRM ESP-in-TCP privilege escalation | 7.8 | Fixed in GCP 6.17.0-1018.19; not listed for GCP 7.0 | Fixed (6.12 line) |

The Ubuntu backends run GCP kernels 6.17 (one host) and 7.0 (the other).
No released Ubuntu kernel fixes CVE-2026-98432 for either line. The
firewall restriction is a stopgap; it does not close the bug.

A verified Debian 13 host has:
- kernel `6.12.113+deb13-cloud-amd64` (package 6.12.113-1), which carries the fix;
- the installer, with Debian support, completing on a KVM guest (Incus 7.5.1
  from the Zabbly repository, services active).

## Scope

In scope: Cloud backends in the GCP project (the prod and spot backends,
and the sentinel once its host identity is confirmed).

Out of scope: BYOC hosts (operator-owned; covered by the BYOC kernel policy
draft) and the GPU nodes (which need separate NVIDIA driver validation on
Debian).

## Current state (verify before each step)

| Backend | Role | Kernel | Network tags | Spot | Notes |
|---|---|---|---|---|---|
| `<prod-backend>` | Platform backend | GCP 7.0 (Ubuntu 24.04) | jump-server, spot-backend | yes | Fixed firewall rules pin its internal IP as a source |
| `<spot-backend>` | Tenant backend | GCP 6.17 (Ubuntu 24.04) | jump-server, sentinel, spot-backend | yes | Sentinel rules match on tags |
| `<sentinel>` | Ingress | Ubuntu 24.04 | — | — | **SSH host key changed; unexplained** |

Read-only checks used to build this table: `uname -r`, `sysctl
net.mptcp.enabled`, the `apt` changelog, and `gcloud compute instances
describe`.

## Preconditions (gates before any build)

- **G0. Sentinel host key confirmed.** Someone confirms whether the sentinel
  was rebuilt or re-keyed, through the cloud console or serial output. No
  migration step touches the sentinel until this is done.
- **G1. Inventory of platform roles.** For each backend, list the platform
  services, the control-plane database and backup jobs, and every tenant.
  The current plan does not have this list yet.
- **G2. Installer merged.** The Debian support commits on the
  `fix/install-debian-trixie` branch are reviewed and merged, so the
  published installer carries the fixes.
- **G3. Replacement AppArmor control.** Ubuntu's
  `kernel.apparmor_restrict_unprivileged_userns` is not present on Debian by
  default. A Debian equivalent is designed and tested on a non-production
  host before any tenant moves.
- **G4. Rollback path.** Recent backups of the platform database and
  configuration are taken and verified, and the old VMs are kept, not deleted.

## Steps

1. **Build a Debian 13 Spot VM** from the `debian-13` image family, in the
   same project and zone as the backend it replaces. Use a new name with a
   `-debian13` suffix. Copy the disk size, service account, and the network
   tags, so the existing firewall rules apply.
   *Gate: approval to create the VM.*
2. **Install** with the merged installer. Verify the Incus version, the
   storage backend (dir, since ZFS is not on the Debian cloud kernel), and
   `systemctl is-active` for both `containarium` and `incus`.
3. **Update IP-pinned firewall rules.** The new VM has a new internal IP.
   Each rule that pins the old IP as a source or destination is updated to the
   new IP, in the same change window.
   *Gate: approval to change firewall rules.*
4. **Replace the AppArmor control** (G3) on the new VM and test it. Confirm
   the same denials that the Ubuntu control gives.
5. **Migrate tenants in batches** with the existing cross-backend move
   path. Move one batch, check each container (service up, network reachable,
   data intact), then the next batch. Stop on the first failure.
   *Gate: approval per batch.*
6. **Cut over platform roles** (control-plane, backups, sentinel routes) to
   the new backend, one role at a time, each with its own health check.
   *Gate: approval per role.*
7. **Retire the old backend in stages:** stop it first, keep its disk and
   snapshot for an agreed period, then delete. Do not delete on the same day
   as the cutover.

## Rollback

- Before step 5: delete the new VM. Nothing has moved.
- During step 5: move the batch back with the same move path, from the new
  backend to the old one. The old VM stays running until the batch is verified.
- After step 6: restore the platform roles to the old backend, using the
  pre-cutover configuration and database backup.

## Risks

- **Spot preemption.** Both current backends are Spot VMs, and so was the
  test VM. A preempted platform backend interrupts service. Decide per role
  whether it stays on Spot.
- **Tag or IP mismatch** silently blocks traffic. Check each rule after step 3.
- **Ubuntu-only assumptions** in provisioning (Terraform, startup scripts,
  CI images) are not yet updated for Debian. Step 1 is done by hand until they
  are.
- **Sentinel key change.** Until G0 is closed, the ingress path is not
  trusted.

## Open decisions

1. Which platform roles stay on Spot.
2. The change window and the approver for each gate.
3. Whether the Debian backend is built from the Terraform module or by hand
   for the first migration.
4. Retention period for the old backends before deletion.

## Related

- [`KERNEL-PATCH-RUNBOOK.md`](KERNEL-PATCH-RUNBOOK.md) — the interim patch
  procedure; this plan replaces its manual reboot for these backends.
- The BYOC recommended-kernel policy (draft) — should be updated to match
  the decision here once it's made.
- [`BYOC-HOST-HARDENING-BASELINE.md`](BYOC-HOST-HARDENING-BASELINE.md).
