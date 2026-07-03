# Host Kernel Patching — Runbook (and the gap it documents)

> Status: **gap analysis + interim manual procedure. No automation exists
> yet.** Tracking: #889 (drain-and-relocate before reboot), #890 (live
> kernel patching evaluation), #891 (fleet kernel version monitoring +
> CVE/USN watch).
> Related: [`SECURITY-FAQ.md`](SECURITY-FAQ.md) — "what stops one tenant
> from reaching another" names a host-kernel LPE as the honest cost of
> shared-kernel isolation. This doc is the other half of that answer:
> what we actually do when that LPE has a CVE.

## Why this doc exists

Containarium runs tenants as Incus/LXC system containers on a shared host
kernel (see [`SECURITY-FAQ.md`](SECURITY-FAQ.md)). There is no hypervisor
boundary, so a host-kernel local-privilege-escalation (LPE) or
container-escape CVE is a full-severity, cross-tenant event on that host.
This runbook exists because, as of this writing, **there is no automated
path to remediate one** — only a manual, disruptive procedure. That's
worth writing down precisely so the gap doesn't hide behind good intentions.

## Current state (as verified against this repo)

- **Auto-upgrades are deliberately disabled fleet-wide.**
  `terraform/gce/scripts/startup-sentinel.sh` and `startup-spot.sh` (and
  their `terraform/modules/containarium/scripts/` mirrors) both disable
  `apt-daily.timer` / `apt-daily-upgrade.timer` with the comment "manual
  patching only" — this was done to stop OOM hangs on a small sentinel VM,
  but the effect is fleet-wide: no host auto-patches its kernel or OS
  packages.
- **No kernel-CVE tracking.** CI's `govulncheck` / `Trivy` / `gosec`
  (`.github/workflows/security.yml`) scan Go dependencies and container
  images — not the host Linux kernel. Nothing watches the Ubuntu USN feed
  for kernel advisories.
- **No safe way to take a host offline.** `containarium capacity withdraw
  --drain` gracefully stops workloads within a bounded window, but only
  for BYOC-advertised spare capacity — not "every tenant on this host."
  There is no container live-migration primitive. Rebooting a host with
  live tenant containers on it today means hard-stopping all of them.
- **Virtual patching doesn't cover this.** The eBPF Tier 1 virtual-patch
  deny rules (`docs/security/VIRTUAL-PATCHING-DESIGN.md`) block
  network-reachable exploit paths — a vulnerable upstream service a tenant
  reaches. A host-kernel LPE is a local syscall path inside a container,
  not a network flow; a `TC_INGRESS` eBPF hook cannot intercept it. Do not
  reach for virtual patching as a mitigation for a kernel CVE — it's the
  wrong tool for this threat class.

## Interim manual procedure (until #889 / #890 land)

Until the automation below exists, this is the actual procedure an
operator should follow on notice of a host-kernel CVE:

1. **Assess exploitability.** Confirm the CVE applies to the fleet's
   running kernel line (`uname -r` on the host) and requires no
   unavailable local preconditions.
2. **Decide urgency vs. blast radius.** An actively-exploited LPE against
   a container-escape primitive is a stop-the-line event; a
   defense-in-depth hardening fix is not.
3. **Notify tenants on the affected host** if patching requires a reboot
   (it usually will, absent #890) — there is no graceful drain today, so
   this is a disruptive, all-tenants-down operation on that host.
4. **Patch and reboot.**
   ```
   apt-get update && apt-get install -y linux-image-generic
   reboot
   ```
   Confirm the new kernel is running (`uname -r`) and Incus, the eBPF
   network-policy object (if loaded — `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT`),
   and all containers come back healthy.
5. **Record the patch** (kernel version, CVE, date, host) — there is no
   automated audit trail for this today; do it by hand in the operator's
   own tracking until #889/#890 add one.

This procedure is intentionally manual and disruptive. It is not an
acceptable long-term answer for a production multi-tenant fleet — that's
the point of #889 and #890.

## What closes the gap (tracked, not yet built)

1. **#889 — drain-and-relocate before reboot.** A general "drain a host
   for maintenance" primitive: stop scheduling new containers onto it,
   gracefully stop or relocate (via the existing cross-backend
   `move_container` path) what's running, report per-container outcome,
   only then proceed with the reboot. Generalizes the existing bounded
   drain-window concept in `internal/cmd/capacity.go` beyond
   BYOC-advertised capacity.
2. **#890 — live kernel patching (Canonical Livepatch / kpatch).**
   Removes the need for a reboot (and therefore #889) for the common case
   of routine kernel security fixes. Needs a pilot to confirm compatibility
   with the loaded eBPF network-policy program before fleet rollout.
3. **#891 — fleet kernel version monitoring + CVE/USN watch.** Exports
   `KernelVersion` (already collected by `GetSystemInfo`) as an OTel
   gauge for dashboard visibility, plus a scheduled check against a
   kernel-CVE advisory source. Deliberately sequenced *after* #890: if
   Canonical Livepatch is adopted, its advisory feed may cover the CVE
   side for free, narrowing #891 to just the OTel export.

## Open questions

- **Coverage limits.** Canonical Livepatch's free tier caps the number of
  covered machines — the fleet's growth trajectory may outgrow it. #890's
  evaluation should size this against the current + projected fleet count.
- **BYOC hosts.** Operator-owned BYOC backends are outside our patch
  cadence entirely — this runbook only covers hosts we provision
  (`terraform/gce/`, `terraform/modules/containarium/`). BYOC operators
  own their own kernel patch cadence; worth a line in the BYOC onboarding
  docs pointing back here as a "what we do, you should too" reference.
- **GPU hosts.** `docs/NODE-VM-PROVISIONING.md` already treats GPU/VFIO
  reboots as a distinct, manually-gated, partially-reversible operation.
  A kernel patch reboot on a GPU host should compose with that existing
  care, not bypass it.

## What this is NOT

- Not a replacement for the eBPF virtual-patching layer
  (`VIRTUAL-PATCHING-DESIGN.md`) — that mitigates network-reachable
  service vulnerabilities, a different threat class from a host-kernel
  LPE.
- Not a statement that the gap is acceptable — it's written down
  precisely so it doesn't quietly become the permanent answer.

## Related

- [`SECURITY-FAQ.md`](SECURITY-FAQ.md) — names the host-kernel LPE as the
  honest cost of shared-kernel isolation; this doc is what we do about it.
- [`VIRTUAL-PATCHING-DESIGN.md`](VIRTUAL-PATCHING-DESIGN.md) — the
  network-layer mitigation this runbook is explicitly not a substitute for.
- [`NETWORK-ISOLATION-DESIGN.md`](NETWORK-ISOLATION-DESIGN.md) — the
  loaded eBPF program #890 needs to sanity-check against after a live patch.
- [`OPERATOR-SECURITY-RUNBOOK.md`](OPERATOR-SECURITY-RUNBOOK.md) — day-to-day
  operator procedures; this doc should be linked from there once #889/#890
  give it more than a manual procedure to point to.
