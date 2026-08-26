# Design: CPU reservation and overcommit visibility

**Date:** 2026-08-27
**Status:** proposed
**Stack:** Go 1.26 + protobuf/gRPC (grpc-gateway); no frontend component; ships inside the existing daemon binary
**Issue:** #1571 — "No CPU reservation primitive: a box's declared CPU is a ceiling only — resize raises the ceiling, never the floor"

## Problem

#1571 observes that a box's declared `--cpu N` bounds the ceiling
(`limits.cpu` + a hard CFS quota, since #1034) but nothing guarantees it a
floor. On a contended LXC host a box can be delivered a small fraction of its
declared CPU, `resize --cpu` (the obvious remedy) is a no-op against that
kind of starvation, and there is no field anywhere that raises a box's
floor. The issue proposes two shapes to close the gap: (1) a genuine
reservation/weight knob, or (2) if a floor is out of scope, make the
ceiling-only semantics visible instead. This doc resolves which to build,
and states explicitly what happens to #1034's prior decision.

## Design decision

**Reject a new reservation/weight primitive. The declared CPU already
becomes an effective floor once host overcommit is bounded — ship the two
pieces that make the mechanism the codebase already has (hard CFS quotas +
the #1029 admission gate) actually deliver on that, instead of adding a new
Incus scheduling primitive.**

### Why `limits.cpu.priority` does not solve this (upholding #1034)

Read directly from Incus's own docs
(`doc/reference/instance_options.md`, "Allowance and priority"):

> `limits.cpu.priority` is another factor that is used to compute the
> scheduler priority score when a number of instances sharing a set of CPUs
> have the same percentage of CPU assigned to them.

Two facts follow, both verified (not assumed):

1. `limits.cpu.priority` only has an effect when `limits.cpu.allowance` is
   set in its **percentage** form (Incus's "generic CPU shares mechanism") —
   the form #1034 deliberately rejected in favor of the time-slice hard-quota
   form the codebase writes today (`pkg/core/incus/cpu_limits.go`). Applying
   the ordering knob would require reverting to the rejected mode for any box
   that wants it.
2. Even under the percentage form, priority is a **relative tie-breaker**
   among instances that already have the *same* percentage share and are
   contending for the *same* physical CPUs — not an absolute number of
   guaranteed cores. It cannot express "alice gets at least 500m" the way
   `--cpu-request` does on the K8s backend (#1557/#1572); it can only express
   "when alice and bob are tied, prefer alice."

So shape (1) as literally proposed — expose `limits.cpu.priority` — would
add API surface, a second CPU-allowance code path (percentage vs.
time-slice), and a two-tier CPU model (some boxes hard-quota'd, some
soft-shared with priority), all in exchange for a guarantee that is still
not absolute and reopens exactly the unbounded-burst failure mode #1034
fixed — this time selectively, per opted-in box, which is a harder invariant
to reason about than the uniform rule that exists today. **#1034's decision
is reaffirmed, not reconsidered**: hard CFS quotas stay the only allowance
form this codebase writes.

The only mechanism Incus has for an *absolute* CPU floor is exclusive core
pinning (`limits.cpu` as a CPU set, e.g. `"0-3"`) — already available today
via CPU-set notation, deliberately not the default because it forfeits the
density that is the LXC backend's reason to exist. This design does not
change that; pinning remains a manual, host-topology-aware escape hatch, not
something to automate here.

### Why hard quotas + bounded overcommit already are a floor

`parseCPULimit` (post-#1034) gives every box a **hard** CFS quota — the
kernel schedules exactly the declared share to that box whenever it demands
it, capped at that share. If the *sum* of every co-located box's quota never
exceeds the host's physical capacity, then even under simultaneous full
demand from every box on the host, CFS has enough total bandwidth to honor
every one of them — which is precisely a floor, delivered by hard quotas
already in the tree, with no new primitive.

The gap is not a missing mechanism, it's that nothing today keeps committed
quotas within physical capacity: `internal/server/cpu_admission.go` (#1029
direction 2) already does exactly this job, but:

- it is **off by default** and only enforced once an operator opts in
  (`--cpu-overcommit-factor` + `--cpu-overcommit-enforce`, documented in
  `docs/CPU-CAPACITY-ADMISSION.md`);
- it only runs on **create** (`container_server.go:578`) — a **resize** can
  push a host arbitrarily further past capacity with *zero* check, which is
  the sharper version of #1571's own repro ("`resize --cpu 16` succeeds ...
  delivers no additional CPU");
- there is no first-class way to **see** a host's current
  committed:physical ratio — an operator (or an agent) has no signal that
  the floor guarantee is or isn't being honored, which is exactly why
  "resize it bigger" reads as a plausible fix. `docs/CPU-CAPACITY-ADMISSION.md`
  already names this as a known follow-up ("A read surface for current
  commitment ... would let operators see a host's overcommit ... without
  grepping logs").

Closing those three gaps is shape (2) from the issue, done completely: not
just per-box throttling counters (already in flight via #1573/PR #1574) but
the host-level overcommit signal those counters need to be interpretable
against, plus closing the resize-side hole in the gate that actually
produces the floor guarantee.

## What this design adds

### A. Resize is admitted through the same gate as create

`ResizeContainer` (LXC path) calls `admitCPUCapacity` the same way
`CreateContainer` does, but checked against the **delta**
(`newCores - currentCores`), not the full new value — a resize that lowers
CPU, or one that doesn't touch CPU at all, is never blocked by admission.
`committedCoresExcluding` already excludes the tenant's own current
container from the sum, so the delta check composes with it directly: admit
iff `committed + delta ≤ physical × factor`.

This does not change the gate's off-by-default / advisory-first rollout
posture (`docs/CPU-CAPACITY-ADMISSION.md`'s existing guidance stands
unchanged) — it closes the specific hole where resize bypasses a gate that
create already goes through.

### B. `SystemInfo.committed_cpu_cores`

New field on `SystemInfo` (proto/containarium/v1/config.proto, next field
number 24), populated by summing `incus.CommittedCores` over the host's
tenant containers (the same logic `committedCoresExcluding` already has,
minus the "exclude this tenant" parameter — a plain total, not an admission
check). `total_cpus` already exists on the same message; a caller derives
the ratio as `committed_cpu_cores / total_cpus`. This is exactly the
"read surface for current commitment" `docs/CPU-CAPACITY-ADMISSION.md`
already lists as a known gap, not a new concept.

K8s runtime: `total_cpus` is already `0` there today (the Incus resource
read no-ops per that doc's "Runtime" note); `committed_cpu_cores` follows
the same no-op, `0` = "not applicable to this runtime," consistent with how
the rest of `SystemInfo` already degrades on K8s.

### C. Documentation: name the gate as the floor mechanism

`docs/CPU-CAPACITY-ADMISSION.md` gains a short paragraph stating explicitly
what section "Why hard quotas + bounded overcommit already are a floor"
above says: with the gate enabled at a factor an operator's workload
actually supports, the declared CPU is a real floor, not just a ceiling; with
the gate off (the default), it is a ceiling only, and that is a deliberate,
named trade-off rather than an oversight. `containarium resize --help` and
`containarium create --help` get one line pointing at the doc so an operator
hits the explanation at the point they'd reach for `resize --cpu` as a
remedy — directly answering the issue's own complaint that today's help text
("CPU: Always safe to increase or decrease") reads as though raising it
produces more CPU.

## What is explicitly NOT being built

- No `limits.cpu.priority` / percentage-allowance exposure of any kind —
  rejected above; #1034 stands.
- No per-box absolute reservation UI beyond what CPU-set pinning already
  provides manually.
- No cross-host / cluster-wide reservation scheduling. The gate is
  deliberately per-host, matching the existing pool-placement design
  (`--placement-cpu-aware` ranks peers by committed ratio but does not
  reserve across hosts).
- No change to the gate's off-by-default posture. Turning it on globally is
  an operator decision with fleet-specific consequences (per the existing
  doc's rollout section) — orthogonal to closing the resize-time hole and
  the visibility gap.

## Contracts

- `proto/containarium/v1/config.proto`: `SystemInfo.committed_cpu_cores`
  (`double`, field 24) — `make proto` regenerates `pkg/pb/`, the swagger
  doc, and the gateway shim.
- `internal/server/container_server.go`: `ResizeContainer`'s LXC path calls
  `s.admitCPUCapacity` (or a small delta-aware variant of it) before
  applying a CPU increase.
- `internal/server/cpu_admission.go`: factor the physical/committed lookup
  so both `CreateContainer` and the new `SystemInfo` populator share one
  source of truth (`hostPhysicalCores`, a `committedCores` with no
  exclusion for the report path vs. `committedCoresExcluding` for the
  admission path).
- Docs: `docs/CPU-CAPACITY-ADMISSION.md`, `internal/cmd/resize.go` and
  `internal/cmd/create.go` help text.

## Test strategy

- `pkg/core/incus`: no change (`CommittedCores` already covered).
- `internal/server/cpu_admission_test.go`: extend with a delta-based
  admission test — table-driven, reusing the existing `seedServer` /
  `incustest.NewMockBackend` harness already in this file (see
  `TestAdmitCPURequest`, `seedServer`). Cases: a CPU-decrease resize always
  admits regardless of host load; a CPU-increase resize is admitted/rejected
  by the same `physical × factor` rule as create, checked against the delta
  only (not the full new value); a resize that doesn't touch CPU never calls
  admission at all.
- New `TestSystemInfoCommittedCores` (or extend an existing
  `container_server_*_test.go`): seed a mock backend with known tenant
  containers via `seedServer`, assert `GetSystemInfo` returns
  `committed_cpu_cores` equal to the sum of their `CommittedCores`, and that
  core-infra containers are excluded the same way `committedCoresExcluding`
  already excludes them.
- Docs/CLI help text changes: no automated test (prose), reviewed by hand
  in the PR per this repo's normal doc-review path.

## Rejected alternatives

1. **Expose `limits.cpu.priority` + percentage soft-share as an opt-in
   "reserved" CPU mode.** Rejected: does not deliver an absolute floor (only
   a relative tie-breaker among equal-percentage neighbors, per Incus's own
   docs), reopens #1034's unbounded-burst problem for any box that opts in,
   and requires a second CPU-allowance code path plus new proto/CLI surface
   for a guarantee that is still weaker than what bounded overcommit already
   gives for free.
2. **Exclusive CPU pinning as the general default.** Rejected: forfeits the
   CPU density that is the LXC backend's value proposition; remains
   available today as a manual escape hatch (`--cpu 0-3` set notation) for
   an operator who wants it for one specific box.
3. **Ship only #1573's per-box throttling counters and stop there.**
   Rejected: leaves the resize-time admission hole open (a resize can widen
   a ceiling on an already-saturated host with zero capacity check — a
   sharper cousin of the bug #1572 just fixed on the K8s side) and leaves an
   operator with per-box throttling numbers but no host-level context to
   interpret them against (is this box throttled because *it* is
   oversubscribed, or because the whole host is?).

## Next steps

File as follow-up issues for `/engineer:implement`, in priority order:

1. **Resize admission (item A).** Closes the sharper, resize-side half of
   #1571's own repro. Small, self-contained, reuses existing test harness.
2. **`SystemInfo.committed_cpu_cores` (item B).** Proto + regen + one
   summing function reused from the admission gate.
3. **Docs/CLI help updates (item C).** Bundle with either 1 or 2, or ship
   standalone — no code dependency.

#1571 itself should stay open (or be re-scoped to track item 1, the
resize-admission gap) rather than being closed by this design doc alone —
none of the above is implemented yet.
