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

`parseCPULimit` (post-#1034) gives every box with a **numeric** CPU request
(whole-core, millicpu, or decimal — not a manually pinned CPU-set) a
**hard** CFS quota — the kernel schedules exactly the declared share to
that box whenever it demands it, capped at that share. A CPU-set box
(`--cpu 0-3`) carries no allowance/quota at all (see the caveat later in
this section) and is out of scope for this argument. If the *sum* of every
co-located numeric-quota box's quota never exceeds the host's physical
capacity, then even under simultaneous full demand from every one of them,
CFS has enough total bandwidth to honor every one — which is precisely a
floor, delivered by hard quotas already in the tree, with no new primitive.

The gap is not a missing mechanism, it's that nothing today keeps committed
quotas within physical capacity: `internal/server/cpu_admission.go` (#1029
direction 2) already does exactly this job, but:

- it is **off by default** and only enforced once an operator opts in
  (`--cpu-overcommit-factor` + `--cpu-overcommit-enforce`, documented in
  `docs/CPU-CAPACITY-ADMISSION.md`). **The floor claim holds only for
  `--cpu-overcommit-enforce` on *and* a factor of `1` or less.** Advisory
  mode (`enforce=false`) blocks nothing, so committed quotas can still
  exceed capacity even with a factor configured. A factor greater than `1`
  is *deliberate* overcommit — `docs/CPU-CAPACITY-ADMISSION.md`'s own
  example (`--cpu-overcommit-factor 4 --cpu-overcommit-enforce`) explicitly
  permits committed quotas up to 4× physical capacity, which is the
  ceiling-only regime, not a floor. Any other configuration — including the
  default — should be described as ceiling-only or advisory, never as
  providing a floor;
- **it does not budget core-role containers.** `committedCoresExcluding`
  (the function both `CreateContainer`'s admission check and this design's
  proposed resize check use) explicitly skips every core-role container
  (`c.Role.IsCoreRole()`) — the platform's own Postgres/Caddy/control-plane
  containers, which carry real, non-trivial CPU requests today
  (`internal/server/core_services.go` sets `CPU: "2"`, `"1"`, `"1"`, `"4"`
  across the core services actually provisioned). So even a factor-1,
  enforced host can be pushed past its true physical capacity once core-infra
  CPU is added on top of a tenant-committed total that itself sits exactly
  at `physical × 1`. Closing this is an operator-configuration concern, not
  a code change this design scopes: set the tenant-facing factor low enough
  to leave headroom for the host's known core-infra footprint (e.g.
  `physical_cores − core_infra_cores`, expressed as a factor below 1), or
  treat `committed_cpu_cores` (item B below) explicitly as *tenant* capacity
  rather than total host capacity when sizing that headroom;
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

Closing the resize and visibility gaps is shape (2) from the issue, done
completely: not just per-box throttling counters (already in flight via
#1573/PR #1574) but the host-level overcommit signal those counters need to
be interpretable against, plus closing the resize-side hole in the gate
that actually produces the floor guarantee. The core-role and
factor-configuration points above are not new code — they are conditions an
operator must meet for the floor claim to hold, and this design states them
explicitly rather than letting "the gate is enabled" be mistaken for
"the floor is guaranteed."

## What this design adds

### A. Resize is admitted through the same gate as create

`ResizeContainer` (LXC path) calls `admitCPUCapacity` unchanged — the exact
function `CreateContainer` already calls — passing the resize's **full new
CPU value**, not a delta. This works with no new formula because
`committedCoresExcluding` already excludes the tenant's own current
container from the sum: admitting `newCores` against `committed_excl` is the
same "would this fit if the box were (re)created at this size" check create
already performs. A resize that does not increase CPU (`newCores ≤
currentCores`) skips the call entirely and is never blocked.

(An earlier draft of this section proposed checking `committed_excl + delta`
where `delta = newCores − currentCores`. That double-subtracts the tenant's
own current allocation — `committed_excl` already has it removed once, and
adding a delta computed against it removes it again — and silently admits
resizes it should reject. Worked example: an 8-core host at factor 1
(ceiling 8 cores), other tenants committing 4, this tenant currently at 4
(host exactly at the ceiling). Resizing to 8 should be **rejected** — the
true post-resize total is `4 + 8 = 12 > 8`. The delta formula computes
`4 + (8−4) = 8 ≤ 8` and wrongly admits. Passing the full `newCores` avoids
the bug entirely: `4 + 8 = 12 > 8` → correctly rejected. This is caught here
so it doesn't get carried into the implementation issue as a hidden
correctness bug.)

Three things this call site must account for that create's didn't have to:

- **The cluster reconciler shares this function.** `dual_server.go:1287`
  already wires `admitCPUCapacity` into `NewClusterReconciler(...).SetAdmission(...)`
  for cluster VM creation. The resize path must call the existing function
  as-is (or add a new function alongside it), not change
  `admitCPUCapacity`'s signature — a delta-aware or otherwise incompatible
  signature change breaks that call site silently. (Cluster VM *resize*, if
  the reconciler supports it, is not scoped here — a separate unguarded path
  to note but not fix in this pass.)
- **Peer-forwarded resizes must not check the wrong host.** `ResizeContainer`
  tries the container locally first and, only on a not-found error, forwards
  the request over HTTP to the peer that actually holds it
  (`internal/server/container_server.go`, the `peerPool.FindContainerPeer` /
  `ForwardRequest` block). The admission check must run only once the
  container is confirmed to live on **this** host — placed unconditionally
  before the local attempt, it would evaluate this host's committed cores
  against a container that isn't even here, and could reject a resize that
  the actual owning host (reached via the existing forward path) would have
  admitted fine. The forwarded HTTP call already re-enters the peer's own
  `ResizeContainer` handler, so once this fix lands there, the peer runs its
  own gate against its own host automatically — no forwarding-side admission
  logic is needed, only correct placement on the local side.
- **The exclusion is by tenant, not by container — a pre-existing
  imprecision, not a new one.** `committedCoresExcluding` excludes every
  container whose `Tenant` matches the given username
  (`c.Tenant == username`), not only the specific container being resized.
  `ContainerInfo.Tenant`'s own doc comment describes it as an explicit,
  independent ownership label (`user.containarium.tenant`), separate from
  container naming — so a tenant with more than one container under that
  label would have *all* of them excluded from the sum during a resize of
  just one, understating true commitment and potentially over-admitting.
  This is not introduced by reusing the function for resize: `CreateContainer`
  already has the identical exposure today. It is out of scope to fix here —
  doing so means threading a container identity (not just a tenant string)
  through the shared helper for every caller, a larger change than one
  resize-admission issue — but the follow-up issue and its test plan should
  say so explicitly rather than implying the check is airtight for every
  tenant shape.

This does not change the gate's off-by-default / advisory-first rollout
posture (`docs/CPU-CAPACITY-ADMISSION.md`'s existing guidance stands
unchanged) — it closes the specific hole where resize bypasses a gate that
create already goes through.

**Caveat on the floor guarantee's precision.** "Sum of hard quotas ≤
physical capacity ⇒ every box gets its declared share" assumes quota is
fungible across any physical core. In practice every numeric CPU request
also gets a `limits.cpu` cpuset (`Count`, sized `ceil(cores)` — see
`pkg/core/incus/cpu_limits.go`) confining its bandwidth to a specific set of
visible cores, and Incus periodically rebalances which physical cores back
that set. The floor is therefore accurate in aggregate and over time, not a
kernel-enforced instantaneous guarantee — momentary co-pinning onto the same
physical cores can still cause transient contention within a bounded-total
host. This doesn't change the recommendation (it is still a real,
substantially-better floor than today's none-at-all, and the alternative
knob discussed and rejected above doesn't offer a stronger guarantee
either), but the design should not be read as claiming a hard per-instant
kernel guarantee. Separately, a manually CPU-pinned box (`--cpu 0-3` set
notation) carries no allowance/quota at all and is unthrottled within its
pinned set — `CommittedCores`' cardinality count for such a box is a rougher
proxy of its real impact than the quota-based accounting used elsewhere;
this is a pre-existing property of `CommittedCores`, not something this
design changes or fixes.

### B. `SystemInfo.committed_cpu_cores`

New field on `SystemInfo` (proto/containarium/v1/config.proto, next field
number 24), populated by summing `incus.CommittedCores` over the host's
**tenant** containers (the same logic `committedCoresExcluding` already
has, minus the "exclude this tenant" parameter — a plain total, not an
admission check). Core-role containers (platform Postgres/Caddy/control-
plane) are excluded from this sum, same as they are from the admission
check — so `committed_cpu_cores` reports **tenant** capacity, not total
host capacity. This is deliberate, not an oversight: it is the number an
operator sizing a tenant-facing overcommit factor actually wants, and it
matches the core-role budgeting caveat in the section above — an operator
combining `committed_cpu_cores` with `total_cpus` to size a factor must
still separately account for the host's known core-infra CPU footprint,
the same requirement that applies to the admission gate itself. `total_cpus`
already exists on the same message; a caller derives the tenant-only ratio
as `committed_cpu_cores / total_cpus`, understanding that ratio does not
yet subtract core-infra. This is exactly the "read surface for current
commitment" `docs/CPU-CAPACITY-ADMISSION.md` already lists as a known gap,
not a new concept.

K8s runtime: `total_cpus` is already `0` there today (the Incus resource
read no-ops per that doc's "Runtime" note); `committed_cpu_cores` follows
the same no-op, `0` = "not applicable to this runtime," consistent with how
the rest of `SystemInfo` already degrades on K8s.

**Mixed-version peer fleet, acknowledged and accepted.** `GetSystemInfo`'s
peer fan-out (`container_server.go`, the `ForwardGetSystemInfo` /
`protojson.Unmarshal(body, &peerResp)` block) decodes each peer's JSON
response with default `protojson` options, which reject unknown fields — so
a daemon that hasn't yet upgraded to carry `committed_cpu_cores` in its
compiled proto will fail to parse a newer peer's response and drop that
peer from its fleet view entirely for the duration of a rolling upgrade
window. This is a real, generalizable characteristic of adding *any* field
to `SystemInfo`, not something specific to this one: the same exposure
already exists, unaddressed, for every prior addition
(`daemon_version` #354, `ssh_ingress_host` #1011, `storage` #1209). This
design does not introduce a new mixed-version compatibility scheme, because
no prior `SystemInfo` field addition has — that would be a separate,
larger piece of work (e.g. `DiscardUnknown: true` on the peer-forwarding
unmarshal, decided once for the whole message, not per-field) worth its own
issue if the rolling-upgrade window's fleet-visibility gap is judged worth
closing generally. `committed_cpu_cores` accepts the same transient
blind spot every other field already carries.

### C. Documentation: name the gate as the floor mechanism

`docs/CPU-CAPACITY-ADMISSION.md` gains a short paragraph stating explicitly
what section "Why hard quotas + bounded overcommit already are a floor"
above says: the declared CPU is a real floor **only** when the gate is
enforced (not merely advisory) at a factor of `1` or less, *and* the
operator has left headroom for the host's known core-infra CPU footprint on
top of that; any other configuration — including the off-by-default
posture, advisory mode, or a factor above `1` — is ceiling-only or
advisory, not a floor, and should be described as such rather than implied
to be safe. `containarium resize --help` and
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
- `internal/server/cpu_admission_test.go`: extend with a resize-admission
  test — table-driven, reusing the existing `seedServer` /
  `incustest.NewMockBackend` harness already in this file (see
  `TestAdmitCPURequest`, `seedServer`). Cases: a CPU-decrease (or unchanged)
  resize never calls admission and always proceeds regardless of host load;
  a CPU-increase resize is admitted/rejected by calling `admitCPUCapacity`
  with the resize's full new CPU value (not a delta) — including the
  boundary case from the worked example above (host exactly at ceiling,
  resize to a value that would exceed it once the tenant's own current
  allocation is added back in) to pin the bug the corrected formula avoids;
  and a resize forwarded to a peer (container not found locally) does not
  evaluate admission against the local host at all. Note in the test file
  (as a comment, not necessarily a new case) that the tenant-level exclusion
  is coarser than the single container being resized — pre-existing in
  `committedCoresExcluding`, not introduced here — so a future test covering
  a tenant with more than one container is a known gap, not silently assumed
  covered.
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
