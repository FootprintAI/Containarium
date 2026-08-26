# Results

This file holds the reviewed, committed summary of actual benchmark runs —
not the raw per-run logs (those land under `results/`, gitignored, one
timestamped file per run; see `scripts/lib.sh`'s `resource_snapshot` /
`run_density_loop`). Copy the relevant numbers here once a run is complete
and worth keeping as a reference point.

### 2026-08-23 — bare-metal, AMD Ryzen 9 5900X (12c/24t), 125GB RAM host

Hard cap per VM: 8 vCPU / 48GiB RAM / 200GB disk (Incus KVM VM)
Sandbox profile: cpu 100m/200m, mem 128Mi/256Mi (control); cpu 200m mem 256Mi request==limit (Containarium — see "Fairness notes")
Containarium version: v0.66.0    Agent-sandbox version: v0.5.1    K8s version: v1.30.14 (kubeadm)
Both groups ran under the same `runsc` (gVisor) RuntimeClass — see README.md "What's actually under test".

| | k8s + agent-sandbox (control) | Containarium (experiment) |
|---|---|---|
| Sandboxes reached Ready/RUNNING | **69** | **34** |
| Attempted (incl. failures) | 72 | 37 |
| Node CPU requests at stop | 8000m / 8000m (**100%**) | 7900m / 8000m (**98%**) |
| Node memory at stop | 18% | 18% |
| Wall-clock for the density loop | ~7 min | ~5 min |
| Image | `busybox:1.36` | `containarium-agent-box:v0.66.0` (see "Fairness notes" — required, not a choice) |

**Both sides were CPU-request-bound, not memory-bound** — memory sat at
18% on both when the stopping rule triggered; the ceiling in both cases
was Kubernetes CPU admission, confirmed via `kubectl describe node`
"Allocated resources" at the stopping point.

**The ~2x gap tracks the CPU-request asymmetry almost exactly, not
gVisor.** Containarium's boxes request 200m each (`create --cpu/--memory`
sets request==limit, no separate request knob); the control group's pods
request only 100m each (limit 200m). 69 × 100m ≈ 6900m + ~1100m system
overhead ≈ 8000m (100%); 34 × 200m = 6800m + similar system overhead ≈
7900m (98%). Halving the control group's count (69/2 ≈ 34.5) lands almost
exactly on Containarium's actual result (34) — consistent with the
documented prediction in README.md's "Fairness notes" that this asymmetry
should roughly halve Containarium's density, independent of gVisor.

**gVisor confirmed live on every unit, both sides** — `uname -r` inside a
sample pod from each group returned `4.19.0-gvisor`; the post-run
"pods by RuntimeClass" snapshot in each run's raw log
(`results/*.md`, gitignored) shows every `sbdens-*`/`box` pod scheduled
under `runsc`.

Notes / anomalies:
- This was the first real end-to-end run of these scripts and surfaced
  (and fixed, in earlier commits on this PR) several real bugs along the
  way: the base VM image ships without sshd/cloud-init; a `kubectl wait`
  race on Calico pods; gVisor registered under the wrong containerd
  plugin ID on containerd v2.x; `jq`/`git` missing from the base image;
  a Helm chart bug where `gateway.namespace=""` breaks install outright;
  `create`'s default `--image` isn't valid on the k8s backend
  (filed [#1524](https://github.com/FootprintAI/Containarium/issues/1524));
  and `containarium list` is entirely broken on the k8s backend
  (filed [#1525](https://github.com/FootprintAI/Containarium/issues/1525)).
  The chart bug is filed as [#1526](https://github.com/FootprintAI/Containarium/issues/1526).
  None of these affect the validity of the numbers above — all were
  provisioning-time or CLI-ergonomics issues, worked around before the
  density loops ran — but they're worth fixing upstream regardless of
  this benchmark.
- `kubectl top nodes` was unavailable (no metrics-server installed) — CPU
  request/limit accounting from `kubectl describe node` was used instead,
  which is what actually gates scheduling anyway.
- Neither side hit the sandbox-resource-profile's *memory* limit at all;
  a re-run with a much higher `VM_CPUS` (see README.md's estimation
  discussion) would more directly isolate gVisor's own per-pod cost from
  the CPU-admission ceiling, since CPU is the bottleneck at this VM size.
  **Done below — see the 2026-08-24 run.**

### 2026-08-24 — same host, memory-bound re-run (isolating gVisor's own cost)

Hard cap per VM: **20** vCPU (up from 8 — near this host's physical 12c/24t
ceiling) / 48GiB RAM / 200GB disk (Incus KVM VM)
Sandbox profile: cpu **25m/50m** (down from 100m/200m — see rationale
below), mem 128Mi/256Mi unchanged
Containarium version: v0.66.0    Agent-sandbox version: v0.5.1    K8s version: v1.30.14 (kubeadm)
Both groups again ran under the same `runsc` (gVisor) RuntimeClass.

**Why the sandbox CPU profile changed, not just `VM_CPUS`:** the prior run's
own numbers proved `VM_CPUS` alone can't flip the bottleneck on this host —
reaching each side's *memory*-request ceiling needs ~37 cores of headroom
(see the estimation discussion this PR's README added), and this host only
has 12 physical cores. Shrinking the per-sandbox CPU request instead
(100m/200m → 25m/50m, keeping the memory profile fixed) achieves the same
goal — memory becomes binding — without needing a bigger host.

| | k8s + agent-sandbox (control) | Containarium (experiment) |
|---|---|---|
| Sandboxes reached Ready/RUNNING | **373** | **186** |
| Attempted (incl. failures) | 376 | 189 |
| Node memory requests at stop | 47984Mi / 48GiB (**99%**) | 47856Mi / 48GiB (**99%**) |
| Node CPU requests at stop | 10425m / 20000m (52%) | 10400m / 20000m (52%) |
| Wall-clock for the density loop | ~15 min | ~15 min |

**Memory is now genuinely the bottleneck on both sides** (99%/99% memory
vs. 52%/52% CPU at the stopping point) — the flip the re-scoped profile was
designed to produce.

**The ratio holds: 373 vs. 186 is almost exactly 2:1**, same as run 1's 69
vs. 34 — because both runs are ultimately gated by the same underlying
asymmetry (control's pods request `128Mi`; Containarium's boxes request
`256Mi`, exactly 2x, since `create` sets request==limit). **This is the
clean isolation the re-run set out to get:** with CPU pressure removed,
the density gap is *still* explained by the request-size asymmetry, not by
gVisor's per-pod memory overhead — 373 × 128Mi ≈ 46.6GiB and 186 × 256Mi ≈
46.5GiB, i.e. both sides used essentially the *same total memory budget*,
just divided into differently-sized chunks. gVisor's own per-pod cost, if
any, is too small to see against a 128–256Mi request granularity — a
future run using `top`/cgroup memory accounting instead of request-based
admission would be needed to measure it directly.

Notes / anomalies:
- Same fixes from run 1 applied cleanly with no new manual intervention —
  provisioning both VMs was fully automated this time end-to-end.
- `containarium-agent-box` image and gateway workaround unchanged from run 1.

### 2026-08-24 — third scenario: Containarium native LXC workhorse (no k8s, no gVisor)

Hard cap per VM: 20 vCPU / 48GiB RAM / 200GB disk (Incus KVM VM)
Sandbox profile: cpu 200m (LXC-scenario-specific floor, see README.md "Third
scenario"), mem 256Mi — same declared ceiling as the other two runs' Containarium side.
Containarium version: local build off `main` + this scenario's fixes (image-bake #1037, list() concurrency #1532/#1533).
Backend: native LXC/Incus, no Kubernetes, no gVisor, no pooling (#1488/#1523 out of scope — see README.md).

Run in four segments — each of the first three stopped on something that
turned out to be a bug or an unsized default, not a resource wall, so each
was resumed (`--start-index`, added for exactly this) after fixing the
problem live rather than treated as final. Only the fourth segment hit a
wall that held up:

| | seg 1 (#1532 bug) | seg 2 (real /24 wall) | seg 3 (self-inflicted pg_hba gap) | seg 4 (real wall) | **combined** |
|---|---|---|---|---|---|
| Sandboxes reached RUNNING | 181 | 70 | 313 | 5 | **569** |
| Attempted (incl. failures) | 186 | 73 (from 184) | 317 (from 260) | 13 (from 580) | 589 |
| Wall-clock | ~87 min | ~17 min | ~2h23min | ~33 min | ~4h |

**Final host state (569 tenant + 2 core = 571 containers):** memory 39GiB/46GiB
used (7.9GiB reclaimable buff/cache, 1.0GiB genuinely free), i.e. still not
memory-exhausted. Per-container actual memory grew from ~50MiB (at 181) to
~90-95MiB (at 253) to higher still by 571 — noted but not root-caused.
**What actually stopped segment 4 was CPU, and specifically not the tenant
containers' own CPU** (each capped at 200m) — `incusd` itself was consuming
1025% CPU (10+ cores) on the 20-core host, driving a load average of ~117
(≈6x the core count) purely from Incus's own per-container management
overhead at ~570 live containers. Filed #1541. Load dropped to ~43 within
~15 minutes of the loop stopping, confirming it's churn-driven contention
scaling with container count, not a permanent steady-state cost — but a
real wall a production single-host deployment would hit regardless of
available RAM.

**This number is still not directly comparable to the other two scenarios'
counts as a ranked table** — six distinct things were learned pushing it
this far:

1. **Per-create latency was never about scanning.** Individual creates
   originally took ~80-150s. ClamAV/pentest/zap scanning was a plausible
   early hypothesis (a controlled test with them fully disabled showed no
   improvement) — the real cost was a from-scratch OS boot + `apt-get
   install` of the base package set on every single create, on the stock
   cloud image (confirmed via `systemd-analyze` + `/var/log/apt/history.log`).
   Containarium already ships the fix for this (#1037, `containarium
   image-bake`) — the provisioning script just never called it. Baking once
   and re-testing: **112s -> 15.7s** for an identical create. Filed #1530
   documenting the investigation for anyone else who hits this.

2. **Segment 1 didn't stop on a resource wall — it stopped on a `list()`
   scaling bug.** k8s's scheduler reserves the full *declared* memory
   request against node capacity regardless of actual usage (why the other
   two runs stopped almost exactly at `48GiB / declared-request`); Incus's
   `limits.memory` is a cgroup *ceiling*, not a reservation, so the boxes'
   ~50MiB actual usage left plenty of real headroom at 181. What actually
   stopped it: `containarium list` (which the density loop polls for
   `RUNNING` state) started intermittently exceeding a 10s deadline past
   ~180 containers — `ListContainers` made 2 sequential Incus API
   round-trips per container, ~360 sequential calls at that count. Filed
   #1532, fixed in #1533 (bounded-concurrency fetch instead of
   sequential — 32 at a time). Live-verified the fix against this exact
   host: **>10s (timeout) -> consistently under 2s** for the same `list`
   call at 181 containers.
3. **Resumed past the fix with `--start-index 184` and pushed to a real
   wall.** Segment 2 stopped on an actual `create` rejection this time —
   `failed to get container IP: timeout waiting for container network`.
   The bridge (`incusbr0`) is a `/24` (`10.183.188.1/24`, 253 usable
   addresses); the host had exactly 253 containers (251 tenant + 2 core)
   when it stopped. **This is a genuine, real resource wall** — DHCP
   address space, not a bug — and matches the very first hypothesis from
   when segment 1 stopped (before #1532 was found and fixed), now
   confirmed precisely rather than guessed.
4. **This wall isn't a fair fixed comparison point either — the k8s side
   never had a /24 to begin with.** The k8s scenarios' `podSubnet` is
   `192.168.0.0/16` (`scripts/k8s-common.sh`) — 65,536 addresses, 256x
   Incus's default `/24`. Calico also allocates in small per-node blocks
   (default /26, 64 addresses) and grabs more as pod count grows, so a
   single node never hits a flat ceiling the way one static Incus bridge
   subnet does. This is an unsized default, not a discovered limitation:
   Incus's bridge subnet is a config choice (`ipv4.address` on network
   create) — a `/20` (~4094 usable) or `/16` (~65534 usable, matching the
   k8s side) would move this ceiling substantially with no code change.
5. **Widened `incusbr0` to a `/16` live (`10.183.0.1/16`, keeping the
   existing `10.183.188.0/24` range as a subset so the 253 already-running
   containers' leases stayed valid) and resumed — this immediately hit a
   self-inflicted problem, not a new discovery.** `containarium-core-postgres`'s
   `pg_hba.conf` had a rule scoped to exactly `10.183.188.1/24`; once the
   bridge's own gateway/source IP became `10.183.0.1` (outside that /24),
   the daemon's own Postgres connections started failing
   (`FATAL: no pg_hba.conf entry for host "10.183.0.1"`), breaking cluster
   reconcile, passthrough sync, and token revocation lookups — which
   degraded overall daemon responsiveness enough to cause a run of
   readiness timeouts. Fixed live (widened the `pg_hba.conf` rule to
   `10.183.0.0/16`, reloaded), verified via journalctl (errors stopped
   immediately), and resumed again. Not filed as a Containarium issue —
   this is benchmark-environment fallout from resizing the network
   ourselves, not a bug in the shipped product.
6. **The real, final wall: Incus's own daemon CPU overhead, not memory,
   not network, not the tenant workload.** After the pg_hba fix, segment 3
   ran cleanly to 313 (562 combined) before a batch of failures right at
   the fix boundary (already-started units that had blown their timeout
   during the outage). Segment 4 resumed once more and found the actual
   ceiling: at ~570 containers, `incusd` alone consumes 10+ CPU cores
   (1025% CPU, load average ~117 on a 20-core host) — see point-by-point
   detail above and #1541. This is the first wall in this investigation
   that isn't a fixable default or a script bug.

Also found and filed independently (real, applies beyond this benchmark):
#1531, host-side jump-server account creation has been silently failing
since roughly the 10th tenant created on any one host (a `useradd`
subuid/subgid pool collision with Incus's own reserved root range) — the
large majority of this run's 569 tenants have no SSH jump-server account,
with only a warning-level log line as a signal. Not yet fixed (proposed
fix documented on the issue).

Notes / anomalies:
- Not a test of #1488's warm-pool/pooling feature — confirmed not wired
  (`SpawnSandbox` still serves the Phase 1 cold path, see #1523). This
  measures the same cold-create path #1522/#1527 already cover on the k8s
  backend, on Containarium's original backend instead.
- `--podman=false` used for creates (the default installs Podman + pip +
  podman-compose, an asymmetry vs. the other two scenarios' create-time
  cost — see the density script's header comment for the full rationale).
- Scanner subsystems (ClamAV/pentest/zap) disabled via
  `--disable-{security,pentest,zap}-scanner` daemon flags (independent
  product feature, not benchmark-specific — real background CPU
  competition worth avoiding for a clean measurement, even though it
  wasn't the create-latency root cause).
- Sharding across multiple smaller Containarium daemon instances (sentinel
  routing tenants to the right backend, per the existing multi-backend
  architecture) was discussed as an alternative to one large host, but
  wouldn't have avoided the #1531 subuid wall — that one bites per-host at
  ~10-14 tenants, well under any reasonable shard size. Not attempted in
  this run.

### 2026-08-25 — #1541 fix verification: fresh run with `get`-based polling + forced zfs

Same host, VM profile, and sandbox profile as the run above. Goal: confirm
whether #1543's `containarium get` (O(1) single-container lookup, replacing
`list`'s O(N)-per-poll cost in `box_ready()`) actually reduces the Incus
daemon CPU overhead #1541 found — live, on a fresh VM, rather than just by
code inspection.

**First attempt hit a different, unrelated bug**: `incus admin init --auto`
picked the "dir" storage driver again despite zfsutils-linux installed and
the zfs kernel module loaded (the SAME condition that picked zfs
successfully in an earlier run — auto-detection is not reliable). Stopped
at 215 containers on "Unable to unpack image, run out of disk space" (no
copy-on-write with "dir"). Fixed by requesting `--storage-backend=zfs`
explicitly instead of trusting `--auto` (script fix, same PR as the `get`
polling switch).

**Second attempt, with zfs forced + `/16` bridge + `get`-based polling —
reached 931 sandboxes** (936 attempted) before the daemon's Incus
management process itself was OOM-killed by the kernel (`dmesg`: `Out of
memory: Killed process 4343 (incusd)`) — a hard stop, not a graceful
per-unit rejection.

| container count | this run's load average | the original run's load average (same rough point) |
|---|---|---|
| ~180 (unfixed run's #1532 stop) | — | timeout/degraded (list() itself exceeded 10s) |
| ~400 | 13.9-19.1 | not directly comparable (unfixed run never reached this cleanly) |
| ~552-570 | 32-40 | **~117** (unfixed run's peak, at 569 total) |
| ~762 | 125-182 | n/a — unfixed run had already stopped by here |
| ~931 | OOM-killed `incusd` | n/a |

**The `get`-based fix is real and substantial, not a full fix.** At the
directly comparable point (~570 containers), load average dropped from
~117 to ~32-40 — roughly 3x lower. But load still climbed and eventually
exceeded the old peak, just at a meaningfully higher container count
(~762 vs. 569, a ~34% higher ceiling before hitting a comparable wall).
The remaining, still-unaddressed contributor: `internal/traffic.
ContainerCache`'s background refresh (`internal/traffic/collector.go`,
`StartRefresh(ctx, 30*time.Second)`) does its own unconditional full
`ListContainers()` call every ~30s regardless of container count or
activity — confirmed still running on this cadence throughout the run via
its own "Container cache refreshed: N containers" log line. This is
independent of anything the benchmark's own polling does, and is a
genuine remaining candidate for a follow-up fix (e.g., an
incremental/delta refresh, or an interval that backs off with N).

**The true final wall this time was real, severe memory exhaustion** —
not a software bug, not a config default. Per-container actual memory
usage grew over the run (~50MiB at 181 in the earlier run → ~90-100MiB by
253-571 → presumably higher still by 931), and at just under 1000
containers the aggregate consumed essentially the entire 46GiB host,
severely enough that the kernel OOM-killed `incusd` itself rather than a
single tenant container. Not root-caused further (why per-container
memory keeps growing over a run's lifetime — journal/log accumulation
inside each idle container is one plausible candidate, not confirmed).

**How this compares to the k8s + agent-sandbox control group's 373**:
931 is over 2x that number, but — same caveat as documented above, worth
repeating because it's easy to miss in a single "which is bigger" glance
— the two are not admission-bound the same way. k8s reserves the full
*declared* 128Mi request per pod regardless of actual usage; Incus's
`limits.memory` only enforces actual usage against a 256Mi ceiling. This
run's boxes only ever used ~90-100MiB (a fraction of what k8s would have
reserved for a similarly-sized pod), which is *why* it could pack more —
a real, legitimate operational property of Incus's cgroup-ceiling model,
not evidence that gVisor/orchestration overhead makes k8s "worse."

Filed follow-up: #1541 updated with this finding rather than a new issue
(same underlying investigation, refined conclusion — see the issue for
the full comment history: what got fixed, what's still open, and why the
daemon-CPU framing in the issue's original title turned out to be only
part of the picture).

### 2026-08-25 — #1541's second fix verified: `ContainerCache` incremental refresh

Same host and profile as the two runs above. #1546 made `internal/traffic.
ContainerCache`'s background refresh incremental (O(Δ) instead of O(N) per
~30s cycle — only genuinely new/changed container names are re-fetched from
Incus, not the whole fleet every tick) — this run confirms its effect live,
on a fresh VM, against the exact same checkpoint counts as the prior run.

| container count | get-fix-only run (previous) | both fixes (this run) |
|---|---|---|
| ~365-400 | load ~19, `incusd` 914% CPU | load 4-8, `incusd` 48% CPU |
| ~430 | load ~26 | load ~11 |
| ~548-570 | load 32-40 | load 15-21 |
| ~760-762 | load 125-182 (exceeded the *original* unfixed run's peak) | load 38-40 — the wall that reappeared here before is gone |

**Result: 929 sandboxes reached RUNNING** (933 attempted) — essentially
identical to the previous run's 931, confirming the memory ceiling is a
real, reproducible physical limit independent of the CPU fix, not
something either fix should (or does) move. The stop was cleaner this
time: journalctl showed Postgres and internal daemon operations timing
out (`context deadline exceeded`) under severe memory pressure, but
`dmesg` recorded no kernel OOM-kill of `incusd` this run (vs. the
previous run, where it did) — plausibly because `incusd` itself now runs
with a smaller memory footprint under load, so it wasn't the OOM
killer's top-scored target this time. Same underlying cause (the host
ran out of real RAM at ~930 tenants), different specific casualty.

**Both #1541 fixes compound as designed**: the `get`-based polling
fix (#1543) cut load roughly 3x at mid-scale; the `ContainerCache`
incremental-refresh fix (#1546) removed the remaining climb that
previously reappeared past ~600 containers, holding load flat (single
digits to ~40) all the way to the same real memory ceiling both runs
independently found. #1541 is now fully closed out — every identified
contributor has a landed, live-verified fix; the memory ceiling itself is
a genuine hardware limit, not a bug.

### 2026-08-25 — reproducibility check: k8s + gVisor + Containarium re-run

The second scenario (`pod -> gVisor -> containarium`, the real integration
path — see README.md's original scoping) was re-run from scratch on a
fresh k8s cluster, this time with a daemon image built from current `main`
(carrying every #1541-adjacent fix — #1529, #1533, #1542, #1543, #1546 —
plus everything else merged since v0.66.0) and the matching current Helm
chart, rather than the pinned v0.66.0 release used originally.

**Result: 186 sandboxes reached RUNNING, 189 attempted — an exact match**
to the original 2026-08-24 run's numbers, down to the node memory
snapshot at the stopping point (47856Mi/48GiB, 99%, identical both times).
None of the #1541-related daemon fixes moved this number, which is
exactly what should happen: this scenario's ceiling is Kubernetes' own
memory-request admission control (`48GiB ÷ 256Mi ≈ 186`), not daemon
performance — the daemon-side bugs found and fixed in the third scenario
never had anywhere to bite here.

One environment-only snag hit and worked around, not a product bug: the
provisioning script's git-cloned chart is pinned to the resolved
`CONTAINARIUM_VERSION` release tag (v0.66.0), which predates the Helm
chart's `gateway.upstreamKeySecret` -> `CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET`
env var wiring. Swapping in a current-`main`-built daemon image against
that old chart crash-loops the pod (the newer binary validates the env
var; the old chart never sets it). Re-pointing the chart clone at `main`
instead of the pinned tag resolved it — a real thing to note for anyone
mixing a custom daemon build with an old chart checkout, not something
this benchmark's scripts needed to change (they use matched
chart+binary versions by design).

This confirms the blog draft's 186 figure is solid and independently
reproducible, not a one-off measurement.

### 2026-08-26 — #1558: isolating gVisor's own density cost (request-matched)

Every prior k8s+Containarium run (including the "reproducibility check"
above) used `create --memory 256Mi` with no separate request — before
#1557 there was no flag to set one, so every Containarium box was pinned
to request==limit (256Mi), double agent-sandbox's own pods' 128Mi
request. That asymmetry, not gVisor, was the entire explanation for
186-vs-373. #1557 added `--memory-request`/`--cpu-request`; this run
uses them to set Containarium's boxes to the *same* profile as
agent-sandbox's pods — request 128Mi / limit 256Mi, cpu request 25m /
limit 50m (`SANDBOX_MEM_REQUEST`/`SANDBOX_CPU_REQUEST` in
`config.env.example`, wired into the create call by a script fix,
[#1561](https://github.com/FootprintAI/Containarium/pull/1561)) — then
runs the identical profile twice on the identical cluster: once under
`gVisor` (`runtimeClass: runsc`), once under plain `runc`. If the two
counts match, gVisor's own per-pod density cost is negligible at this
sandbox size and the whole 186-vs-373 gap really was the declared-size
asymmetry, full stop. If they differ, that delta is gVisor's own cost.

**Methodology deviation from the first three scenarios, deliberate:**
one VM/cluster reused for both legs, not two freshly-provisioned VMs.
The first three scenarios needed separate VMs because they compared
different *systems* (agent-sandbox vs. Containarium, or k8s vs. no k8s);
this run toggles exactly one variable (`runtimeClass`) on the *same*
system, so a fresh VM per leg would add provisioning noise without
isolating anything extra. Between legs: every `tenant-sbdens-*`
namespace was deleted and confirmed gone (`kubectl get ns` count back to
0), node `Allocated resources` confirmed back to baseline (240Mi/48GiB
memory requests — just system pods), then `helm upgrade --reuse-values
--set runtimeClass=""` flipped the daemon to schedule new boxes on
plain `runc`, and the daemon pod's rollout was confirmed healthy before
starting the second leg.

Host cap and versions unchanged from the runs above (20 vCPU / 48GiB RAM
/ 200GB disk Incus KVM VM). Daemon built from
`feat/1557-memory-cpu-request` (commit `c009427`, PR
[#1560](https://github.com/FootprintAI/Containarium/pull/1560), open at
the time of this run) — carries #1557 plus everything on `main` as of
that branch point. Helm chart at `main`.

| | gVisor (`runsc`) | plain `runc` |
|---|---|---|
| Sandboxes reached RUNNING | **373** | **373** |
| Attempted (incl. failures) | 376 | 376 |
| Node memory requests at stop | 47984Mi / 48GiB (**99%**) | 47984Mi / 48GiB (**99%**) |
| Node CPU requests at stop | 10425m / 20000m (52%) | 10425m / 20000m (52%) |
| Wall-clock for the density loop | ~77 min | ~40 min |
| Pod RuntimeClass (sanity check) | `runsc` on all 373 | `<none>` on all 373 |

**Exact match: 373 vs. 373, identical node memory snapshot down to the
Mi.** This is as clean a confirmation as this kind of live benchmark
ever produces. It also lands within a rounding error of agent-sandbox's
own control-group result (373, from the 2026-08-24 run) — with the
request/limit asymmetry removed, Containarium's k8s+gVisor path doesn't
just close the gap with agent-sandbox, it matches it almost exactly.
**gVisor's own per-pod density cost is not measurable at this sandbox
size (25m/50m CPU, 128Mi/256Mi memory) against a 48GiB host** — every
prior 186-vs-373 comparison was measuring the declared-size asymmetry
end to end, not gVisor overhead, exactly as the original write-up
theorized but couldn't rule out.

**The one real difference between the two legs was wall-clock, not
density: ~77 min (runsc) vs. ~40 min (runc), roughly 2x.** Same total
work, same stopping point, but gVisor's per-pod sandbox startup cost
measurably slows down how fast the cluster gets *to* that density —
without changing how *dense* it can get. A real, separate cost worth
knowing about (create latency, not packing efficiency), consistent with
gVisor's own documented syscall-interception overhead.

**Implication for the blog draft:** the "186 vs. 373, Containarium is
the smaller one" framing was accurate for the profile actually shipped
at the time (`create` with no request/limit split) but is now stale —
with #1557 available, a fairly-configured Containarium k8s+gVisor
deployment matches agent-sandbox's density, not half of it. The 186
number was a real, honestly-reported result of a real CLI gap, not a
measurement error; #1557 closes that gap. `BLOG-DRAFT.md` needs a
follow-up pass to fold this in before it's treated as final.

### 2026-08-26 — sentinel-statefulset: the real topology, benchmarked

README.md's "The experiment group's k8s footprint" describes Containarium's
k8s deployment mode as conceptually `Service → Deployment
(containarium-sentinel, traffic forwarding) → StatefulSet
(containarium-daemon, provisions boxes)` — three k8s-native layers in front
of box provisioning, versus the third scenario's single bare process. That
was prose with no number behind it. This run builds it for real and
measures what it actually costs.

**This is a benchmark-only exploration, not a production chart change** —
`charts/containarium-k8s/` is untouched. The daemon is stateless (no PVCs,
all durable state in the k8s API/etcd via CRDs), so a StatefulSet buys it
nothing architecturally; there is no real `containarium-sentinel` binary
that forwards HTTP/gRPC to the daemon's own API (`internal/sentinel` does
something unrelated — iptables DNAT to spot VMs — see
`manifests/sentinel-statefulset/README.md`). The sentinel here is a stock
`nginx:1.27-alpine` reverse proxy standing in for one. New files only:
`manifests/sentinel-statefulset/`, `scripts/07-provision-containarium-sentinel.sh`,
`scripts/08-run-density-containarium-sentinel.sh`.

How the daemon's container spec got into the StatefulSet without
hand-duplicating Helm's env-var logic: `helm install` the real chart with
`daemon.replicaCount=0` (so its own Deployment never runs a pod), read
back the resulting (0-replica but fully-specced) Deployment with `kubectl
get -o json`, and reshape `spec.template.spec` into a StatefulSet with
`jq` — the container spec is copied exactly, not re-typed.

Same host cap as every other k8s scenario (20 vCPU / 48GiB RAM / 200GB
disk Incus KVM VM), same profile as the 373 baseline (cpu 25m/50m, mem
request `128Mi` / limit `256Mi` via #1557's `--memory-request`/
`--cpu-request`).

**Daemon version snag, found live, same shape as the #1558 entry above:**
the CLI and daemon image this VM resolves via `CONTAINARIUM_VERSION=latest`
are the last *released* tag (v0.66.0) — #1557 is on `main`, unreleased.
`containarium create --cpu-request ...` failed outright with `unknown
flag`. Built a `containarium` CLI binary from the current `main` checkout
(`go build cmd/containarium/main.go` — needed `docker run --network=host`
for the build container too; same TLS-over-bridge-network issue the
#1558 daemon image build hit) and reused the `containarium-daemon:bench-1558`
image already built for that earlier run (same #1557 source, still
functionally current). Swapping the image surfaced a second, unrelated
issue: the newer daemon binary enforces #1496's upstream-gateway-key
startup check more strictly than v0.66.0's build did, and the
`CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET`/`_PUBLIC_KEY` env vars
were absent from the reshaped StatefulSet even though the same `helm
install --set gateway.upstreamKeySecret=...` flags 03's proven pattern
uses were passed — recovered the public key from the already-created
Secret (`ssh-keygen -y`) and patched both env vars onto the StatefulSet
directly. Not yet root-caused *why* the values didn't land in the first
place (a Helm `--set` edge case with the specific value shape, or a
timing issue in this script's install step) — flagged, not chased
further, since the workaround is clean and the resulting container spec
is byte-identical to what 03's own pattern produces.

**Third issue, also found live: nginx's static DNS resolution.** The
sentinel's `proxy_pass` targets the daemon StatefulSet pod's own DNS name
(`containarium-bench-daemon-0.containarium-bench-daemon-headless`) —
nginx resolves that hostname *once*, at container startup, and caches the
IP for its lifetime. Restarting the daemon pod (twice, chasing the two
issues above) gave it a new IP each time, silently stranding the
sentinel's cached resolution — `upstream timed out` on every request
until the sentinel itself was restarted. Fixed by restarting
`containarium-bench-sentinel` once daemon was finally stable, immediately
before the density loop. A production sentinel would need dynamic
resolution (nginx's `resolver` directive + a variable in `proxy_pass`) to
survive pod restarts; not needed for a one-shot measurement where nothing
restarts mid-run.

| | plain Deployment (baseline) | sentinel-statefulset |
|---|---|---|
| Sandboxes reached RUNNING | **373** | **373** |
| Attempted (incl. failures) | 376 | 376 |
| Node memory requests at stop | 47984Mi/48GiB (99%) | 47984Mi/48GiB (99%) |
| Node CPU requests at stop | 10425m/20000m (52%) | 10425m/20000m (52%) |
| Wall-clock for the density loop | ~15 min (original run) / ~77 min (#1558's runsc leg, same profile) | ~77 min |
| Pods by RuntimeClass (sanity check) | `runsc` on all 373 | `runsc` on all 373 |

**Exact match — 373 vs. 373, identical node memory snapshot down to the
Mi.** The extra Service → Deployment(sentinel) → StatefulSet(daemon) hop
is invisible to density: the bottleneck is still k8s memory-request
admission for sandbox pods, which this topology change doesn't touch at
all. Wall-clock also landed within noise of the #1558 runsc leg's ~77
minutes (same profile, same gVisor cost, no sentinel) — an extra
in-cluster HTTP hop through nginx per `create` call didn't move the
needle against gVisor's own per-sandbox startup cost, which already
dominates that number.

**What this settles and what it doesn't.** It settles the question the
prose in README.md couldn't: this specific topology shape, built for
real, costs nothing measurable in density or wall-clock at 373 sandboxes
on a 48GiB host. It does *not* validate the topology as a production
design — the daemon is still stateless, the "sentinel" here is a generic
proxy standing in for a component that doesn't exist yet, and a real
implementation would carry real engineering cost (build, operate, secure
an actual forwarding layer) that this benchmark can't measure. Nor does
it rule out cost at a different scale — one StatefulSet pod and one
sentinel replica were never going to bottleneck 373 sequential creates;
whether either component becomes a real bottleneck under concurrent load
or many daemon replicas is a different, unasked question.

### 2026-08-26 — nested-incus-pod (#1565): mechanism validated, resource-limit enforcement blocked

Fourth scenario, tracked from #1565: put a nested `incusd` inside one k8s
pod, run the existing `containarium daemon --runtime=lxc` alongside it
pointed at that nested Incus, and see whether every `containarium create`
becoming a real LXC container — cgroup-ceilinged by the nested Incus,
invisible to Kubernetes' own admission accounting beyond the one pod's
declared request/limit — could reach scenario 3's (929) density from
*inside* a k8s-scheduled pod. **Result: the mechanism itself works, but
the specific thing this whole benchmark series measures — a per-container
resource *limit* actually being enforced — does not, in this environment.
No density number came out of this run.**

Host cap: 20 vCPU / 48GiB RAM / 200GB disk (Incus KVM VM), same as every
other k8s scenario. Base cluster: `provision_base_k8s` (kubeadm + Calico)
with `install_gvisor` deliberately *not* called — this pod must run under
plain `runc` (gVisor blocks the mount/cgroup/namespace syscalls Incus
itself needs; see manifests/nested-incus-pod/README.md). Pod: single
`ubuntu:24.04` container, `privileged: true`, no `runtimeClassName`,
`resources.requests == limits` = 16 CPU / 40Gi (the one declared number
the whole experiment is about), `emptyDir` at `/var/lib/incus` (`dir`
storage backend — no block device inside a pod). Daemon built from
`main` (same snag as the #1558 and sentinel-statefulset entries above:
the released tag, v0.66.0, predates `--disable-{security,pentest,zap}-
scanner`) and served to the pod over a throwaway HTTP endpoint on the VM
itself, since the pod can reach the VM's own IP directly.

**Milestone 0 (spike) passed cleanly, no caveats.** A bare `incus admin
init --auto --storage-backend=dir` plus `incus launch images:ubuntu/24.04
test1` — Incus's own default profile, no explicit resource limits —
worked exactly like on bare metal: `incusd` started as a plain background
process (no systemd inside the container; the real binary is
`/opt/incus/lib/systemd/incusd`, not on `$PATH`), the container reached
`RUNNING`, `incus exec test1 -- echo ok` succeeded, and Incus's own
`incusbr0` bridge came up nested *inside* the pod's own Calico-managed
network namespace with a real DHCP-assigned IP (`10.224.76.16`) — the
single biggest risk this scenario's design doc flagged (Incus's bridge
creation conflicting with Calico's veth/netns setup) turned out to be a
complete non-issue.

**Milestone 1 (the real pod) also came up clean** — daemon healthy, core
services attempted (see below), base image baked (#1037) — but revealed
the real wall the moment box creation was actually tried.

**What actually blocks the density run:** every `containarium create`
call — with the benchmark's own 200m/256MiB profile, and even with zero
explicit `--cpu`/`--memory` flags (containarium's own defaults, 4
cores/4GB) — fails identically:

```
Error: failed to create container via HTTP API: failed to create
container: ... failed to start container (operation failed): Failed to
run: /opt/incus/bin/incusd forklxc <name>-container ...: exit status 1
```

The container-specific LXC log names it precisely:

```
cgfsng - Device or resource busy - Could not enable "+cpuset +cpu +io
+memory +hugetlb +pids +rdma +misc" controllers in the unified cgroup 11
cgfsng - No such file or directory - Failed to set "memory.max" to
"268435456"
start - Failed to setup cgroup limits for container "<name>-container"
```

An *unconstrained* create (Incus's bare default profile — the spike's
`test1`, and confirmed again live via a direct `incus launch` with no
`-c limits.*`) starts fine in this same pod. Only a create that asks
Incus to enforce a per-container cgroup ceiling fails — which is every
single `containarium create` call, since the CLI always sets
`limits.cpu`/`limits.memory` to something (explicit values, or its own
4-core/4GB default). That is precisely the mechanism this entire
benchmark series exists to measure (declared-vs-actual cgroup
accounting), so this scenario cannot produce a comparable density number
without it.

**Root cause, as far as this run diagnosed it (not fixed, not chased
further — see below):** `/proc/self/cgroup` inside the pod reads
`0::/kubepods.slice/kubepods-pod<uid>.slice/cri-containerd-<id>.scope` —
a full, host-rooted path, not `/`. That means this cluster's containerd/
runc is *not* giving even a `privileged: true` pod its own cgroup
namespace; nested Incus is creating its LXC containers' cgroups as real
siblings of the pod's own live-managed cgroup subtree, contending with
whatever kubelet/containerd are simultaneously doing there. `cgroup.
subtree_control` already listed every controller as available and
enabled at the point Incus tried to delegate further — the failure isn't
missing controllers, it's contention/depth at that specific host-rooted
path. The zabbly Incus package's own (unused here) systemd unit sets
`Delegate=yes` on `incus.service` — systemd's mechanism for exactly this
kind of controlled sub-delegation — which this pod never gets, since
there's no systemd (no init at all) running as PID 1 inside a bare
`ubuntu:24.04` container.

**Two plausible fixes, neither attempted in this run** (real engineering
effort, judged out of scope for a benchmark-only exploration — see
manifests/nested-incus-pod/README.md): (1) run systemd as the pod's PID 1
(the standard "systemd-in-a-container" pattern — needs a systemd-capable
image/boot sequence, not just `apt-get install systemd` inside a running
bare container) so the shipped `incus.service`'s `Delegate=yes` actually
takes effect; (2) a node-level containerd/CRI config change so privileged
pods get a private cgroup namespace (`cgroupns_mode`), which is outside
what a Pod manifest alone can request and would need touching this
cluster's base provisioning, not just this scenario's own files.

**What this settles and what it doesn't.** It settles that the shared-
process-hosting mechanism itself is sound — a nested Incus genuinely runs
inside a k8s pod, with working storage, networking, and exec, no fictional
kernel wall. It does *not* produce a density number, because the one
thing that mechanism needs to actually work (per-box resource ceilings)
doesn't, in this specific cluster's cgroup delegation setup. This is a
narrower, more specific finding than "nested Incus in a pod doesn't
work" — it's "nested Incus in a pod doesn't work *for resource-limited
containers*, in a cluster where privileged pods don't get their own
cgroup namespace" — which is exactly the kind of precise, actionable
negative result worth keeping rather than silently abandoning.

## Template

```
### <date> — <host spec: CPU model, cores, RAM>

Hard cap per VM: <VM_CPUS> vCPU / <VM_MEM_MB>MB RAM / <VM_DISK_GB>GB disk
Sandbox profile: cpu <SANDBOX_CPU_REQUEST>/<SANDBOX_CPU_LIMIT>, mem <SANDBOX_MEM_REQUEST>/<SANDBOX_MEM_LIMIT>
Containarium version: <tag>    Agent-sandbox version: <tag>    K8s version: <kubeadm version>

| | k8s + agent-sandbox | Containarium workhorse |
|---|---|---|
| Sandboxes reached Ready/RUNNING | | |
| Attempted (incl. failures) | | |
| Wall-clock for the run | | |
| Fixed overhead before sandbox #1 (kube-system pods / core containers) | | |

Notes / anomalies:
```
