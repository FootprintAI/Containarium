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
