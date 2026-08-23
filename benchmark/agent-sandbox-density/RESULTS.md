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
