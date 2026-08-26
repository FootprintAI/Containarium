# Sandbox density: k8s (agent-sandbox) vs. Containarium workhorse

**Question:** given the *same* hard resource cap on the *same* class of
machine, how many isolated agent sandboxes can each approach actually run
before it runs out of room?

- **Control group** — a VM running vanilla Kubernetes
  ([kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/))
  with gVisor installed and the upstream
  [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
  controller running, creating one `Sandbox` custom resource per unit
  directly via `kubectl`, its pod scheduled under a `runsc` `RuntimeClass`.
- **Experiment group** — the *identical* base cluster (same kubeadm, same
  gVisor install, same `RuntimeClass`), running the Containarium daemon
  (Helm chart, `--runtime=k8s`) configured to schedule every box pod under
  that same `RuntimeClass`: **pod → gVisor → containarium**. Each unit is
  created via `containarium create`, which the daemon turns into the
  *same* kind of `Sandbox` CR the control group creates directly — the
  daemon uses the identical upstream controller underneath (see
  [`docs/KIND-QUICKSTART.md`](../../docs/KIND-QUICKSTART.md)).

**gVisor runs on both sides on purpose** — see
[What's actually under test](#whats-actually-under-test). Both VMs get
**identical hard resource caps** (CPU count, memory, disk) via a KVM-backed
Incus VM,
and both sandboxes get the **same sandbox resource profile** (see
[Sandbox resource profile](#sandbox-resource-profile) below, and
[Fairness notes](#fairness-notes) for one documented asymmetry in how that
profile is applied).

This lives in-repo (rather than as a one-off gist) so the methodology is
reviewable, the numbers are reproducible, and the scripts can be re-run
whenever a release changes either side's footprint.

## What's actually under test

The obvious version of this benchmark would be "k8s vs. k8s+gVisor" — but
that mixes two different questions into one number: *does gVisor cost
density*, and *does Containarium's orchestration cost density*. Running
gVisor on **both** sides removes the first question as a variable, so
what's left to measure is narrower and more useful: given the identical
kernel isolation boundary, what does routing sandbox creation through
Containarium — an extra daemon hop, plus whatever resource accounting
choices its CLI makes — actually cost, if anything, versus creating the
same `Sandbox` CR directly?

Concretely, the two things that can still differ once gVisor is held
constant are:

1. **The daemon hop.** `containarium create` → Containarium daemon →
   `Sandbox` CR, versus `kubectl apply` → `Sandbox` CR directly. The daemon
   itself is fixed overhead, not a per-sandbox cost — but "fixed" doesn't
   mean "one pod": see
   [The experiment group's k8s footprint](#the-experiment-groups-k8s-footprint)
   below for what that hop is actually made of, and
   [Fairness notes](#fairness-notes) for how it's accounted for here.
2. **Request == limit.** `containarium create --cpu/--memory` sets both to
   the same value; the control group's pods get a lower separate request.
   Since Kubernetes admission packs on requests, this is a real,
   per-sandbox cost multiplier — see [Fairness notes](#fairness-notes) for
   why it should bias the result *against* Containarium, not for it. Fixed
   in [#1557](https://github.com/FootprintAI/Containarium/issues/1557) —
   see [Results so far](#results-so-far-373--373--929).

If the numbers come back close, that says Containarium's orchestration is
close to free on top of gVisor. If they don't, the gap is attributable to
one of the two items above, not to gVisor itself — and (2) was a fixable
CLI gap, not an architectural one (now fixed; see below).

## The experiment group's k8s footprint

Item 1 above says the daemon hop is "fixed overhead, not a per-sandbox
cost" — true, but worth being precise about what that fixed cost actually
*is*, since "one extra pod" understates it. Containarium's k8s deployment
mode is conceptually a small stack of Kubernetes-native primitives in
front of the actual provisioning logic, not a single process:

```
client / agent
      │
      ▼
  Service            (stable in-cluster address)
      │
      ▼
  Deployment          containarium-sentinel — traffic forwarding
      │
      ▼
  StatefulSet         containarium-daemon — actually provisions boxes
      │
      ▼
  Sandbox CR  →  agent-sandbox controller  →  pod (runsc)
```

Three Kubernetes-native scheduling and networking layers — a `Service`,
a `Deployment` running the `containarium-sentinel` component that forwards
traffic, and a `StatefulSet` running the `containarium-daemon` itself —
sit between a client and the point where a sandbox actually gets
provisioned. Compare that to the [third scenario](#third-scenario-native-lxc-workhorse)'s
native LXC backend: a single `containarium daemon` process on the host,
talking directly to the Incus API, no Kubernetes layer at all. That
three-layer stack is real, fixed, per-deployment infrastructure the LXC
path simply never carries — it doesn't scale with sandbox count, but it
isn't free either, and it's worth naming rather than folding silently
into "one extra pod."

**Not the literal chart this benchmark's primary run deploys —
`charts/containarium-k8s/`** (what `03-provision-containarium.sh` installs)
runs the daemon as a single `Deployment` with `sshpiper` as its gateway
component, no separate `containarium-sentinel` and no `StatefulSet`. But
this topology has since actually been built and benchmarked, not just
described — see `scripts/07-provision-containarium-sentinel.sh` /
`08-run-density-containarium-sentinel.sh` and RESULTS.md's 2026-08-26
"sentinel-statefulset" entry: **373 sandboxes, an exact match to the
plain-Deployment baseline, with wall-clock landing within noise of
gVisor's own cost.** The extra Service → Deployment(sentinel) →
StatefulSet(daemon) hop is measurably invisible to both density and
speed at this scale — the bottleneck stays k8s memory-request admission
for sandbox pods either way.

That settles the fixed-overhead question this section originally raised,
but it's still a benchmark-only exploration, not a production
recommendation: the daemon is stateless (no PVCs, all durable state in
the k8s API/etcd via CRDs) so the StatefulSet buys nothing
architecturally, and the "sentinel" in that run is a stock nginx reverse
proxy standing in for a `containarium-sentinel` component that doesn't
exist yet (the real `internal/sentinel` binary does something unrelated
— see `manifests/sentinel-statefulset/README.md`). One StatefulSet pod
and one sentinel replica also were never going to bottleneck 373
sequential creates — whether either becomes a real bottleneck under
concurrent load or many daemon replicas is a different, unmeasured
question.

## Why this matters

Containarium's pitch has always been *blast-radius*, not raw density — see
[docs/AX-COMPARISON.md](../../docs/AX-COMPARISON.md) and
[docs/product/agent-substrate-roadmap-position.md](../../docs/product/agent-substrate-roadmap-position.md).
This benchmark exists to find out, honestly, whether that security posture
also happens to come with a density cost, a density win, or a wash — and to
have a number instead of a guess the next time the question comes up.

**We are not trying to make k8s look bad.** The control group runs vanilla
`kubeadm` (not a slimmed-down edge distro) specifically so the comparison is
against what most people actually run, and both sides get the fairest
resource accounting we can manage (see [Fairness notes](#fairness-notes)).
If Containarium loses on density, that's a real, reportable result.

## Methodology

1. Provision two Incus VMs on the same physical host, one at a time
   (see [Why sequential, not parallel](#why-sequential-not-parallel)), each
   given the **same** hard CPU/memory/disk cap.
2. **Both VMs** get the identical base cluster (`scripts/k8s-common.sh`):
   `kubeadm` + Calico, kubelet `--max-pods` raised (the stock default of
   110 would cap density before any real resource limit does — see
   [Kubelet max-pods](#kubelet-max-pods)), and the upstream agent-sandbox
   controller + CRDs. Any drift between the two sides here would confound
   the comparison, so this step is one shared script, not two similar ones.
3. **Experiment VM only, on top of that base:** install gVisor
   (`runsc` + the containerd shim), register a `runsc` `RuntimeClass`, then
   Helm-install the Containarium daemon with `runtimeClass: runsc` so
   every box it creates is scheduled under it.
4. Run the matching density-loop script against each VM: create sandboxes
   one at a time with the fixed resource profile below, wait for each to
   reach a ready state, and keep going until creation starts failing for a
   resource reason (not a transient/config reason) for
   `FAILURE_STREAK_TO_STOP` consecutive attempts (default 3 — see
   `scripts/lib.sh`).
5. Record the final count plus a resource snapshot (host `free -h`,
   `nproc`, disk usage, and either `kubectl top nodes` or
   `containarium list` resource totals) at the stopping point.
6. Tear the VM down, repeat for the other side.

Results get appended to [`RESULTS.md`](RESULTS.md) as an actual run
happens. All three scenarios below have now been run end-to-end — see
[Results so far](#results-so-far-373--186--929) for the headline numbers
and [`RESULTS.md`](RESULTS.md) for every run's full data.

## Sandbox resource profile

Deliberately a **fresh, minimal profile** — not a reuse of Containarium's
own built-in per-box memory floor (`256Mi` request / `1Gi` limit, see
`pkg/core/box/k8s/objects.go`) and not a reuse of any specific customer
workload shape. The goal here is a density *ceiling*, not a realistic
workload simulation:

| Resource | Request | Limit |
|---|---|---|
| CPU | `100m` | `200m` |
| Memory | `128Mi` | `256Mi` |

Both values are overridable via `config.env` (see
[`config.env.example`](config.env.example)) — if you re-run this against a
different profile, please note the profile used alongside the result in
`RESULTS.md` rather than overwriting the default row.

## Hard resource caps

Both VMs get the same hard cap, set in `config.env`:

```
VM_CPUS=<N>
VM_MEM_MB=<N>
VM_DISK_GB=<N>
```

`scripts/00-create-vm.sh` provisions an **Incus VM** (KVM-backed) with
`limits.cpu`/`limits.memory` set to these — a true hardware-partitioned
ceiling on the guest (the guest OS only ever sees that much CPU/RAM — it
isn't a soft cgroup limit inside a shared host that the guest could exceed
under pressure), the same guarantee a VirtualBox VM would give.

**Why Incus rather than VirtualBox**, if the host already runs one: a
second hypervisor means a second kernel module (VirtualBox's `vboxdrv`)
loaded alongside whatever's already there. On a host already running live
workloads under an existing KVM-based hypervisor (Incus, libvirt, etc.),
that's an avoidable stability variable — reuse whatever hypervisor is
already proven running on that host instead. If your host has neither, any
KVM-backed option works the same way; the scripts just need `incus`
(or an equivalent adapted the same way) on the host doing the provisioning.

Pick values that fit comfortably within whatever's actually free on the
host you're running on — check with `free -h` (`available`, not `free`)
before picking a number, since some of what looks "used" may be reclaimable
page cache. This repo intentionally does **not** hardcode a host name, IP,
or specific machine's specs — see CLAUDE.md's anonymization convention.
Fill in your own target host by pointing `scripts/00-create-vm.sh` at it
(see its `--help`); it runs locally on whatever machine has Incus
installed, so for a remote host, SSH in first and run these scripts there.

## Why sequential, not parallel

Both VMs get the *same* hard resource cap, sized against what's actually
free on the host. Running them side by side would mean each VM's real cap
is the full amount, but the *host's* free capacity is split between them —
which either forces you to halve each VM's cap (comparing two smaller
environments, not the one you meant to compare) or overcommits the host
(letting one run's cache pressure quietly steal from the other, which
breaks the "hard cap" premise this whole benchmark rests on). Running one
VM fully, tearing it down, then running the other keeps each side's
measurement honest against the *same* full-sized cap.

## Kubelet max-pods

Stock kubelet defaults to `--max-pods=110` regardless of actual node
capacity — a density benchmark that leaves this at the default is measuring
the default, not the resource ceiling. `scripts/01-provision-k8s-control.sh`
raises it explicitly (see `K8S_MAX_PODS` in `config.env`); pick a number
comfortably above what you expect the memory/CPU cap to allow so the kubelet
flag is never the thing that actually stops the run — if it is, the result
says "kubelet's --max-pods", not "resource exhaustion", and should be
re-run with a higher value.

## gVisor access path (not needed for this benchmark)

`kubectl exec`/`port-forward` straight to a `runsc`-scheduled box pod
doesn't work — a gVisor networking characteristic, not a Containarium bug
(kubernetes-sigs/agent-sandbox#158, this repo's #1489; see
[`docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md`](../../docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md)
"Hard isolation via RuntimeClass"). This benchmark only needs to know
whether a box reached `RUNNING` — via the k8s API, which works fine
either way — not to actually SSH into it, so `03-provision-containarium.sh`
deliberately disables the sshpiper gateway (`gateway.namespace=""`) rather
than standing one up for no reason. If you want to poke at a box
afterward, re-enable the gateway per
[`docs/KIND-QUICKSTART.md`](../../docs/KIND-QUICKSTART.md) — real
pod-to-pod networking (which the gateway uses) is unaffected by gVisor,
only the kubelet-mediated exec/port-forward path is.

## Fairness notes

- Same physical host, same hard resource cap, same base cluster setup
  (`scripts/k8s-common.sh` — literally one script, not two hand-kept-in-sync
  copies), same sandbox resource profile, same stopping rule
  (`FAILURE_STREAK_TO_STOP` consecutive resource-reason failures) on both
  sides.
- **Documented asymmetry, not hidden:** the control group's `Sandbox`
  pods get separate request/limit values (see the profile table below);
  Containarium's `create --cpu/--memory` sets **both** request and limit to
  the same (LIMIT) value — there's no separate request knob on the CLI
  (`pkg/core/box/k8s/objects.go`). Since Kubernetes admission packs on
  *requests*, not limits, Containarium's boxes ask the scheduler for more
  room per unit than the control group's pods do for the same actual usage
  ceiling. This should bias the result *against* Containarium's density,
  not for it — worth keeping in mind reading the numbers.
- **Different container images, and it's not a knob to equalize.** The
  control group's `Sandbox` pods run a minimal `busybox:1.36`. Found live
  that a Containarium box can't: `create`'s default image
  (`images:ubuntu/24.04`, an LXC-style reference) isn't a valid OCI image
  and breaks the pod outright (`InvalidImageName`) on the k8s backend, and
  a bare `busybox` in its place crash-loops — Containarium's box runtime
  expects its own `containarium-agent-box` image (podman-in-pod, sshd,
  MCP server). So the experiment side runs that real, heavier image
  instead. This is a genuine, structural difference in what each side
  actually deploys, not a methodology gap to correct away — a Containarium
  box IS that runtime, by product design. It gets reported (image name in
  each run's results file), not normalized.
- The CNI, kube-proxy, and other cluster-system pods consume some of the
  node's capacity before a single sandbox is created — real overhead a k8s
  deployment actually pays on *both* sides now, not an artifact to be
  corrected away. It gets reported as part of the resource snapshot, not
  subtracted from the result.
- The Containarium daemon's own pod (plus, on the experiment side only,
  gVisor's per-pod `runsc` sandbox process overhead) is the equivalent
  fixed cost on that side, and is likewise left in place and reported, not
  subtracted.
- Both density loops use the identical stopping rule and snapshot logic in
  `scripts/lib.sh`, so a methodology change (e.g. a different
  `FAILURE_STREAK_TO_STOP`) only has to be made once and applies to both
  sides.

## Running it

```sh
cp config.env.example config.env
# edit config.env: VM_CPUS, VM_MEM_MB, VM_DISK_GB, and (optionally) the
# sandbox resource profile / K8S_MAX_PODS / FAILURE_STREAK_TO_STOP

# Control group
scripts/00-create-vm.sh --name sandbox-bench-control
scripts/01-provision-k8s-control.sh --name sandbox-bench-control
scripts/02-run-density-k8s.sh --name sandbox-bench-control
scripts/99-teardown-vm.sh --name sandbox-bench-control

# Experiment group
scripts/00-create-vm.sh --name sandbox-bench-containarium
scripts/03-provision-containarium.sh --name sandbox-bench-containarium
scripts/04-run-density-containarium.sh --name sandbox-bench-containarium
scripts/99-teardown-vm.sh --name sandbox-bench-containarium

# Third scenario (optional) — see "Third scenario: native LXC workhorse"
scripts/00-create-vm.sh --name sandbox-bench-containarium-lxc
scripts/05-provision-containarium-lxc.sh --name sandbox-bench-containarium-lxc
scripts/06-run-density-containarium-lxc.sh --name sandbox-bench-containarium-lxc
scripts/99-teardown-vm.sh --name sandbox-bench-containarium-lxc
```

Each density script writes a timestamped results file under `results/`
(gitignored — see `RESULTS.md` for the reviewed/committed summary format)
and prints a one-line summary at the end.

## Third scenario: native LXC workhorse

A third comparison point, alongside the two k8s-based groups above:
Containarium's original backend — plain LXC/Incus containers, no
Kubernetes, no gVisor, no pooling. Same host, same hard resource cap,
same sandbox resource profile as whatever run it's compared against
(convert `Mi`→`MiB` for Incus's native `limits.memory` format — see
`06-run-density-containarium-lxc.sh`'s header comment for why the
conversion is a rename, not a real unit change).

**This is not a test of the `#1488` warm-pool/`SpawnSandbox` feature.**
As of this writing `SpawnSandbox` still serves the Phase 1 cold path —
the pool/reconciler code is in the tree but not wired into the request
path (tracked in
[#1523](https://github.com/FootprintAI/Containarium/issues/1523)). This
scenario uses plain `containarium create`, the same cold-create
mechanism the k8s scenarios' `create` already exercises — it isolates
the *backend* (LXC vs. k8s+gVisor), not pooling. Once `#1523` lands, a
real pooling comparison would need a different metric entirely (spawn
latency P50/P99, cold vs. warm — not simultaneous density; an active
pool member is a whole dedicated container, same footprint as a cold
one, per the pool's own design doc).

Unlike the k8s scenarios, `containarium list` works normally here (its
"incus backend not available" failure —
[#1525](https://github.com/FootprintAI/Containarium/issues/1525) — only
fires against a `--runtime=k8s` daemon; this one genuinely is
Incus-backed), and the default `--image` works as documented (no
[#1524](https://github.com/FootprintAI/Containarium/issues/1524)-style
`InvalidImageName` — that bug is k8s-backend-specific too).

## Fourth scenario: nested Incus inside a k8s pod

An exploration of the idea sketched in ["The experiment group's k8s
footprint"](#the-experiment-groups-k8s-footprint) above, taken further:
what if, instead of one k8s pod per box, one k8s pod hosted a **nested
`incusd`**, running the existing, unmodified `containarium daemon
--runtime=lxc` inside it? Kubernetes would then only ever admit the one
pod's own declared request/limit, while the nested Incus packs however
many boxes it can inside — the same declared-vs-actual accounting trick
that makes the third scenario (929) denser than the k8s scenarios (373),
attempted *inside* a k8s-scheduled pod instead of on a bare VM. Tracked in
[#1565](https://github.com/FootprintAI/Containarium/issues/1565); manifests
and scripts in `manifests/nested-incus-pod/`,
`scripts/09-provision-nested-incus-pod.sh`,
`scripts/10-run-density-nested-incus-pod.sh`.

**No density number came out of this.** The mechanism itself works —
nested Incus starts cleanly inside a real k8s pod, with working storage
and networking, no fictional kernel wall (the biggest flagged risk,
Incus's bridge conflicting with Calico's pod networking, turned out to be
a non-issue). What doesn't work, in this cluster: Incus enforcing a
per-container cgroup *resource limit* — which is every single
`containarium create` call, and precisely the mechanism this whole
benchmark series measures. See [`RESULTS.md`](RESULTS.md)'s 2026-08-26
entry for the full, precise diagnosis (a cgroup-namespace/delegation gap,
not a hard architectural block) and
`manifests/nested-incus-pod/README.md` for what a follow-up attempt would
need to try next. Like the third scenario, this is a benchmark-only
exploration — it does not touch `charts/containarium-k8s/` and is not a
proposed production architecture.

## Results so far: 373 / 373 / 929

Three scenarios have actually been run end-to-end on the same host (full
numbers, host specs, and every fix's before/after data are in
[`RESULTS.md`](RESULTS.md)):

| Scenario | Sandboxes | Notes |
|---|---|---|
| Control — k8s + gVisor + agent-sandbox | **373** | pods request `128Mi`; k8s admission-bound |
| Experiment — k8s + gVisor + Containarium (`pod → gVisor → containarium`) | **373** | request=`128Mi`/limit=`256Mi` via [#1557](https://github.com/FootprintAI/Containarium/issues/1557)'s `--memory-request` — exact match once the request-size asymmetry was fixed (was **186** before the fix; see RESULTS.md's 2026-08-26 entry) |
| Third scenario — Containarium native LXC/Incus, no k8s, no gVisor | **929** | `limits.memory` is a cgroup ceiling, not a k8s reservation — different deployment mode, not a gVisor comparison |
| Fourth scenario — nested Incus inside one k8s pod | *(none)* | Mechanism validated, but per-container cgroup resource limits don't enforce in this cluster — see [Fourth scenario](#fourth-scenario-nested-incus-inside-a-k8s-pod) above |

A write-up of what those three numbers actually mean (the 186-vs-373 gap,
the CLI fix, and the 373-vs-373 re-run) lives in the marketing blog, not
this repo — see
[FootprintAI/Containarium-cloud#1329](https://github.com/FootprintAI/Containarium-cloud/pull/1329)
(in review) or, once merged, <https://containarium.dev/blog/agent-sandbox-density-benchmark>.
This repo keeps the methodology, scripts, and raw results; the write-up
of what they mean lives with the rest of the marketing site.

## Fixing daemon overhead at scale (#1541)

Pushing the third scenario past a few hundred sandboxes surfaced real
Containarium daemon overhead, unrelated to the LXC-vs-k8s question the
benchmark is actually asking — tracked and closed as
[#1541](https://github.com/FootprintAI/Containarium/issues/1541), two
independent fixes:

1. **The benchmark's own polling was O(N).** `box_ready()` called
   `containarium list` — which fetches every container's full state —
   every ~2s while waiting on *one* box to boot. Fixed by adding
   `containarium get <name>`, an O(1) single-container lookup
   ([#1543](https://github.com/FootprintAI/Containarium/pull/1543)), and
   switching `06-run-density-containarium-lxc.sh` to use it.
2. **The daemon's own traffic-attribution cache had the same bug,
   independent of the benchmark.** `internal/traffic.ContainerCache`
   relisted and refetched *every* container every 30s, forever, regardless
   of churn. Fixed to diff incrementally — only fetch names not already
   cached, drop names that disappeared, leave the rest alone
   ([#1546](https://github.com/FootprintAI/Containarium/pull/1546)).

Both fixes were live-verified on fresh VMs with load-average checkpoints at
matching container counts (see RESULTS.md's 2026-08-25 entries). Neither
fix moved the actual ceiling: it's a real ~930-sandbox physical-memory wall
on the 46GiB test host, hit cleanly (`context deadline exceeded` under
memory pressure) instead of stalling early on self-inflicted daemon CPU
load. Two smaller bugs found along the way and folded into the
provisioning script below:

- `incus admin init --auto`'s storage-driver detection is unreliable — it
  picked `dir` over `zfs` on a fresh VM twice, despite `zfsutils-linux`
  being installed. `05-provision-containarium-lxc.sh` now passes
  `--storage-backend=zfs` explicitly rather than trusting `--auto`.
- Host account creation (`useradd`, for the SSH jump-server path) silently
  broke after about a dozen tenants from subuid-pool exhaustion — fixed in
  [#1542](https://github.com/FootprintAI/Containarium/pull/1542) (`-K
  SUB_UID_COUNT=0 -K SUB_GID_COUNT=0`).

If you're pushing density further than ~900 on a similarly-sized host, the
bridge network's default `/24` DHCP range (~253 usable addresses) becomes
the next wall before RAM does — widen it first (`incus network set
incusbr0 ipv4.address=<superset-of-current-subnet>/16`), and remember to
widen the matching `pg_hba.conf` rule for the daemon's own Postgres
connection to the same range, then `kill -HUP <postgres-pid>` to reload it.

## Layout

```
benchmark/agent-sandbox-density/
├── README.md                    — this file
├── config.env.example           — copy to config.env, fill in your host's numbers
├── RESULTS.md                   — reviewed summary of actual runs, one dated entry per run
├── manifests/
│   ├── sandbox-template.yaml     — Sandbox CR (agents.x-k8s.io/v1beta1) with the resource profile above
│   ├── sentinel-statefulset/     — benchmark-only Service/Deployment(sentinel)/StatefulSet(daemon) manifests, see its own README.md
│   └── nested-incus-pod/         — benchmark-only nested-Incus-in-a-pod manifests, see its own README.md
└── scripts/
    ├── lib.sh                       — shared logging / resource-snapshot / stop-on-N-failures helpers (density loop supports resuming via --start-index)
    ├── k8s-common.sh                — shared kubeadm+CNI+agent-sandbox-controller base, used by both 01 and 03
    ├── 00-create-vm.sh              — Incus: create a KVM-backed VM with a hard CPU/mem/disk cap
    ├── 01-provision-k8s-control.sh  — the shared k8s base, nothing more (control group)
    ├── 02-run-density-k8s.sh        — create Sandbox CRs until the stopping rule triggers
    ├── 03-provision-containarium.sh — shared k8s base + gVisor/runsc RuntimeClass + Helm-installed Containarium daemon
    ├── 04-run-density-containarium.sh — `containarium create` (pod -> gVisor -> containarium) until the stopping rule triggers
    ├── 05-provision-containarium-lxc.sh — third scenario: Incus + Containarium daemon, native LXC backend, no k8s/gVisor (explicit zfs storage backend, image-bake, scanners disabled)
    ├── 06-run-density-containarium-lxc.sh — `containarium create` on the LXC backend until the stopping rule triggers (--start-index to resume a stopped run)
    ├── 07-provision-containarium-sentinel.sh — benchmark-only: same base as 03, daemon.replicaCount=0 + jq-reshaped into manifests/sentinel-statefulset/
    ├── 08-run-density-containarium-sentinel.sh — `containarium create` through the sentinel hop until the stopping rule triggers
    ├── 09-provision-nested-incus-pod.sh — benchmark-only: shared k8s base (no gVisor) + a privileged pod running nested incusd + containarium daemon
    ├── 10-run-density-nested-incus-pod.sh — `containarium create` inside the nested-Incus pod until the stopping rule triggers (blocked — see RESULTS.md)
    └── 99-teardown-vm.sh            — stop + delete the VM
```
