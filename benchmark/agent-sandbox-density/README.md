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
   itself is one extra pod's worth of fixed overhead, not a per-sandbox
   cost — see [Fairness notes](#fairness-notes).
2. **Request == limit.** `containarium create --cpu/--memory` sets both to
   the same value; the control group's pods get a lower separate request.
   Since Kubernetes admission packs on requests, this is a real,
   per-sandbox cost multiplier — see [Fairness notes](#fairness-notes) for
   why it should bias the result *against* Containarium, not for it.

If the numbers come back close, that says Containarium's orchestration is
close to free on top of gVisor. If they don't, the gap is attributable to
one of the two items above, not to gVisor itself — and (2) is a fixable
CLI gap, not an architectural one.

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
happens — this PR ships the plan and the scripts; a follow-up records
numbers once the benchmark has actually been executed.

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
```

Each density script writes a timestamped results file under `results/`
(gitignored — see `RESULTS.md` for the reviewed/committed summary format)
and prints a one-line summary at the end.

## Layout

```
benchmark/agent-sandbox-density/
├── README.md                    — this file
├── config.env.example           — copy to config.env, fill in your host's numbers
├── RESULTS.md                   — reviewed summary of actual runs (template for now)
├── manifests/
│   └── sandbox-template.yaml    — Sandbox CR (agents.x-k8s.io/v1beta1) with the resource profile above
└── scripts/
    ├── lib.sh                       — shared logging / resource-snapshot / stop-on-N-failures helpers
    ├── k8s-common.sh                — shared kubeadm+CNI+agent-sandbox-controller base, used by both 01 and 03
    ├── 00-create-vm.sh              — Incus: create a KVM-backed VM with a hard CPU/mem/disk cap
    ├── 01-provision-k8s-control.sh  — the shared k8s base, nothing more (control group)
    ├── 02-run-density-k8s.sh        — create Sandbox CRs until the stopping rule triggers
    ├── 03-provision-containarium.sh — shared k8s base + gVisor/runsc RuntimeClass + Helm-installed Containarium daemon
    ├── 04-run-density-containarium.sh — `containarium create` (pod -> gVisor -> containarium) until the stopping rule triggers
    └── 99-teardown-vm.sh            — stop + delete the VM
```
