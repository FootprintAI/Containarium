# Sandbox density: k8s (agent-sandbox) vs. Containarium workhorse

**Question:** given the *same* hard resource cap on the *same* class of
machine, how many isolated agent sandboxes can each approach actually run
before it runs out of room?

- **Control group** — a VM running vanilla Kubernetes
  ([kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/))
  with the upstream
  [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
  controller installed, creating one `Sandbox` custom resource per unit.
- **Experiment group** — a VM running the Containarium daemon as a plain
  LXC/Incus "workhorse" (no Kubernetes at all), creating one box per unit via
  `containarium create`.

Both VMs get **identical hard resource caps** (CPU count, memory, disk) via
VirtualBox, and both sandboxes get **identical CPU/memory request+limit
values** (see [Sandbox resource profile](#sandbox-resource-profile) below).
The only thing that differs between the two runs is the orchestration layer.

This lives in-repo (rather than as a one-off gist) so the methodology is
reviewable, the numbers are reproducible, and the scripts can be re-run
whenever a release changes either side's footprint.

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

1. Provision two VirtualBox VMs on the same physical host, one at a time
   (see [Why sequential, not parallel](#why-sequential-not-parallel)), each
   given the **same** hard CPU/memory/disk cap.
2. **Control VM:** install `kubeadm` + a CNI, raise the kubelet
   `--max-pods` ceiling (the stock default of 110 would cap density before
   any real resource limit does — see
   [Kubelet max-pods](#kubelet-max-pods)), then install the upstream
   agent-sandbox controller and CRDs.
3. **Experiment VM:** install the Containarium daemon in its default
   LXC/Incus "workhorse" mode (no `--runtime=k8s` — that backend targets
   *existing* clusters, it isn't what we're measuring here).
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

Both VMs get the same VirtualBox-enforced hard cap, set in `config.env`:

```
VM_CPUS=<N>
VM_MEM_MB=<N>
VM_DISK_GB=<N>
```

`scripts/00-create-vm.sh` sets these via `VBoxManage modifyvm --cpus` /
`--memory`, which VirtualBox enforces as a true ceiling on the guest (the
guest OS only ever sees that much CPU/RAM — it isn't a soft cgroup limit
inside a shared host that the guest could exceed under pressure). Pick
values that fit comfortably within whatever's actually free on the host
you're running on — check with `free -h` (`available`, not `free`) before
picking a number, since some of what looks "used" may be reclaimable page
cache. This repo intentionally does **not** hardcode a host name, IP, or
specific machine's specs — see CLAUDE.md's anonymization convention. Fill
in your own target host by pointing `scripts/00-create-vm.sh` at it (see
its `--help`); it runs locally on whatever machine has VirtualBox
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

## Fairness notes

- Same physical host, same hard resource cap, same sandbox resource
  profile, same stopping rule (`FAILURE_STREAK_TO_STOP` consecutive
  resource-reason failures) on both sides.
- The control group's CNI, kube-proxy, and other cluster-system pods
  consume some of the node's capacity before a single `Sandbox` is
  created — this is real overhead a k8s deployment actually pays, not an
  artifact to be corrected away. It gets reported as part of the resource
  snapshot, not subtracted from the result.
- Containarium's own core service containers (Postgres, Caddy, the
  otel collector, etc. — see `internal/server/core_services.go`) are the
  equivalent fixed overhead on the experiment side, and are likewise left
  in place and reported, not subtracted.
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
    ├── 00-create-vm.sh              — VBoxManage: create a VM with a hard CPU/mem/disk cap
    ├── 01-provision-k8s-control.sh  — kubeadm + CNI + raised max-pods + agent-sandbox controller
    ├── 02-run-density-k8s.sh        — create Sandbox CRs until the stopping rule triggers
    ├── 03-provision-containarium.sh — containarium daemon in workhorse (LXC/Incus) mode
    ├── 04-run-density-containarium.sh — `containarium create` until the stopping rule triggers
    └── 99-teardown-vm.sh            — stop + delete the VM
```
