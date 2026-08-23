# Results

This file holds the reviewed, committed summary of actual benchmark runs —
not the raw per-run logs (those land under `results/`, gitignored, one
timestamped file per run; see `scripts/lib.sh`'s `resource_snapshot` /
`run_density_loop`). Copy the relevant numbers here once a run is complete
and worth keeping as a reference point.

No runs have been executed yet — this PR ships the plan and the scripts.

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
