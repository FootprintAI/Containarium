# nested-incus-pod manifests

Raw k8s manifests (not Helm-templated) for the fourth benchmark scenario
tracked in [#1565](https://github.com/FootprintAI/Containarium/issues/1565):
one privileged pod running a nested `incusd` plus the existing,
unmodified `containarium daemon --runtime=lxc` inside it, pointed at that
nested Incus over its own Unix socket. Every `containarium create` then
becomes a real LXC container, cgroup-ceilinged by the nested Incus — but
Kubernetes only ever admits the *one* declared request/limit on the pod
below, regardless of how many boxes the nested Incus packs inside it.
See `../../RESULTS.md`'s 2026-08-26 entry for what actually happened.

**This is a benchmark-only exploration, not a proposed production
architecture.** `charts/containarium-k8s/` is untouched by this scenario.

## What's here

- `spike-pod.yaml` — a throwaway Milestone-0 pod (no ConfigMap, no
  containarium at all) used to answer one question before building
  anything real: can a nested `incusd` even start and run a container
  inside a k8s pod at all? It passed cleanly — see RESULTS.md.
- `pod-configmap.yaml` — the real pod's startup script (installs Incus,
  starts `incusd` as a plain background process — there's no systemd/init
  inside a bare `ubuntu:24.04` container, so the zabbly package's own
  `incus.service` unit is never actually used — installs and starts the
  containarium daemon, bakes the base image).
- `pod.yaml` — the real pod: `privileged: true`, no `runtimeClassName`
  (must be plain `runc` — gVisor blocks the mount/cgroup/namespace
  syscalls Incus itself needs to manage its own child containers), one
  `emptyDir` for `/var/lib/incus` (the `dir` storage backend — no block
  device inside a pod), `resources.requests == limits` — the single
  declared number the whole experiment is about.

## Why the daemon isn't started via the real Incus systemd unit

The zabbly Incus package installs a real `incus.service` systemd unit
(`Delegate=yes`, pointing at `/opt/incus/lib/systemd/incusd`) — but there
is no systemd, no init of any kind, running as PID 1 inside a bare
`ubuntu:24.04` container. `pod-configmap.yaml`'s start script backgrounds
`incusd` directly (`nohup ... &`) instead. This turned out to matter: see
RESULTS.md — the *reason* resource-limited containers fail to start here
is plausibly exactly this gap (`Delegate=yes` never takes effect without
systemd actually managing the cgroup), not something a Pod manifest alone
can fix. A genuine systemd-as-PID-1 setup was judged out of scope for
this benchmark-only pass; it's the most promising next step if anyone
picks this back up.

## Why `containarium create` never succeeded here

Short version — full diagnosis in `RESULTS.md`: nested Incus itself
works fine (the spike proved a real, unconstrained container starting,
networking, and being exec'd into). What doesn't work is Incus enforcing
a per-container cgroup *limit* — `containarium create` always sets
`limits.cpu`/`limits.memory` to something (explicit flags, or its own
4-core/4GB default), and every single one of those creates fails with
`cgfsng: Device or resource busy` trying to delegate cgroup controllers
further, and `Failed to set "memory.max"`. `/proc/self/cgroup` inside the
pod shows a full host-rooted path rather than `/`, meaning this cluster's
containerd/runc isn't giving even a `privileged: true` pod its own cgroup
namespace — nested Incus's child-container cgroups are real siblings of
the pod's own live-managed cgroup subtree, not a private, delegated
subtree it fully owns. That's precisely the mechanism this whole
benchmark series is about (declared-vs-actual cgroup accounting), so this
scenario could not produce a comparable density number.
