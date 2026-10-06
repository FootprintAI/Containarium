# CPU capacity admission (#1029)

By default a Containarium daemon places every container a caller asks for,
regardless of how much CPU is already committed on the host. `limits.cpu` bounds
*which* cores a container sees, and (since #1034) `limits.cpu.allowance` gives it
a hard CFS quota — but nothing stops an operator from committing far more cores
than the host physically has. On a shared multi-tenant host that overcommit is
how one busy tenant degrades every co-located one.

This is an **opt-in** admission gate: when enabled, a create is refused (or, in
advisory mode, logged) if it would push the host's committed cores past
`logical_cpus × factor` (Incus counts logical CPUs — vCPUs incl. SMT threads — matching the unit `limits.cpu` uses).

## When a declared CPU is a real floor, not just a ceiling

**This section is about the LXC/Incus backend specifically** — the runtime
this gate applies to (see "Runtime" under "Semantics and scope" below; on
K8s the gate no-ops entirely, and the analogous concept is the backend's own
`--cpu-request`/`resources.requests.cpu` split, a separate mechanism, not this
gate).

On LXC/Incus, a box's `--cpu` (or `resize --cpu`) always bounds a *ceiling* —
the hard CFS quota #1034 gives every numeric CPU request. Whether that
number is also a **floor** — a guarantee the box actually gets that much CPU
under contention — depends entirely on this gate's configuration, and only
one configuration delivers that guarantee:

- **The gate must be enforced, not merely advisory.** `--cpu-overcommit-enforce`
  off (the default posture even with a factor set) blocks nothing — a host
  can already be arbitrarily oversubscribed.
- **The factor must be greater than `0` and no greater than `1`
  (`0 < factor ≤ 1`).** `0` (or negative) does not mean "strict" — it
  disables the gate entirely (see "Configuration" below), which is the
  ceiling-only case, not a floor. A factor above `1` is *deliberate*
  overcommit: the example later in this doc (`--cpu-overcommit-factor 4
  --cpu-overcommit-enforce`) explicitly permits committed quotas up to 4×
  physical capacity, which is a ceiling-only regime by design, not a floor.
- **The operator must leave headroom for the host's own core-infra CPU.**
  The gate's committed-cores accounting excludes core-role containers (the
  platform's own Postgres/Caddy/control-plane, not tenant workload — see
  "What counts as committed" below), so a factor of exactly `1` still lets
  the *host* be pushed past its true physical capacity once core-infra CPU
  is added on top of a maxed tenant commitment. Size the tenant-facing
  factor to leave room for the host's known core-infra footprint (e.g. a
  factor slightly under `1`, or `(physical_cores − core_infra_cores) /
  physical_cores`), not exactly `1`.

Any other configuration on LXC/Incus — the off-by-default posture, advisory
mode, a factor of `0` or below, or a factor above `1` — means a declared CPU
is a **ceiling only**. That is a deliberate, named trade-off documented
here, not an oversight: existing fleets are frequently already well past 1×
overcommit (see below), and nothing about `resize --cpu <bigger>` on such a
host changes what it delivers, because the box was never CPU-starved by its
own ceiling in the first place — it was starved by every co-located box's
ceiling being unenforced together. Reaching for a bigger `--cpu` is not the
remedy; enabling and enforcing this gate (with realistic headroom) is.

`get_system_info` / `SystemInfo.committed_cpu_cores` (paired with
`total_cpus`) gives an operator or agent a live read on how committed a host
currently is, without grepping the advisory logs below.

## Why opt-in, and why a *factor* rather than a hard 1×

CPU is compressible — modest overcommit is normal and desirable, because tenants
rarely peg their full allocation simultaneously. A hard 1× (no overcommit) would
strand capacity. The factor lets each operator choose their own oversubscription
ratio against their own workload mix.

It is off by default because existing fleets are frequently already well past 1×
(an 8-core host holding several `limits.cpu=8` tenants sits near ~14×); turning
on strict enforcement globally would make those hosts refuse every new create
until they were rebalanced. Enabling is a deliberate operator step.

## Configuration

Two daemon flags (each with an environment-variable fallback):

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--cpu-overcommit-factor` | `CONTAINARIUM_CPU_OVERCOMMIT_FACTOR` | `0` | Ceiling multiple of the host's logical CPUs (vCPUs). `0` (or negative) disables the gate. |
| `--cpu-overcommit-enforce` | `CONTAINARIUM_CPU_OVERCOMMIT_ENFORCE` | `false` | When the factor is set, actually reject over-ceiling creates. When `false`, the gate is advisory (logs what it would reject). |

Example — allow up to 4× overcommit, enforced:

```
containariumd daemon --cpu-overcommit-factor 4 --cpu-overcommit-enforce
```

## Recommended rollout (advisory → enforce)

Enforcing blind on a live fleet risks surprising rejections. Roll out the way
the network-policy engine was rolled out — observe first:

1. **Observe.** Set `--cpu-overcommit-factor` to your candidate ratio and leave
   `--cpu-overcommit-enforce` off. The daemon logs one
   `[cpu-admission] ADVISORY (not enforced): would reject …` line per create it
   *would* have blocked, with the host's committed/requested/ceiling numbers.
2. **Calibrate.** Watch those logs across your real workload. If legitimate
   creates would be rejected, raise the factor (or rebalance hosts) until the
   advisory line only fires on genuine overcommit.
3. **Enforce.** Add `--cpu-overcommit-enforce`. Over-ceiling creates now fail
   with gRPC `ResourceExhausted` and a message naming the numbers; the caller
   can retry on a less-loaded backend/pool.

## Budgeting the platform's own CPU (#2284)

The gate budgets **tenant** CPU only. Core-role containers — Postgres, Caddy,
VictoriaMetrics, the control plane, the security and OTel sidecars — are
skipped by `committedCoresExcluding`, and `SystemInfo.committed_cpu_cores`
applies the same exclusion. That is deliberate (it is the number a
tenant-facing factor is sized against), but it means the factor alone says
nothing about whether the platform's own processes still get CPU when
tenants contend. One live 8-CPU host carried ~199 tenant cores against a 4×
(32-core) advisory ceiling with 49 `would reject` lines in a day and blocked
none; creates then stalled while the daemon and `incusd` were healthy but
starved.

Three things make that visible now:

- **`SystemInfo` reports all three numbers**: `committed_cpu_cores` (tenant),
  `core_committed_cpu_cores` (platform) and `total_cpus` (physical), plus the
  gate's posture as the `CPUAdmissionMode` enum (`DISABLED` / `ADVISORY` /
  `ENFORCING`) and `cpu_overcommit_factor`. `containarium info` prints them as
  a `CPU Budget:` block; the MCP `get_system_info` tool prints the same.
- **Advisory mode warns instead of failing silently.** When the gate is
  advisory and tenant-committed cores already exceed `total_cpus × factor`,
  the daemon logs one `[cpu-admission] WARNING:` line at start naming the
  ratio and saying the gate is not enforcing, and `containarium info` prints
  the same `WARNING:` line. Under the ceiling, or in enforcing / disabled
  mode, the daemon logs a plain `CPU budget:` posture line and the CLI shows
  the numbers without a warning.
- **A headroom recipe.** The declared CPU is a real floor only when the gate
  is enforced at a factor that leaves the platform's cores un-overcommitted:

  ```
  factor ≤ (total_cpus − core_committed_cpu_cores) / total_cpus
  ```

  Worked example: 8 logical CPUs, core containers committing 2 + 1 + 1 + 4 = 8
  cores (the `core_services.go` defaults) → headroom factor 0: the platform
  alone already covers the host, and *any* tenant commitment overcommits it.
  Trim the core requests (or use a bigger host) until core-committed is well
  under `total_cpus`; e.g. 16 CPUs with 4 core cores → factor ≤ 0.75. A factor
  above that is a ceiling, not a floor (see "When a declared CPU is a real
  floor" above), and should be described as such.

### Optional: a reserved core set for platform containers

For an absolute floor rather than a budget, pin the core-role containers to a
CPU set with the existing `limits.cpu` range notation and keep tenants off
those cores:

```
incus config set core-postgres limits.cpu 0-1        # platform on cores 0–1
containarium create alice --cpu 2-7                   # tenants on the rest
```

`incus.CommittedCores` counts a range by its width (`0-1` → 2 cores), so the
budget numbers above stay correct. The pin is only a floor if **every** tenant
on the host is kept off the reserved cores — a fleet-wide setting, not a
per-box one; a single tenant left on `limits.cpu: 8` (any 8 cores) shares the
reserved set and the floor is partial. Document the convention for the host
and verify it with `containarium info`'s core-committed line.

### Host daemons: `CPUWeight=` for `incusd` and the daemon

The budget above is about containers. The two host processes every create
depends on — `incusd` and the `containarium` daemon — used to run in
`system.slice` at systemd's default `CPUWeight=100`, the same weight every
tenant instance has, so a saturated host starved the processes that would
have created the next box. `containariumd service install` (and therefore
`hacks/install.sh`, `scripts/setup-peer.sh` and `pool join`) now installs:

- `CPUAccounting=yes` + `CPUWeight=1000` inline in `containarium.service`;
- the same two lines as a drop-in for the packaged incus unit,
  `/etc/systemd/system/incus.service.d/50-containarium-cpu-weight.conf`
  (incus.service is the distro's / Zabbly's file and is never edited in place);
- `systemctl set-property --runtime incus.service CPUWeight=1000` right after
  `daemon-reload`, so the running `incusd` picks the weight up without a
  restart (a restart would stop every tenant); the drop-in takes over at the
  next boot.

A weight is a share under contention, not a cap and not a real-time
priority: when the host is idle nothing changes, and when ~70 tenants are
runnable the two daemons each get roughly ten times one tenant's slice.
The number lives in one place, `hostcheck.PlatformCPUWeight`.

`containarium doctor` reports **platform daemons CPU weight** as a posture
check. It reads the *effective* `cpu.weight` of both units' cgroups
(`/sys/fs/cgroup/system.slice/<unit>/cpu.weight`), so a drop-in that was
written but never applied, or a cgroup v1 host, shows red with the reason;
like every posture check it is non-blocking.

### The local health probe on a busy host (#2317)

Placement refuses the local backend when it is not fit to take new work
(`no healthy backend found in pool …`), and `containarium backends` / the
`ListBackends` RPC report the same verdict as the local entry's `Healthy` field.
On a host that carries many instances under CPU pressure, that verdict has to
stay answerable: it asks Incus for its server info only (not a listing of every
instance, so the cost does not grow with the tenant count), one probe is shared
by all concurrent callers, and a single failed or slow sample does not flip the
host to unhealthy while Incus has answered within the last 15 seconds. A daemon
that stays unresponsive past that window is still reported unhealthy.

- `CONTAINARIUM_LOCAL_HEALTH_TIMEOUT` (a Go duration, default `3s`, accepted
  range `100ms`–`30s`) is how long a caller waits for the probe. Raise it on a
  host that is routinely saturated; out-of-range values fall back to the default.
- The daemon logs `[health] local backend unhealthy: …` and
  `[health] local backend healthy again` only on a change, and
  `[health] local backend probe slow: …` (at most once per 30s) when a probe that
  succeeded used over a quarter of its budget — the early sign of saturation.

### Reading the host's CPU count when Incus is slow (#2325)

The gate needs the host's logical CPU count on every create. That number is hardware-static, so the daemon reads
Incus' resource inventory once and then serves it from memory: a read shares one in-flight request, is bounded to a
few seconds, and keeps serving the last good value (stale is fine for the CPU count, model, memory total and GPUs)
if a later refresh fails or times out. Incus' hardware scan can stop answering on a saturated host; without this a
create would have blocked on it before reaching the gate's own logging. If Incus has never answered, the gate falls
back to the OS's logical CPU count (logged once per daemon run) so it keeps working instead of skipping itself. The
same bounded read serves `GetSystemInfo`, `ListBackends` and the metrics collectors; used memory and disk are
refreshed about every 10 seconds, and the load averages are always read fresh from `/proc/loadavg`.

## Semantics and scope

- **Per-host, and it composes with pools.** The gate runs on the daemon that
  actually creates the box. A pool/peer-routed create is forwarded to the target
  peer's own daemon, which runs *its* gate against *its* host — so no
  cross-host capacity view is needed, and each host enforces its own ceiling.
- **Daemon-only — local CLI mode never runs it.** `containarium create`/
  `resize` invoked without `--server` talks to Incus directly
  (`internal/cmd/create.go`'s `createLocal`, `resize.go`'s
  `runResizeLocal`) and never reaches the daemon's gRPC handlers this gate
  lives in. A local-mode create/resize is not subject to this gate at all,
  regardless of how it's configured — only requests that actually go
  through a daemon (`--server ...`) are gated.
- **What counts as committed.** The sum of every tenant container's committed
  cores (`CommittedCores` over its `limits.cpu` / `limits.cpu.allowance`). Two
  exclusions: **core-infra** containers (platform Postgres/Caddy — not tenant
  workload) and the **tenant being recreated** (so a resize-by-recreate doesn't
  count its own outgoing container against its replacement).
- **Fail-open.** If the host's logical CPU count or its container list can't
  be read, the create proceeds. A capacity check must never be the reason a box
  can't be made.
- **Runtime.** Applies to the LXC/Incus substrate. On the k8s runtime the Incus
  resource read fails and the gate no-ops (Kubernetes does its own admission).

## Capacity-aware pool placement (`--placement-cpu-aware`)

Admission refuses an over-committed host; ranking keeps hosts from getting there
by *spreading* new containers. With `--placement-cpu-aware`
(`CONTAINARIUM_PLACEMENT_CPU_AWARE`), a pool create with no explicit backend is
routed to the **least CPU-committed** healthy peer — lowest committed-cores /
logical-CPU ratio — instead of the arbitrary first-healthy peer picked today.

```
containariumd daemon --placement-cpu-aware
```

- **No per-create cost.** Each peer's committed and logical-CPU counts are cached on
  the existing ~30s peer-discovery cadence (via the daemon's internal admin
  token); placement reads the cache. Ratios are therefore slightly stale, which
  is fine for spreading.
- **Ratio, not absolute cores** — so a lightly loaded 32-core host outranks a
  near-full 8-core host.
- **Unknown falls back.** A peer just discovered (or whose last capacity fetch
  failed) is "unknown" and ranks after every peer whose load we do know; it
  becomes known within a discovery tick. If *no* peer's capacity is known,
  placement is plain first-healthy.
- **Scope.** Peer ranking only. The "local backend wins when healthy"
  short-circuit is deliberately unchanged — letting local participate in the
  ranking is a larger behavior change (data gravity, latency) best decided
  separately. Pairs naturally with, but is independent of, the admission gate
  above.

## Not covered here (follow-ups)

- **Local participation in ranking.** Today an in-pool healthy local backend
  still wins unconditionally; a future option could rank local alongside peers.

## Concurrent admission (#1588)

Two concurrent creates/resizes admitting against the same host's committed
cores could each read a stale (pre-mutation) snapshot and jointly exceed the
ceiling — the check and the mutation weren't atomic with respect to each
other. Closed by an in-memory reservation: an admitted request reserves its
cores (`ContainerServer.cpuReservations`) for the duration of its caller's
mutation, and every subsequent admission check on that host counts other
tenants' outstanding reservations on top of the real committed total, not
just the real total alone. The caller releases the reservation once its
mutation concludes (success or failure) — `CreateContainer`, `ResizeContainer`,
and the cluster reconciler's VM provisioning all do this.

A reservation also expires on its own after `cpuReservationTTL` (10 minutes)
as a safety net for a caller whose completion this package can't directly
observe — the k8s Box-CR path hands off to the operator's own
reconciliation and never calls release explicitly.
