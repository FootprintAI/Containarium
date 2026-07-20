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
containarium daemon --cpu-overcommit-factor 4 --cpu-overcommit-enforce
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

## Semantics and scope

- **Per-host, and it composes with pools.** The gate runs on the daemon that
  actually creates the box. A pool/peer-routed create is forwarded to the target
  peer's own daemon, which runs *its* gate against *its* host — so no
  cross-host capacity view is needed, and each host enforces its own ceiling.
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
containarium daemon --placement-cpu-aware
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
- **A read surface for current commitment.** The advisory logs expose the
  numbers; a first-class report (extending `GetSystemInfo` with committed cores)
  would let operators see a host's overcommit — and a peer's — without grepping
  logs.
