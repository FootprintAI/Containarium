# CPU capacity admission (#1029)

By default a Containarium daemon places every container a caller asks for,
regardless of how much CPU is already committed on the host. `limits.cpu` bounds
*which* cores a container sees, and (since #1034) `limits.cpu.allowance` gives it
a hard CFS quota — but nothing stops an operator from committing far more cores
than the host physically has. On a shared multi-tenant host that overcommit is
how one busy tenant degrades every co-located one.

This is an **opt-in** admission gate: when enabled, a create is refused (or, in
advisory mode, logged) if it would push the host's committed cores past
`physical_cores × factor`.

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
| `--cpu-overcommit-factor` | `CONTAINARIUM_CPU_OVERCOMMIT_FACTOR` | `0` | Ceiling multiple of physical cores. `0` (or negative) disables the gate. |
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
- **Fail-open.** If the host's physical core count or its container list can't
  be read, the create proceeds. A capacity check must never be the reason a box
  can't be made.
- **Runtime.** Applies to the LXC/Incus substrate. On the k8s runtime the Incus
  resource read fails and the gate no-ops (Kubernetes does its own admission).

## Not covered here (follow-ups)

- **Capacity-aware placement ranking.** Today pool placement picks the first
  healthy peer; a natural extension is to prefer the *least-committed* peer so
  overcommit is spread rather than merely refused at the edge (#1029 direction 2,
  "deprioritize" variant).
- **A read surface for current commitment.** The advisory logs expose the
  numbers; a first-class report (extending `GetSystemInfo` with committed cores)
  would let operators see a host's overcommit without grepping logs.
