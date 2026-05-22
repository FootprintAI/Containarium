# Ephemeral Sandbox — Design Note

> Status: **Exploration / not yet approved.** Filed in response to
> the CubeSandbox comparison ([readme](https://github.com/TencentCloud/CubeSandbox))
> — their `<60ms` MicroVM cold-start exposes a workload Containarium
> doesn't serve today: short-lived per-task agent sandboxes.

## Where we are today

Every Containarium container is a **persistent LXC**: ZFS-backed
rootfs, takes seconds-to-minutes to create (Incus pull + provision +
SSH-key seeding), and is expected to live for the tenant's lifetime.
This is the right shape for "alice has a dev box she SSHs into for a
month" — the workload the platform was built for.

It's the wrong shape for "alice's agent needs to run this Python
snippet, in isolation, for 30 seconds." Today the agent's options
are:

1. **Run it in alice's persistent box.** Fastest, but no isolation
   — a malicious snippet has alice's files and credentials.
2. **Create a fresh container per task.** Strong isolation, but
   `containarium create` takes ~30-90s; unusable in an agent inner
   loop.
3. **Plug an external service (e2b, CubeSandbox).** Solves the
   problem outside Containarium; loses the unified auth surface and
   per-tenant accounting.

The gap is real and the workload is growing as agents move from
"one-shot code-gen" to "loop-and-iterate."

## Goal

A new container class — **ephemeral sandbox** — that:

- Starts in **single-digit seconds** (best-effort `<5s`; not aiming
  for CubeSandbox's `<60ms` since LXC kernel-share has a different
  cost model than MicroVM snapshot-clone).
- Has **no persistent state**: rootfs is tmpfs / overlayfs-on-tmpfs;
  destroyed on stop.
- Is **claimed from a per-tenant warm pool** so per-tenant
  provisioning costs amortize across many tasks.
- Reuses the existing **JWT scope + ownership authz** surface — no
  separate auth model.
- Stays **LXC-based** for v1 (no MicroVM jump). The isolation gap
  vs. CubeSandbox is acknowledged and documented; operators who
  need MicroVM-grade isolation can run CubeSandbox alongside.

## Threat model

| Threat | Mitigated? |
| --- | --- |
| Sandbox-to-host escape via LXC | Same as today (unprivileged LXC + AppArmor). **No improvement.** |
| Sandbox-to-sandbox leak via shared bridge | Out of scope here — covered by [`NETWORK-ISOLATION-DESIGN.md`](security/NETWORK-ISOLATION-DESIGN.md). |
| Tenant-to-tenant leak via warm pool | Mitigated: each tenant has its own pool; sandboxes are destroyed on stop. |
| Long-lived state survives an attack | Mitigated: no persistent rootfs. |
| Resource exhaustion (DoS via spawn flood) | Per-tenant rate limit on `create-sandbox`; pool size caps total claim. |

## Architecture sketch

```
                         ┌──────────────────────────────┐
                         │   Tenant warm pool           │
   POST /v1/sandboxes ──>│   (per-tenant, N pre-warmed) │
   tenant=alice          │                              │
                         │  [stopped]  [stopped]  ...   │
                         └────┬─────────────────────────┘
                              │ claim
                              v
                         ┌──────────────────────────────┐
   <-- sandbox_id ------ │   alice-sb-7af3              │
                         │   ephemeral=true             │
                         │   rootfs: overlayfs(tmpfs)   │
                         │   network: tenant netns      │
                         └──────────────────────────────┘
                              │
                              │ POST /v1/sandboxes/<id>/exec
                              v
                         ┌──────────────────────────────┐
                         │   {stdout, stderr, exit}     │
                         └──────────────────────────────┘
                              │
                              │ DELETE /v1/sandboxes/<id>  (or TTL)
                              v
                         [destroyed; pool repopulates]
```

### Pieces to build

1. **Sandbox lifecycle proto + handlers** — `CreateSandbox`,
   `ExecInSandbox`, `WriteFileInSandbox`, `ReadFileInSandbox`,
   `DeleteSandbox`. Mirror the e2b verb shape so an eventual
   compat-shim is cheap.
2. **Warm-pool reconciler** — a daemon goroutine that maintains
   `min_warm` stopped sandboxes per tenant. Topped up on claim,
   trimmed on idle.
3. **Ephemeral LXC profile** — `ephemeral: true` + tmpfs rootfs
   (Incus has both). Container-config keyed by `pool_owner=<tenant>`
   so the reconciler can find them.
4. **Claim path** — `sandbox.Claim(tenant)` grabs the next stopped
   sandbox, renames it to a per-task name, starts it, returns
   sandbox_id. Triggers async pool-replenish.
5. **TTL sweeper** — sandboxes auto-deleted after `idle_ttl`
   (default 5 minutes) to prevent leaks if the agent forgets to
   delete.
6. **MCP wrapper** — `mcp__containarium-prod__sandbox_create` /
   `sandbox_exec` for the agent surface. Scope `sandboxes:write`.

## Phased rollout

| Phase | Scope | Bound |
| --- | --- | --- |
| **A** | Sandbox proto + CLI (`containarium sandbox {create,exec,delete}`). Pool size 0; create-on-demand only. Validates the API shape end-to-end. | 1 week |
| **B** | Per-tenant warm pool reconciler. Configurable `min_warm` per tenant. First-claim latency drops from ~30s to single-digit seconds. | 1 week |
| **C** | TTL sweeper + per-tenant rate limit on `create-sandbox`. Hardens DoS surface. | 3 days |
| **D** | MCP `sandbox_*` tools + scope. Agent surface. | 3 days |
| **E** | e2b-compatible shim at `/v1/sandboxes/e2b/*` (optional). Lets E2B-SDK users point at Containarium without code changes. | 1 week |

Phase A is independently shippable as a primitive even if B-E never
land — it gives operators a documented "fresh container per task"
flow that didn't exist.

## Performance budget

Honest targets — not competing with CubeSandbox:

| Metric | Today (`containarium create`) | Target (warm pool) |
| --- | --- | --- |
| First-byte to claim | 30-90s | < 5s |
| Steady-state claim | 30-90s | < 2s |
| Per-sandbox memory floor | ~80MB (LXC base) | Same |
| Density per backend | dozens | hundreds |

The two-orders-of-magnitude gap vs. CubeSandbox (`<60ms`) is the
LXC-vs-MicroVM gap, not a Containarium implementation gap. Calling
it out so we don't promise what the design can't deliver.

## Open questions

- **Pool sizing policy.** Static per-tenant `min_warm`? Or
  workload-aware (track recent claim rate, auto-scale)? Static is
  simpler; workload-aware avoids over-allocation on a quiet tenant.
- **Cross-tenant pool sharing for cost savings.** Tempting on
  bare-metal where a 10-tenant deployment with `min_warm=3`
  pre-allocates 30 sandboxes. A shared pool with per-claim
  reinitialization is the e2b model. Trade isolation for density.
- **Image / template story.** v1 ships one ephemeral template
  (probably python-data-science, mirroring CubeSandbox's
  `sandbox-code` default). Multi-template needs the same
  `CreateSandbox(template=...)` shape e2b uses.
- **Network model.** New per-sandbox netns? Or share the tenant's
  netns (so sandboxes see the tenant's persistent box)? The
  eBPF design doc lands the answer.

## Decision log

- **LXC, not MicroVM, for v1.** Operational simplicity (no new
  hypervisor binary, no kernel-version coordination) > the 100x
  cold-start gap. Operators with the MicroVM workload can run
  CubeSandbox alongside.
- **Per-tenant pools, not shared pools.** Stronger isolation
  default; cost can be revisited if real workloads show waste.
- **e2b-compatibility as Phase E, not core.** The verb shape is
  influenced by e2b but the wire format isn't promised yet; a
  compat shim is opt-in.

## What this is NOT

- A replacement for the persistent-box default. Persistent boxes
  remain the right answer for dev-environment workloads.
- A MicroVM platform. CubeSandbox already exists for that workload
  and does it well.
- A code-execution-only product. The sandbox is a generic Linux
  process surface; code-interp is one of many templates.
