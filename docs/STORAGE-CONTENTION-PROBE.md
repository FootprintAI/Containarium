# Storage contention probe

Measures whether one tenant's writeback stalls another tenant's `fsync` on
the same backend.

## A single number is not a health signal

This is the whole reason the tool exists. On a backend where every tenant
rootfs sits on one filesystem — and therefore on one journal — an idle
latency check reports the affected containers as the **fastest** storage in
the fleet:

| measurement | 50 × (4 KiB write + fsync) |
| --- | --- |
| affected tenant, **idle** | **17 ms** |
| physical host, same partition | 46 ms |
| a ZFS-backed backend, busy | 196 ms |
| affected tenant, **under co-tenant load** | **11,885 ms** |

Reading the first row alone, the broken backend looks healthier than the
healthy one. Only the **ratio** between a quiet baseline and a probe taken
under co-tenant load separates them.

## The load has to be volume, not fsync frequency

The second trap. What reproduces the stall is co-tenant dirty-page *volume*:

| load applied to a co-tenant | probe result |
| --- | --- |
| 4 × tight `fsync()` loops, 4 KiB writes | 32 ms — *barely moves* |
| 8 × (64 MiB buffered write → `fsync`) + CPU | **11,885 ms** |

`storage-probe load` therefore writes 64 MiB between syncs. A unit test pins
the bytes-per-fsync ratio so the generator cannot quietly regress into the
small-write pattern that does not reproduce the bug.

## Running it

Run the two halves in **different boxes on the same backend**.

```bash
# 1. quiet baseline, in box B
containarium storage-probe probe

# 2. in box A — generate co-tenant load (Ctrl-C to stop)
containarium storage-probe load

# 3. in box B again, while A is still running
containarium storage-probe probe

# 4. classify the pair
containarium storage-probe compare --baseline-ms 17 --under-load-ms 11885
```

```
ratio:      699.1x
verdict:    severe
```

Use `--dir` to target a specific filesystem. The default is the box's temp
directory, which is on the rootfs — that is where the contention shows up,
because it is the rootfs that tenants share.

## Verdicts

| verdict | condition | meaning |
| --- | --- | --- |
| `isolated` | ratio < 3x | co-tenant load did not meaningfully affect fsync latency |
| `degraded` | ratio 3–20x, **or** a high ratio whose absolute latency is still small | a real slowdown, short of a shared-journal collapse |
| `severe` | ratio ≥ 20x **and** ≥ 50 ms per fsync under load | fsync latency collapsed — the shared-journal signature |
| `unknown` | — | baseline unusable. **Not a pass.** |

The gap between the `isolated` and `severe` thresholds is deliberately wide.
The tight-fsync load that did *not* reproduce the bug still reached ~1.9x, and
a probe that flagged ordinary load variance is one operators learn to ignore.

**`severe` needs both a ratio and an absolute number, because a ratio has no
scale.** A migrated backend measured 15.6 ms idle → 318 ms under four busy
co-tenants: a 20.4x ratio, but 51x *better* in absolute terms than the host
that prompted this work. Ratio alone called that `severe`, which would have
put a machine where builds are fine in the same bucket as one where they stall
for 20 seconds. 20x on a 15 ms baseline is 318 ms; 20x on a 1,000 ms baseline
is 20 s — the same ratio, a different problem.

## Take enough samples

The distribution has a long tail by construction, so a small sample lies. A
three-sample run of the scaling curve above produced a **non-monotonic**
result — four busy tenants appearing better than two — purely from two
outliers. Six samples produced a clean monotonic curve. Treat any single run
as indicative, not conclusive, and compare medians as well as means.

## Limitations

- The thresholds are calibrated against one measured incident. They are a
  starting point, not a validated classifier, which is why this is a manual
  tool rather than wired into automated backend health.
- It measures a *pair* of runs you take by hand. Orchestrating the two-box
  run automatically is not implemented.

Related: `docs/BACKEND-STORAGE-DRIVER.md` for which driver a backend should
use, and issue #1206 for the original investigation.
