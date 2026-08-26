# 929, 373, 373: a density gap, a one-flag fix, and a different deployment mode entirely

We wanted to know a simple thing: how many isolated agent sandboxes can you
actually fit on one machine? So we ran a real, live density benchmark
across three deployment modes on the same host, pushed each until it
broke, found a real gap, fixed it, and re-ran to confirm.

- **373** — Kubernetes + [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox), sandboxes as gVisor pods
- **373** — Containarium running the same way: `pod → gVisor → Containarium`, same Kubernetes, same isolation, **once a real CLI gap was fixed**
- **929** — Containarium's native LXC backend, no Kubernetes, no gVisor at all

The middle number used to be 186. We found out why, fixed the actual
cause — a genuine, one-flag CLI gap, not a measurement error — and
re-ran the exact same comparison. It now matches exactly. Here's the
whole story, including the part where we were wrong first.

## Round one: 186 vs. 373, and why

Same host, same hard resource cap (48GiB RAM / 20 vCPU), same sandbox
profile family, both under Kubernetes with the identical `runsc` (gVisor)
RuntimeClass. The first time we ran this, Containarium's boxes only
reached 186 against agent-sandbox's 373 — roughly half.

The cause traced to how each side declares its sandbox's memory:

- agent-sandbox's pods request **128Mi**, with a **256Mi** limit
- Containarium's `create` had no way to set those two numbers
  separately — `--memory 256Mi` set *both* request and limit to 256Mi,
  exactly 2x agent-sandbox's request

Kubernetes' scheduler reserves the full **declared request** against
node capacity the instant a pod is scheduled, whether the pod ever
touches that memory or not. At the stopping point, node memory requests
hit 47984Mi/48GiB (99%) for agent-sandbox and 47856Mi/48GiB (99%) for
Containarium — both sides essentially saturated the same total memory
budget, just divided into differently-sized chunks: 373 × 128Mi ≈
46.6GiB, 186 × 256Mi ≈ 46.5GiB. Halving the request size, not halving
anything else, produced almost exactly half the count. We re-ran it
independently on a fresh cluster to rule out a fluke — 186 ready, 189
attempted, an exact match down to the node memory snapshot. It was a
real, solid, reproducible number. It just wasn't the whole story yet.

## The fix: a missing CLI flag, not an architecture problem

`ResourceLimits.memory` (`pkg/core/box/k8s/objects.go`) was always
applied as *both* request and limit — there was no field, no flag, no
way to ask for a smaller request under a bigger limit, the way Burstable
QoS pods (agent-sandbox's included) are normally sized. Kubernetes
itself supports `request ≠ limit` fine; Containarium's `create` API had
simply never exposed the second number.

We added it —
[#1557](https://github.com/FootprintAI/Containarium/issues/1557),
shipped as [PR #1560](https://github.com/FootprintAI/Containarium/pull/1560):
`containarium create` gained `--memory-request`/`--cpu-request`, separate
from `--memory`/`--cpu` (which stay the limit). Empty preserves the old
behavior exactly — this is additive, not a breaking change.

## Round two: 373 vs. 373, exact match

With the fix landed, we re-ran the comparison on a fresh cluster —
Containarium's boxes now declared at the *same* profile as
agent-sandbox's pods (request 128Mi / limit 256Mi memory, 25m/50m CPU) —
and, since only the runtime class was the remaining variable, we also
took the opportunity to isolate gVisor's own cost cleanly: the identical
matched profile, run once under gVisor (`runsc`) and once under plain
`runc`, on the same cluster.

| | gVisor (`runsc`) | plain `runc` |
|---|---|---|
| Sandboxes reached RUNNING | **373** | **373** |
| Attempted (incl. failures) | 376 | 376 |
| Node memory requests at stop | 47984Mi/48GiB (99%) | 47984Mi/48GiB (99%) |
| Wall-clock for the density loop | ~77 min | ~40 min |

**Exact match, identical node memory snapshot down to the Mi, and it
lands within a rounding error of agent-sandbox's own 373.** With the
request/limit split available, Containarium's k8s+gVisor path doesn't
just close the gap with agent-sandbox — it matches it. gVisor's own
per-pod density cost is not measurable at this sandbox size against a
48GiB host: the entire 186-vs-373 gap really was the declared-size
asymmetry, exactly as we suspected but couldn't yet prove the first time
around. Worth naming honestly: agent-sandbox's pods still run a minimal
`busybox` image against Containarium's real, heavier
`containarium-agent-box` runtime in this run too — that asymmetry never
went away, and the counts matched exactly anyway, because density here
is governed by the declared memory *request*, not image size or pull
time.

The one real, measurable difference between the two legs wasn't density
— it was time. ~77 minutes under gVisor vs. ~40 minutes under plain
`runc` to reach the same 373, roughly 2x. gVisor's per-sandbox startup
overhead is real; it shows up in *how fast* you get to a given density,
not in *how dense* you can get. Worth knowing, not worth losing sleep
over for most workloads — but it's the honest, separate cost gVisor
actually has here.

## Where 929 comes from — a different deployment entirely

Containarium also ships a native LXC/Incus backend: no Kubernetes, no
gVisor, sandboxes run directly on the host. Run the same benchmark there
and you get **929** — but this isn't a gVisor-vs-gVisor result, because
there's no gVisor and no Kubernetes admission control in this path at
all. It's a different question: raw LXC density vs. k8s+gVisor density,
with a different isolation model underneath.

<!-- diagram: declared vs. actual used, three columns — see blog-preview.html -->

Kubernetes reserves what's *declared*, always — that's the mechanism
behind both 373s above. Incus's `limits.memory`, when there's no
Kubernetes scheduler in front of it, is a cgroup **ceiling**, not a
reservation: through most of this run, boxes declared at 256Mi were only
actually using something like 90-100MiB (measured at checkpoints along
the way, not a number we confirmed still held at the final count) — and
only that much counted against the host. That's a real, legitimate
operational property of running LXC directly — and a real trade-off. No
admission backpressure means nothing tells the platform "stop" until the
host actually runs out. When we pushed far enough, that's exactly what
happened: the host ran out of real RAM at ~930 sandboxes, full stop,
independent of anything else we fixed along the way.

## What we actually hit pushing the LXC path to 929

Getting there wasn't one clean run — two real fixes, found live, then a
wall that held:

1. **`containarium list` didn't scale.** The benchmark's own polling loop
   called `list` (which fetches every container's full state) every ~2s
   while waiting on one sandbox to boot. At a few hundred containers that
   put real, unnecessary load on the management daemon. Fix: a `get`
   command for the one-container case ([#1543](https://github.com/FootprintAI/Containarium/pull/1543)) — roughly 3x lower daemon
   load at the same container count once we swapped the benchmark to use it.
2. **A background cache had the same bug, independent of the benchmark.**
   Containarium's own traffic-attribution cache re-fetched *every*
   container's details every 30 seconds, forever, regardless of whether
   anything changed. Fixed to only re-fetch what actually changed
   ([#1546](https://github.com/FootprintAI/Containarium/pull/1546)) — the daemon CPU wall that had crept back in past ~600
   containers disappeared entirely; load stayed flat (single digits) all
   the way to the same real memory ceiling.

**Then the real wall: RAM, not CPU.** It landed at ~930 sandboxes on both
the fixed run and the earlier, buggy one — not because fixing the software
bugs moved the physical ceiling, but because the fixes let us actually
*reach* it cleanly instead of stalling early on self-inflicted daemon CPU
overhead.

Each fix, measured live at the same checkpoint container counts:

| containers | before either fix | `get` fix only | both fixes |
|---|---|---|---|
| ~400 | n/a — the unfixed run never got a clean reading this early | load ~19, `incusd` at 914% CPU | load 4-8, `incusd` at 48% CPU |
| ~570 | `incusd` at 1025% CPU, load ~117 — **this is where it stopped** | load 32-40 | load 15-21 |
| ~760 | — | load 125-182 | load 38-40 |
| final count | **569** (stopped: `incusd` CPU wall) | **931** (stopped: RAM, `incusd` OOM-killed) | **929** (stopped: RAM, `context deadline exceeded`) |

We also found and fixed a couple of smaller things along the way — a
per-create install step that should've been baked into an image once
instead of repeated on every create, and a host account creation bug that
silently broke after about a dozen tenants. Full detail, every number,
every commit: [`RESULTS.md`](RESULTS.md) in the benchmark folder.

## What this actually means

**If you need gVisor-grade isolation under Kubernetes**, Containarium's
sandboxes now pack exactly as densely as agent-sandbox's — 373 vs. 373,
confirmed twice. That wasn't true when we started this investigation: it
took finding a real gap and shipping a real fix
([#1557](https://github.com/FootprintAI/Containarium/issues/1557)) to
get here, and we're telling that whole story rather than only the
flattering ending. The one remaining cost is time-to-density under
gVisor (~2x slower to fill the same host), not density itself. If your
agents are idle-heavy (most agent sandboxes spend most of their time
waiting, not computing), the lever that matters for *either* system is
the same regardless: your actual memory usage is probably far below
whatever you've declared as the request — lower it, or tune a VPA to
track reality.

**If you're willing to leave Kubernetes and gVisor's isolation model
behind**, Containarium's native LXC backend can pack meaningfully more —
929 vs. 373 — because it isn't reserving headroom nobody's using. That's
a real, different trade-off (weaker isolation boundary, no admission
backpressure, a hard wall when you finally exhaust real memory), not a
strictly-better number, and not the same comparison as the gVisor-matched
result above.

---

*Full methodology, every host spec, every raw number, and the complete
bug-by-bug investigation are in [`benchmark/agent-sandbox-density/`](.)
in the Containarium repo — reproduce it yourself, or tell us where the
comparison should go next.*
