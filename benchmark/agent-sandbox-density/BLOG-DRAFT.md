# 929, 373, 186: what actually explains agent sandbox density

We wanted to know a simple thing: how many isolated agent sandboxes can you
actually fit on one machine? So we ran a real, live density benchmark
across three deployment modes on the same host, pushed each until it
broke, and fixed what we broke along the way.

- **373** — Kubernetes + [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox), sandboxes as gVisor pods
- **186** — Containarium running the same way: `pod → gVisor → Containarium`, same Kubernetes, same isolation
- **929** — Containarium's native LXC backend, no Kubernetes, no gVisor at all

If you only remember one of those numbers, remember that the **gVisor-matched
comparison is 186 vs. 373 — and Containarium is the smaller one.** That's not
a caveat buried in the fine print; it's the fair fight, and it's worth
understanding exactly why before the 929 number means anything.

## The apples-to-apples result: 186 vs. 373

Same host, same hard resource cap (48GiB RAM / 20 vCPU), same sandbox
profile family, both under Kubernetes with the identical `runsc` (gVisor)
RuntimeClass. The only real difference is how each side declares its
sandbox's memory:

- agent-sandbox's pods request **128Mi**
- Containarium's `create` sets request and limit to the same value —
  **256Mi**, exactly 2x

Kubernetes' scheduler reserves the full **declared request** against node
capacity the instant a pod is scheduled, whether the pod ever touches that
memory or not. `48GiB ÷ 128Mi ≈ 373`. `48GiB ÷ 256Mi ≈ 186`. Halve 373 and
you land almost exactly on 186. **The entire gap is the declared-size
asymmetry — not gVisor overhead, not orchestration cost.** Same isolation
technology, same admission model, smaller declared footprint wins. Nothing
about Containarium is more efficient here; it just asks for less. If we'd
declared Containarium's sandboxes at 128Mi too, the two numbers converge.

## Where 929 comes from — a different deployment entirely

Containarium also ships a native LXC/Incus backend: no Kubernetes, no
gVisor, sandboxes run directly on the host. Run the same benchmark there
and you get **929** — but this isn't a gVisor-vs-gVisor result, because
there's no gVisor and no Kubernetes admission control in this path at all.
It's a different question: raw LXC density vs. k8s+gVisor density, with a
different isolation model underneath.

<!-- diagram: declared vs. actual used, three columns — see blog-preview.html -->

The mechanism is the same *kind* of gap, just triggered differently.
Kubernetes reserves what's *declared*, always, both for agent-sandbox's
pods and for Containarium's own pods above — that's why 186 tracks 373 so
cleanly. Incus's `limits.memory`, when there's no Kubernetes scheduler in
front of it, is a cgroup **ceiling**, not a reservation: a box declared at
256Mi that's only using ~90MiB only counts ~90MiB against the host. That's
a real, legitimate operational property of running LXC directly — and a
real trade-off. No admission backpressure means nothing tells the platform
"stop" until the host actually runs out. When we pushed far enough, that's
exactly what happened: the host ran out of real RAM at ~930 sandboxes,
full stop, independent of anything else we fixed along the way.

## What we actually hit pushing the LXC path to 929

Getting there wasn't one clean run — it took three real fixes, found live,
in order:

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
3. **The real wall was RAM, not CPU** — and it landed at ~930 sandboxes on
   both the buggy and the fixed run, which is exactly the confirmation we
   wanted: fixing the software bugs didn't move the physical ceiling, it
   just let us actually reach it cleanly instead of stalling early on
   self-inflicted overhead.

Each fix, measured live at the same checkpoint container counts:

| containers | before either fix | `get` fix only | both fixes |
|---|---|---|---|
| ~400 | `incusd` at 914% CPU | load ~19 | load 4-8 |
| ~570 | load ~117 | load 32-40 | load 15-21 |
| ~760 | — (had already stopped) | load 125-182 | load 38-40 |
| ~930 | 569 (stopped: bug) | 931 (stopped: RAM) | 929 (stopped: RAM) |

We also found and fixed a couple of smaller things along the way — a
per-create install step that should've been baked into an image once
instead of repeated on every create, and a host account creation bug that
silently broke after about a dozen tenants. Full detail, every number,
every commit: [`RESULTS.md`](RESULTS.md) in the benchmark folder.

## What this actually means

Two separate, honest takeaways, not one flattering headline:

**If you need gVisor-grade isolation under Kubernetes**, Containarium's
sandboxes don't magically pack denser than agent-sandbox's — on this
benchmark they packed for fewer, purely because of a declared-size choice
that's easy to change. If your agents are idle-heavy (most agent sandboxes
spend most of their time waiting, not computing), the real lever for
*either* system is the same: your actual memory usage is probably far
below whatever you've declared as the request. Lower it, or tune a VPA to
track reality — without touching gVisor, without touching either
project's code.

**If you're willing to leave Kubernetes and gVisor's isolation model
behind**, Containarium's native LXC backend can pack meaningfully more —
because it isn't reserving headroom nobody's using. That's a real,
different trade-off (weaker isolation boundary, no admission
backpressure, a hard wall when you finally exhaust real memory), not a
strictly-better number.

---

*Full methodology, every host spec, every raw number, and the complete
bug-by-bug investigation are in [`benchmark/agent-sandbox-density/`](.)
in the Containarium repo — reproduce it yourself, or tell us where the
comparison should go next.*
