# We packed 929 sandboxes on one box — and it's not about gVisor

We wanted to know a simple thing: how many isolated agent sandboxes can you
actually fit on one machine? So we ran a real, live density benchmark —
Kubernetes + [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
on one side, Containarium's native LXC backend on the other — pushed both
until they broke, and fixed what we broke along the way.

The headline number: **929 Containarium sandboxes vs. 373 agent-sandbox
pods**, both under a 48GiB / 20-vCPU host. But if you stop at that number
you'll walk away with the wrong lesson. The real story is more interesting
— and more useful, whichever side of this you're building on.

## The setup

Same host, same hard resource cap, same sandbox profile (200m CPU /
256Mi memory) on every side. Two groups:

- **Control**: kubeadm + Calico + agent-sandbox, sandboxes as pods
- **Experiment**: Containarium's native LXC/Incus backend — no
  Kubernetes, same host

Both groups' actual boxes idle at roughly the same real memory footprint
(tens of MiB). The difference isn't the sandbox — it's what each system
does with the *declared* resource size when deciding whether to admit one
more.

## The mechanism, not the marketing

Kubernetes' scheduler reserves the full **declared request** against node
capacity the instant a pod is scheduled — 128Mi requested means 128Mi
reserved, whether the pod ever touches it or not. That's a deliberate,
sane default: it protects every *other* tenant on the node from a noisy
neighbor. Our control group hit its wall at exactly `48GiB / 128Mi ≈ 373`
— textbook admission-controlled scheduling, working exactly as designed.

Incus's `limits.memory`, by contrast, is a cgroup **ceiling**, not a
reservation. A box declared at 256Mi that's only using 90MiB only counts
90MiB against the host. Containarium's density number is higher because
it's *not reserving headroom nobody's using* — which is a real,
legitimate operational property, and also a real trade-off: no admission
backpressure means nothing tells the platform "stop" until the host
actually runs out. When we pushed far enough, that's exactly what
happened — the host ran out of real RAM at ~930 sandboxes, full stop,
independent of anything else we fixed along the way.

**If we'd held both sides to the same admission model — memory *request*
== memory *limit*, same as Containarium's `create` always does — Container-
ium's own earlier k8s+gVisor run actually landed *behind* the control
group** (186 vs. 373), because its declared ceiling (256Mi) is exactly 2x
the control group's declared request (128Mi). Same host, same math,
opposite conclusion. The admission model is the variable, not the
sandboxing technology.

## What we actually hit pushing to 929

Getting there wasn't one clean run — it took three real fixes, found live:

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
3. **The real wall was RAM, not CPU** — and it stayed at ~930 sandboxes on
   both the buggy and the fixed run, which is exactly the confirmation we
   wanted: fixing the software bugs didn't move the physical ceiling, it
   just let us actually reach it cleanly instead of stalling early on
   self-inflicted overhead.

We also found and fixed a couple of smaller things along the way — a
per-create install step that should've been baked into an image once
instead of repeated on every create, and a host account creation bug that
silently broke after about a dozen tenants. Full detail, every number,
every commit: [`RESULTS.md`](RESULTS.md) in the benchmark folder.

## What this means if you're running agent-sandbox

Not "switch to Containarium." The actual, portable takeaway: **if your
agents are idle-heavy** (most agent sandboxes spend most of their time
waiting, not computing), your real memory usage is probably far below
whatever you've declared as the request. Kubernetes gives you the lever
to close that gap yourself — lower requests, a VPA tuned to actual usage,
or a `LimitRange` that keeps limits generous while requests track reality
— without touching gVisor, without touching agent-sandbox's own code.
The density gap we measured isn't a verdict on either project; it's a
measurement of two different default postures toward the same trade-off,
and it's one you can dial on either side.

---

*Full methodology, every host spec, every raw number, and the complete
bug-by-bug investigation are in [`benchmark/agent-sandbox-density/`](.)
in the Containarium repo — reproduce it yourself, or tell us where the
comparison should go next.*
