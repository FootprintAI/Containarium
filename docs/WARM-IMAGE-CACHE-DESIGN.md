# Warm-image cache for in-box podman (#908)

Status: **design / RFC** — no code yet. This doc picks a direction and scopes a
v1 before we build. It is grounded in the current box/podman seams (cited
inline); if those move, re-check before implementing.

## Problem

Every box gets its own podman storage, so **every fresh box pulls its images
from scratch**. For multi-GB images, cold-start latency becomes a function of
registry bandwidth and host load:

- The motivating consumer's agent-server image (~3.8 GB) pulled in ~2–3 min on
  an idle backend host, but **~17 min on the same host under load** (measured
  during the runtime-provider work).
- Programmatic consumers have fixed readiness budgets (the OpenHands SDK
  declares a sandbox dead after 300 s). A provider that *sometimes* takes 17 min
  to first-start is not shippable.
- Long pulls also forced the runtime shim to run pulls detached with polling,
  because a single `podman pull` exec spanning the pull gets severed on a
  proxied SSH path. Warm images make that whole class of fragility rare.

This is a **general mechanism gap**, not an application-specific one: recipes
already pay the same cost (a ~2 GB app image under load took 10–15 min in past
deploys). The fix belongs in the box/podman substrate, expressed generically.

## Box-model constraints (why the directions are NOT equivalent)

These are the load-bearing facts. They rule things in and out:

1. **A box is an unprivileged incus LXC instance; podman runs *inside* it.**
   `EnablePodman` turns on LXC nesting (`EnableNesting`) and installs podman +
   `systemctl enable podman` in-box — `pkg/core/container/manager.go:148`,
   `:315`, `:557`. Privileged boxes (`EnablePodmanPrivileged`, AppArmor off) are
   opt-in, not the default (`manager.go:37`, `:158`).
2. **Per-box podman storage is ephemeral** — it lives in the box's rootfs and
   dies with the box. Nothing is shared between boxes today.
3. **No podman on the host is assumed.** The host runs incus; podman is a
   box-level dependency. Anything that needs to *populate* a podman-format
   store must bring its own podman (host install, or a dedicated instance).
4. **The platform already runs "core services" as boxes** —
   `containarium-core-caddy`, `containarium-core-otelcollector`
   (`internal/server/core_otel_collector.go:21`, `container_ip_map_test.go`),
   keyed off an incus core-role label (`pkg/core/box/box.go:143`). A new
   always-on infrastructure service has an established home.
5. **RO host→box bind-mounts are a solved pattern**: `incus config device add
   <box> <dev> disk source=<host> path=<box> readonly=true`
   (`internal/security/scanner.go:278`). We can mount a host path RO into a box.
6. **The box substrate can drop files into a box** (`container.Manager.WriteFile`,
   used via `box/lxc` `WriteFile`) and run commands (`manager.Exec`). Recipe
   `post_start` (the `podman pull`/`podman run` step) runs through `manager.Exec`
   detached — `internal/server/recipe_server.go:286`. No box writes
   `/etc/containers/registries.conf` or `storage.conf` today, so either is a
   greenfield injection at the podman-enable step (`manager.go:557`).

## Don't build a mirror. Ship the wiring; bring your own.

Pull-through registry caching is a **commodity** — `registry:2` proxy mode,
Harbor proxy-cache projects, zot, and every cloud registry's pull-through
mirror all do it well. The mistake would be to build or operate a registry
inside Containarium. **We shouldn't.**

The actual mechanism gap is narrower: **a box today cannot be pointed at a
mirror at all.** No box writes `/etc/containers/registries.conf`, and there is
no config hook to supply one (constraint 6). So the *only* thing Containarium
must ship is that thin box-side wiring — the mirror itself is
bring-your-own, off-the-shelf.

### Direction 1 (recommended) — BYO mirror: config + registries.conf injection

Containarium ships **only**:
1. a config knob (daemon/host) declaring one or more registry mirrors —
   `upstream → mirror URL` (e.g. `ghcr.io → registry-mirror.internal:5000`), and
2. box-create injection that writes `/etc/containers/registries.conf` in the box
   with those mirror entries, at the podman-enable step (`manager.go:557`,
   constraint 6).

The mirror is **whatever the operator already runs** (or stands up from an
off-the-shelf image — see the optional recipe below). First box pulls *through*
it (WAN, once); every box after pulls over the LAN.

- **We build ~zero infra** — a config field + a file the box already knows how
  to receive (`WriteFile`, constraint 6). No service to run, GC, or capacity-plan.
- Works for **arbitrary images, no curation**; **no idmap/overlay sharing**
  (each box keeps its own store, just fed from the LAN mirror); **fails safe**
  (no mirror configured, or mirror down → boxes pull upstream exactly as today).
- Fits the open-core line: OSS ships the generic *mechanism* (point a box at a
  mirror); operators supply the commodity *service*.

**Optional convenience (not product code):** a documented `deploy/` recipe/compose
that stands up `registry:2` in pull-through mode as a `containarium-core-*` box
(constraint 4) for operators who don't already run one. It's an off-the-shelf
image behind a recipe — swappable for Harbor/zot/cloud AR — never a thing we
maintain the internals of.

### Direction 2 — golden base image (no running service either)

Bake the hot images into the **incus base image** boxes launch from: publish a
custom base whose podman store is pre-populated, so a fresh box has them already
present — zero pull, no mirror, no service. Cost: the warm set is coupled to the
base image (rebuild + redistribute the base per region to change it), and it
only helps images known at base-build time. Good complement to Dir 1 for a small,
stable hot set; not a substitute for arbitrary images.

### Direction 3 — shared read-only additional image store (deferred)

Maintain a warmed podman store on the host, RO-bind-mount it into boxes
(constraint 5) + `additionalimagestores` in the box's `storage.conf`. Zero-pull
and fastest, **but** it needs host podman (constraint 3) and runs into
unprivileged-LXC idmap ownership on a shared overlay store (constraint 1) — layer
ownership read back through the box idmap mismatches, which containers/storage
treats as a foreign/corrupt store; making it robust tends to force privileged
boxes. Materially bigger and riskier; not the first win.

| | Dir 1: BYO mirror | Dir 2: golden base | Dir 3: shared RO store |
| --- | --- | --- | --- |
| Infra we build/run | ~none (config + file) | base-image build | host store + RO mounts |
| Warm first-start | tens of seconds (LAN) | seconds (baked in) | seconds (zero-pull) |
| Arbitrary images | yes, no curation | no (baked set only) | no (curated) |
| Needs host podman | no | at base-build only | yes |
| Unprivileged-LXC safe | yes | yes | risky (idmap) |
| Failure mode | upstream pull (today) | upstream pull (today) | box can't read store |
| Update the warm set | change config / mirror | rebuild+ship base | re-warm host store |

## Recommendation: Direction 1 (BYO mirror), Direction 3 as the knob it needs

Ship **Direction 1** — config + `registries.conf` injection, mirror BYO. It is
the *smallest* change that closes the gap, reuses commodity infra instead of
reinventing it, is robust under the unprivileged-LXC reality, and fails safe.
Keep **Direction 2 (golden base)** in the back pocket for a tiny stable hot set.
Treat **Direction 3 (shared RO store)** as a later zero-pull optimization once
the idmap story is proven — not a v1 gate.

Layer a thin **warm-list** on top (the old "Direction 3" control idea): a recipe
/ daemon config can *declare* an image so the operator's mirror is pre-primed
once (a warm pull *through* the mirror at host-init, off the box's hot path).
`oci-service` can advertise its caller image this way. This is a knob, not a
service.

## v1 scope (Direction 1)

1. **Mirror config** — a daemon/host config field: a list of `upstream → mirror`
   entries (and an `insecure` flag for a plain-HTTP LAN mirror). Empty = today's
   behavior, no injection.
2. **Box-create injection** — at the podman-enable step (`manager.go:557`), write
   `/etc/containers/registries.conf` in the box with a `[[registry]].mirror` for
   each configured upstream (`WriteFile`, constraint 6). Gated on config being set.
3. **CLI-first surface** (per CLAUDE.md) — a `containarium warm-image <ref>` verb
   that primes the configured mirror for an image (a pull-through prime), plus
   `--list`. MCP, if any, wraps the same Go function.
4. **Warm-list declaration (optional)** — a recipe field (e.g. `warm_images`) /
   daemon list the host keeps primed via (3).

Deliberately **out of v1:** building/operating a registry (BYO); the shared RO
store (Dir 3); the golden base image (Dir 2); cache federation and GC (the
mirror owns its own lifecycle, off-the-shelf).

## Acceptance

With a mirror configured and image `X` primed (or pulled once by an earlier box):
a fresh box runs `X` to `podman run -d` completion in seconds-to-tens-of-seconds,
independent of WAN conditions. With **no** mirror configured, box creation and
pulls behave exactly as today (no regression). Validate on a real backend host by
timing a second box's pull of the agent-server image vs. the first, pointed at an
off-the-shelf `registry:2` proxy.

## Open questions

- **One mirror per host vs. per region?** Per-host is simplest and keeps the pull
  on the LAN; per-region shares cache but adds a network hop. Start per-host.
- **Mirror identity/TLS** — boxes reach the mirror over the LAN bridge; plain
  HTTP on the bridge (registries.conf `insecure`) vs. a cert. Start with the
  bridge + insecure-local, revisit if boxes can span hosts.
- **Cache eviction** — size cap + LRU is enough for v1; a declared warm-list is
  pinned (never evicted).
- **Does `EnablePodmanPrivileged` change the injection?** No — registries.conf
  injection is identical for privileged and unprivileged boxes; only Direction 2
  cared about privilege.
