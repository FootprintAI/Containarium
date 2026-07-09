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

## The two viable directions

### Direction 1 — pull-through registry mirror (a core service)

Run a registry **pull-through cache** (e.g. `registry:2` in proxy mode, or zot)
as a new **core-service box** per backend host/region — same lifecycle model as
`core-caddy`/`core-otelcollector` (constraint 4). At box create, inject a
`/etc/containers/registries.conf` mirror entry so the box's podman resolves the
target registries (ghcr.io, docker.io, …) through the LAN mirror first
(constraint 6, at `manager.go:557`).

- First box to want an image pulls it *through* the mirror (WAN, once per host);
  the mirror caches the blobs. **Every box after pulls over the LAN.**
- 3.8 GB over a LAN link is seconds-to-tens-of-seconds — meets the acceptance.

**Pros:** works for **arbitrary images, no curation**; no host podman
(constraint 3 satisfied — the mirror is itself a container); **no idmap/overlay
sharing** (each box still has its own store, just fed locally); fits the
existing core-service pattern (constraint 4); degrades safely (mirror down →
boxes fall back to the upstream registry, i.e. today's behavior).

**Cons:** still a per-box *pull* (LAN-fast, not zero-copy); you run and
capacity-manage a cache service (disk lifecycle / GC for the blob cache);
registries.conf must enumerate which upstreams to mirror.

### Direction 2 — shared read-only additional image store

Maintain one **warmed podman image store on the host**, RO-bind-mount it into
each box (constraint 5), and write the box's `/etc/containers/storage.conf` with
`additionalimagestores = ["<mountpath>"]` so podman sees warmed images as
already present. A box's first `podman run` of a warmed image is **zero-pull**.

**Pros:** fastest — no pull at all (meets "seconds", the strongest form of the
acceptance).

**Cons (the reason this is not the v1):**
- **Populating the store needs podman on the host or a dedicated warmer box**
  (constraint 3) — new infrastructure either way.
- **Unprivileged idmap ownership.** Boxes are unprivileged LXC (constraint 1),
  each with its own uid/gid idmap. A shared overlay store populated by a
  *different* podman (host or warmer box, different mapping) is read back through
  the box's idmap; layer file ownership can mismatch, which podman's
  containers/storage treats as a corrupt/foreign store. Making this robust
  tends to force **privileged boxes** (constraint 1's opt-in) or careful
  `raw.idmap` alignment — a materially bigger, riskier change.
- Curation + storage lifecycle for what gets warmed (which is Direction 3).

| | Dir 1: pull-through mirror | Dir 2: shared RO store |
| --- | --- | --- |
| First-start speed (warm) | tens of seconds (LAN pull) | seconds (zero-pull) |
| Arbitrary images | yes, no curation | no — curated warm-list |
| Needs host podman | no (mirror is a container) | yes (or a warmer box) |
| Unprivileged-LXC safe | yes (per-box store, just LAN-fed) | risky (idmap on shared overlay) |
| New infra | one cache core-service | host store + RO mounts + storage.conf |
| Failure mode | falls back to upstream (today) | box can't read store → worse than today |

## Recommendation: Direction 1 as v1, Direction 3 as the knob

Ship the **pull-through mirror** first. It clears the acceptance ("tens of
seconds"), is robust under the unprivileged-LXC reality that makes Direction 2
risky, needs no host podman, works for any image with zero curation, and fails
*safe* (back to today's behavior). Direction 2's zero-pull is a worthwhile
*later* optimization for a curated hot set once the idmap story is proven — it
is not the thing to gate the first win on.

Layer **Direction 3 (warm-list) as a thin control knob** on top: a recipe /
daemon config can *declare* an image as warmable so the mirror is pre-primed
(one warm pull through the mirror at deploy/host-init, not on the box's hot
path). This is where a recipe like `oci-service` would advertise its image.

## v1 scope (Direction 1)

1. **Mirror core-service** — a pull-through registry cache box, provisioned like
   the other `containarium-core-*` services (constraint 4). Config: which
   upstreams to proxy (ghcr.io, docker.io, quay.io), cache dir + size cap. Likely
   a `deploy/` artifact + daemon wiring, not just Go.
2. **Box-create injection** — at the podman-enable step (`manager.go:557`), write
   `/etc/containers/registries.conf` in the box with the mirror as a
   `[[registry]].mirror` for each proxied upstream, when a mirror is configured
   for the host. Gated so a host without a mirror behaves exactly as today.
3. **CLI-first surface** (per CLAUDE.md) — a `containarium warm-image <ref>` verb
   that primes the mirror for a given image (pull-through prime), plus status
   (`containarium warm-image --list`). The MCP tool, if any, wraps the same Go
   function.
4. **Warm-list declaration** — an optional recipe field (e.g. `warm_images`) and/
   or a daemon config list the host keeps primed. `oci-service` can declare its
   caller image warmable via a param passthrough.

Deliberately **out of v1:** the shared RO store (Direction 2), cross-host cache
federation, and any automatic GC policy beyond a size cap.

## Acceptance

On a host with a running mirror and image `X` primed (or pulled once by an
earlier box): a fresh box configured with the mirror runs `X` to `podman run -d`
completion in seconds-to-tens-of-seconds, independent of WAN conditions. On a
host with **no** mirror configured, box creation and pulls behave exactly as
today (no regression). Validate on a real backend host by timing a second box's
pull of the agent-server image vs. the first.

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
