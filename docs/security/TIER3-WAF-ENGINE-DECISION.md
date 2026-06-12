# Tier 3 WAF engine: coraza-caddy plugin vs standalone TPROXY proxy

> Decision aid for the open question in
> [`VIRTUAL-PATCHING-TIER3.md`](./VIRTUAL-PATCHING-TIER3.md) (#662): should the
> userspace WAF run as a **coraza-caddy plugin** in the existing Caddy ingress,
> or as a **standalone Coraza behind the TPROXY steering proxy** (the path
> PR-1/PR-2 built)? Short answer: **they're complementary by traffic topology —
> do the Caddy plugin first for north-south ingress, keep the standalone proxy
> for east-west.** Rationale below.

## The fact that decides most of this: how Caddy is deployed here

Caddy is **not** embedded in the daemon as a Go module. It runs as a **separate
`/usr/bin/caddy` process inside a dedicated `core-caddy` LXC** (see
`internal/server/core_services.go`: `caddy run --config /etc/caddy/Caddyfile`,
admin API on :2019). The daemon manages it over the admin API / Caddyfile — it
does not link Caddy code.

Two consequences:

1. **The coraza-caddy plugin is a custom Caddy *build*, not a daemon dependency.**
   You'd produce a Caddy binary with the plugin (`xcaddy build --with
   github.com/corazawaf/coraza-caddy`), deploy it into the core-caddy LXC in place
   of stock `/usr/bin/caddy`, mount the CRS rule files, and have the daemon emit
   the coraza directives into the Caddy config it already manages. **Coraza + CRS
   never enter the daemon's `go.mod`** — the daemon binary stays lean.
2. **The standalone proxy + Coraza *library* is the opposite:** it adds
   `coraza/v3` + the CRS to the **daemon's** `go.mod` (the daemon binary grows and
   gains that supply-chain surface), likely behind a `waf` build tag.

So the "dependency weight" open question has *two different answers* depending on
the path — and the plugin path keeps the daemon itself dependency-free.

## What each option can actually see (the real deciding axis)

Traffic topology, not engine quality, is the crux. core-caddy only fronts
**north-south ingress** (internet → sentinel → core-caddy LXC → tenant container).
It never sees container-to-container traffic.

| Traffic | coraza-caddy (in core-caddy) | standalone TPROXY proxy (host) |
|---|---|---|
| **North-south ingress** (public → container HTTP/S) | ✅ already routed through it | ✅ if steered |
| **TLS ingress** | ✅ **Caddy already terminates TLS here** — Coraza sees decrypted HTTP for free | ⚠️ proxy must terminate TLS itself (PR-4), fail-open when no cert |
| **East-west** (container → container) | ❌ never hits Caddy | ✅ the only thing that can see it |
| **Direct-to-container** (bypasses Caddy) | ❌ | ✅ |
| **Non-HTTP** | ❌ Caddy is HTTP(S)/L4-limited | ✅ steer any flow (engine must cope) |

This maps directly onto the threat model. Tiers 1–2 already care about
**east-west** (the network-isolation substrate is container-to-container:
intra-tenant gating, metadata deny). A WAF tier that only covered ingress would
be inconsistent with that. But the **canonical #662 acceptance case — "a
multi-segment / TLS Log4Shell attempt"** — is a *north-south, TLS* exploit, which
is exactly where the Caddy plugin is strongest and the standalone proxy is
weakest (TLS).

## Dimension-by-dimension

| Dimension | coraza-caddy plugin | standalone TPROXY proxy |
|---|---|---|
| **TLS** | **free** — Caddy already terminates ingress TLS with the right cert | proxy must terminate (PR-4) + cert plumbing + fail-open hole |
| **HTTP parsing / reassembly** | **free** — Caddy hands Coraza a fully parsed `http.Request`; coraza-caddy is a mature, tested integration | we hand-roll head reassembly (PR-2) / a full parser for Coraza |
| **Daemon dependency surface** | **none** — Coraza+CRS live in the Caddy build, not the daemon | adds coraza/v3 + CRS to the daemon `go.mod` |
| **Deploy/ops** | custom Caddy binary in the core-caddy LXC + CRS files; daemon writes config | nft TPROXY rules (PR-3) + host routing + CAP_NET_ADMIN + a userspace hop |
| **Coverage** | north-south ingress only | east-west + direct + non-HTTP (topology-independent) |
| **eBPF's role** | ~none for ingress (Caddy already routes); eBPF only picks *which routes* get WAF | eBPF/TPROXY **is** the steering — matches #662's framing |
| **Perf** | in-path for already-proxied ingress; marginal per-request WAF cost | extra userspace hop for steered flows; fast path untouched |
| **Reuses PR-1/PR-2** | no (different path) | yes (the proxy + the `Inspector` seam) |

## Recommendation: hybrid, plugin-first

These are **not** mutually exclusive — they cover different traffic. The
`Inspector` interface PR-2 introduced is the unifying abstraction: the same CRS
rule set + the scanner→virtual-patch-rule hook feed both engines.

**Phase ordering (revised from the original design, which led with the standalone
proxy):**

1. **coraza-caddy for north-south ingress — do this first.** It delivers the
   canonical TLS/multi-segment Log4Shell acceptance with TLS termination and HTTP
   parsing *for free*, adds **zero dependency to the daemon**, and reuses the
   ingress path the platform already runs. Highest value, lowest cost, smallest
   blast radius. Work is: a custom Caddy build target + the daemon emitting
   coraza directives into the Caddy config it already manages + shipping the CRS.
2. **Standalone TPROXY proxy (PR-1/PR-2, already built) for east-west / direct.**
   This is the *only* way to cover container-to-container exploits — consistent
   with how Tiers 1–2 treat east-west. Its TLS limitation matters far less here
   (east-west is often cleartext on the bridge), so the fail-open gap is
   acceptable. PR-2's reassembling `BuiltinInspector` already gives real value
   on this path today with no dependency; a Coraza-library inspector behind the
   same interface is the upgrade if/when east-west needs CRS-grade rules.

**Net:** PR-1/PR-2 are not wasted — they own the east-west half. But the *first
production WAF engine* should be **coraza-caddy in the core-caddy LXC**, because
TLS-terminated ingress is both the headline use case and the cheapest place to
get it right.

## Implications for the open questions

- **Dependency weight** → split: ingress WAF lives in the Caddy build (daemon
  `go.mod` untouched); the east-west Coraza engine, if pursued, is the only thing
  that would want the `waf` build tag on the daemon.
- **TLS termination** → reuse Caddy's for ingress (the strong case); the proxy's
  own TLS becomes a lower-priority, east-west-only concern.
- **Coverage gap to flag to operators**: the Caddy-plugin path does **not** see
  east-west; if that's in scope, the standalone proxy must run too. Don't let
  "WAF enabled" imply full coverage when only ingress is wired.

## What this needs from a human

A go/no-go on: (a) producing + deploying a custom Caddy build with coraza-caddy
into the core-caddy LXC (the ops commitment), and (b) whether east-west WAF
coverage is in scope now or deferred (decides if the standalone-proxy Coraza
engine is built). Until then, PR-1/PR-2 stand as the steering + reassembling-
inspection foundation, dependency-free.
