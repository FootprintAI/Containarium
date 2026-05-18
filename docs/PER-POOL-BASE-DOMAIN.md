# Per-Pool Base Domain Routing

**Status**: Shipped. Single-domain support landed in #205 (Phase 3); multi-domain support in #207 (Phase 3b).
**Related**: [MULTI-POOL.md](MULTI-POOL.md), [APP-HOSTING.md](APP-HOSTING.md), [CUTOVER-DEMO-INTO-PROD-SENTINEL.md](CUTOVER-DEMO-INTO-PROD-SENTINEL.md), [PLAN-DEMO-CONTAINER-MIGRATION.md](PLAN-DEMO-CONTAINER-MIGRATION.md).
**Enables**: serving multiple base domains (e.g. `example.com` and `example.org`) from a single sentinel without per-container alias bookkeeping; one backend hosting workloads under multiple parent domains.

## Problem

Before this work, every app hostname a pool's Caddy served had to appear in that primary's `--public-aliases` ([MULTI-POOL.md:178](MULTI-POOL.md#app-domain-routing-via-aliases)). The sentinel's SNI router did exact-match against `Primary.Hostname` plus the alias list and fell back to the legacy single-backend forwarder on miss.

That worked when app domains were a small fixed set (`api.example.com`, `voice.example.com`, …) registered once at primary startup. It broke when:

- **Containers create their own subdomains dynamically.** `expose_port blog` on the demo backend produces `blog.example.org`. The container exists; the Caddy route exists on the backend; the cert ACMEs fine. But the sentinel didn't know that name → demo-backend, so the SNI peek missed and fell back to the wrong backend.
- **A single sentinel needs to serve two or more base domains.** Prod's sentinel handled `*.example.com` purely by the fallback path (single registered backend == prod). Adding `example.org` for the demo backend meant the fallback could no longer be "the one backend" — different SNI suffixes needed to go to different backends.
- **A single backend needs to host workloads under multiple parent domains.** The lab-hosts-demo pattern: the lab backend serves both `*.lab.example.com` (its own pool's workloads) and `*.demo.example.org` (migrated demo workloads). This is the Phase 4 / B2 path in [PLAN-DEMO-CONTAINER-MIGRATION.md](PLAN-DEMO-CONTAINER-MIGRATION.md).

The exact-alias workaround was doable for fixed app domains but doesn't scale to either dynamic subdomains or multi-tenant backends.

## Design

A per-primary **list of base domains** that the SNI router uses for **suffix matching** after exact-alias matching fails and before the legacy fallback.

### Registry

```go
type Primary struct {
    Pool        Pool     `json:"pool"`
    Hostname    string   `json:"hostname"`
    Aliases     []string `json:"aliases,omitempty"`
    BaseDomains []string `json:"base_domains,omitempty"` // suffix-match anchors
    IP          string   `json:"ip"`
    Port        int      `json:"port"`
    BackendID   string   `json:"backend_id,omitempty"`
    ...
}
```

Lookup method:

```go
// LookupByBaseDomainSuffix returns the primary whose BaseDomains contain
// the longest proper DNS suffix of hostname. A primary may advertise
// multiple base domains; each is considered independently. Returns nil
// when no primary qualifies or when two primaries tie on suffix length
// (ambiguity = misconfiguration; fail closed).
func (r *PrimaryRegistry) LookupByBaseDomainSuffix(hostname string) *Primary
```

Suffix match means `strings.HasSuffix(hostname, "." + bd)` for each `bd` in `BaseDomains` — *proper* suffix, so the base domain itself (`example.org`) does NOT match. This keeps the apex hostname usable as a separate `Hostname` or `Alias` for the apex.

### SNI router precedence

`buildSNIRoutingHandler` in `internal/sentinel/manager.go`:

1. Exact `Hostname` / `Alias` match (`LookupByHostname`) — unchanged from pre-Phase-3.
2. `BaseDomains` suffix match (`LookupByBaseDomainSuffix`) — Phase 3 (single) / Phase 3b (multi).
3. Legacy fallback to `fallbackTarget` — unchanged.

The fallback stays as a safety net for unpooled single-backend deployments (no `BaseDomains` configured → step 2 always returns nil → behavior identical to pre-Phase-3).

### Handshake + flag plumbing

`TunnelHandshake` gains `PublicBaseDomains []string`. Repeatable flag on both daemon and tunnel commands:

```
containarium daemon ... --public-base-domain lab.example.com --public-base-domain demo.example.org
containarium tunnel ... --public-base-domain lab.example.com --public-base-domain demo.example.org
```

When unset, the daemon falls back to `[--base-domain]` (single-element list derived from the existing flag) so single-domain deployments need no extra config.

REST POST `/sentinel/primaries` body uses `base_domains: [...]`.

### Tie-breaking

- **Longest suffix wins.** When two base domains both match (e.g. `example.com` and `lab.example.com` for SNI `notebook.lab.example.com`), the longer suffix is more specific and wins. Implemented in `LookupByBaseDomainSuffix` by tracking `bestLen` across all `(primary, base-domain)` pairs.
- **Equal-length ties fail closed.** Two primaries advertising the *same* base domain is a misconfiguration; the lookup returns nil rather than picking arbitrarily. Caught regardless of which slot the duplicate lives in within each primary's `BaseDomains` list.
- **Exact alias beats suffix.** Operator's explicit `--public-aliases` entry overrides the implicit suffix routing (step 1 runs before step 2 in the SNI router).

## Worked examples

### Example A — two backends, two base domains

| Backend | `--pool` | `--public-hostname` | `--public-base-domain` (repeatable) |
|---|---|---|---|
| prod | `prod` | `prod.example.com` | `example.com` |
| demo | `demo` | `demo.example.org` | `example.org` |

Inbound SNI on the prod sentinel:

| SNI | Match path | Forwards to |
|---|---|---|
| `prod.example.com` | exact (Hostname) | prod backend |
| `api.example.com` | exact (Aliases, if listed) | prod backend |
| `blog.example.org` | suffix (`.example.org`) | demo backend |
| `example.com` (apex) | none → fallback | legacy backend |

### Example B — one backend, multiple base domains (lab-hosts-demo)

The lab backend in the [demo container migration plan](PLAN-DEMO-CONTAINER-MIGRATION.md) hosts both its own pool's workloads and migrated demo workloads. One primary registration covers both surfaces:

```
containarium tunnel \
  --pool lab \
  --public-hostname lab-primary.example.com \
  --public-base-domain lab.example.com \
  --public-base-domain demo.example.org \
  --public-port 443
```

| SNI | Match path | Forwards to |
|---|---|---|
| `notebook.lab.example.com` | suffix (`.lab.example.com`) | lab backend |
| `blog.demo.example.org` | suffix (`.demo.example.org`) | lab backend (same!) |
| `api.example.com` | none — `lab.example.com` is more specific than `example.com`, but neither prefix matches `api.example.com`. Falls through. | fallback |

The pool tag stays `lab` — `demo.example.org` is just the routing surface, not a separate trust boundary. If you want demo containers to also be visible as `pool=demo` (for `containarium list --pool=demo` filtering, etc.), use container labels rather than splitting the backend.

### Example C — longest-suffix wins across multi-domain primaries

| Backend | `BaseDomains` |
|---|---|
| lab | `[example.com, demo.example.org]` |
| lab2 | `[sub.example.com]` |

SNI `notebook.sub.example.com` matches both lab's `example.com` (length 11) and lab2's `sub.example.com` (length 15). Lab2 wins — more-specific suffix is the user's intent.

## Edge cases & failure modes

- **Identical base domains across pools.** Two primaries advertise `BaseDomains` containing the same string. `LookupByBaseDomainSuffix` returns nil. Fail closed; surfaces the misconfig instead of silently picking the wrong backend.
- **Suffix collides with exact alias on a different primary.** Exact wins (step 1 before step 2). Operator's explicit choice overrides implicit routing.
- **Tunneled primary disconnects.** Same as pre-Phase-3 — `UnregisterByBackendID` removes the entry; suffix lookups stop matching for those base domains; suffix-matched SNI falls through to the legacy fallback.
- **PROXY-v2 framing.** Suffix-matched destinations go through the same dial-or-yamux path as exact matches, so the existing `m.config.ProxyProtocol` handling still applies. No new code needed.
- **Per-container base-domain selection.** Not a concept — the *backend* advertises its base domains, and the *container* publishes a route under whichever fits. The route-builder in `internal/app/proxy.go` already handles "FQDN that doesn't match the daemon's `--base-domain` → use as-is," so a lab container exposed as `blog.demo.example.org` (FQDN) Just Works even if the daemon's `--base-domain=lab.example.com`.

## Operational additions (per cluster)

These are required regardless of the code; listed here so the work isn't a surprise during rollout.

1. **DNS.** Wildcard record for each base domain → sentinel IP. Cloudflare-managed for `example.org`, separate provider for `example.com`.
2. **ACME on each backend.** Caddy on every backend that advertises a given base domain needs creds to mint certs for subdomains under it. HTTP-01 works transparently over sentinel passthrough; DNS-01 requires the relevant provider's API token in the backend's environment.
3. **GLB cert SAN.** Only if the GLB terminates TLS (prod is passthrough, so this is a no-op).

## What this does NOT change

- ACME on the sentinel itself (sentinel doesn't terminate TLS for app traffic; passthrough only).
- Caddy on any backend (each backend continues to own its own `--base-domain` for daemon-driven route naming; this design just makes the sentinel aware of additional suffix anchors).
- The `--public-aliases` flag (still works for explicit per-domain routing; suffix match is additive).
- Pool-aware container placement (Phase 1 / #204 — that's the input side; this is the output side).

## Test coverage

`internal/sentinel/base_domain_test.go`:

| Test | What it pins |
|---|---|
| `LookupByBaseDomainSuffix` | basic suffix match, deeper subdomain, base-domain-itself-isn't-a-match, unrelated returns nil, empty input |
| `LookupByBaseDomainSuffix_LongestWins` | nested base domains (`lab.example.com` beats `example.com` for the nested name) |
| `LookupByBaseDomainSuffix_AmbiguousFailsClosed` | two primaries with the same `BaseDomains` entry → nil |
| `LookupByBaseDomainSuffix_EmptyBaseDomainSkipped` | unconfigured primary is invisible to suffix lookup |
| `ExactHostnameBeatsSuffix` | router precedence at registry level (alias vs suffix) |
| `LookupByBaseDomainSuffix_MultipleOnOnePrimary` | **Phase 3b** — single primary advertises multiple base domains; both match |
| `LookupByBaseDomainSuffix_MultiDomainLosesToMoreSpecific` | **Phase 3b** — longest-wins still applies across multi-domain primaries |
| `LookupByBaseDomainSuffix_AmbiguousAcrossMultiDomain` | **Phase 3b** — same base domain on two primaries fails closed regardless of slot order |
| `SNIRouting_BaseDomainSuffix` | end-to-end via SNI router harness — suffix match, exact-beats-suffix, fallback |
| `SNIRouting_MultiBaseDomainOnOneBackend` | **Phase 3b** — end-to-end of lab-hosts-demo |
| `RegisterUpdatesBaseDomain` | re-registration replaces the `BaseDomains` list |

`internal/cmd/daemon_base_domains_test.go`:
- `TestResolvePublicBaseDomains` — explicit values win, base-domain fallback when unset, empty in both yields nil.

## Alternatives considered

- **Push container hostnames to the sentinel on every `expose_port`.** Workable but couples the route store to a remote API call on every mutation. Adds latency to route creation and a new failure mode (sentinel unreachable → can't expose a port). Suffix match keeps the contract one-way (daemon → sentinel at registration time, never per-route).
- **Wildcard aliases (`*.example.org` as an alias entry).** Same effect but harder to reason about: aliases are also matched against `Hostname` for non-wildcards, and mixing wildcards into a list invites accidental over-matching. A separate `BaseDomains` field makes the intent explicit.
- **Caddy on the sentinel.** Would centralize routing but adds TLS termination on the sentinel (vs. today's passthrough), which breaks per-backend ACME, complicates client IP recovery, and adds another component to keep alive. Not worth it for this use case.
- **`BaseDomain string` (single, Phase 3) instead of `BaseDomains []string` (Phase 3b).** The single-domain version shipped first and was complete for the demo-via-prod-sentinel use case. Multi-domain landed when the Phase 4 plan revealed the need for one backend (the lab) to serve both `*.lab.example.com` and `*.demo.example.org`. Migration from singular → plural was a clean field rename across ~10 files with no semantic drift.
