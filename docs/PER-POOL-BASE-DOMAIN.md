# Per-Pool Base Domain (Design)

**Status**: Draft — not yet implemented.
**Depends on**: [MULTI-POOL.md](MULTI-POOL.md), [APP-HOSTING.md](APP-HOSTING.md).
**Drives**: serving multiple base domains (e.g. `kafeido.app` and `containarium.dev`) from a single sentinel without per-container alias bookkeeping.

## Problem

Today, every app hostname a pool's Caddy serves must appear in that primary's `--public-aliases` ([MULTI-POOL.md:178](MULTI-POOL.md#app-domain-routing-via-aliases)). The sentinel's SNI router does exact-match against `Primary.Hostname` plus the alias list ([primary_registry.go:139-156](../internal/sentinel/primary_registry.go)) and falls back to the legacy single-backend forwarder on miss ([manager.go:608-611](../internal/sentinel/manager.go)).

That works when app domains are a small fixed set (`api.kafeido.app`, `voice.kafeido.app`, …) registered once at primary startup. It breaks when:

- **Containers create their own subdomains dynamically.** `expose_port blog` on the demo backend produces `blog.containarium.dev`. The container exists; the Caddy route exists on the backend; the cert ACMEs fine. But the sentinel doesn't know that name → demo-backend, so the SNI peek misses and falls back to the wrong backend.
- **A single sentinel needs to serve two or more base domains.** Today prod's sentinel handles `*.kafeido.app` purely by the fallback path (single registered backend == prod). Adding `containarium.dev` for the demo backend means the fallback can no longer be "the one backend" — different SNI suffixes need to go to different backends.

The workaround (register every container's hostname as an alias and update on every `expose_port`) is doable but ugly: it'd require a sentinel-API round-trip on every route mutation, with all the cache-invalidation pain that implies.

## Proposal

Add a **per-primary base domain** that the SNI router uses for **suffix matching** after exact-alias matching fails and before the legacy fallback.

### Registry change

`Primary` gains a `BaseDomain` field, populated from a new `--public-base-domain` daemon flag (default empty == legacy behavior):

```go
type Primary struct {
    Pool       Pool      `json:"pool"`
    Hostname   string    `json:"hostname"`
    Aliases    []string  `json:"aliases,omitempty"`
    BaseDomain string    `json:"base_domain,omitempty"` // NEW: suffix-match anchor
    IP         string    `json:"ip"`
    Port       int       `json:"port"`
    BackendID  string    `json:"backend_id,omitempty"`
    ...
}
```

New lookup method:

```go
// LookupByBaseDomainSuffix returns the primary whose BaseDomain is a
// proper DNS suffix of hostname. Returns nil if no primary matches or
// if multiple primaries match (ambiguity is a configuration error;
// fail closed rather than pick arbitrarily).
func (r *PrimaryRegistry) LookupByBaseDomainSuffix(hostname string) *Primary
```

Suffix match means `strings.HasSuffix(hostname, "." + p.BaseDomain)` — *proper* suffix, so `containarium.dev` does NOT match the BaseDomain literally (only `something.containarium.dev`). This keeps `containarium.dev` itself usable as a primary `Hostname` for the apex.

### SNI router precedence

`buildSNIRoutingHandler` ([manager.go:582](../internal/sentinel/manager.go)) becomes:

1. Exact hostname match (`LookupByHostname`) — current behavior, unchanged.
2. **New**: BaseDomain suffix match (`LookupByBaseDomainSuffix`).
3. Fallback to `fallbackTarget` — current behavior, unchanged.

The fallback stays as a safety net for unpooled single-backend deployments (no `BaseDomain` configured → step 2 always returns nil → behavior identical to today).

### Handshake change for tunneled primaries

`TunnelHandshake` ([tunnel_auth.go](../internal/sentinel/tunnel_auth.go)) gains `PublicBaseDomain string`. The tunnel command picks it up from a new `--public-base-domain` flag in `internal/cmd/tunnel.go`. On `OnTunnelConnect` the value flows through to the `primaries.Register(...)` call (`manager.go:823-835`).

### Daemon-side change

`internal/cmd/daemon.go` already has `--base-domain` for the backend's own Caddy. Reuse it: if `--public-base-domain` isn't set explicitly, default to `--base-domain`. This means most operators set one flag, and the sentinel learns it automatically via the existing primary registration.

## Worked example

| Backend | `--pool` | `--public-hostname` | `--base-domain` (== `--public-base-domain` default) |
|---|---|---|---|
| prod | `prod` | `containarium-prod.kafeido.app` | `kafeido.app` |
| demo | `demo` | `demo.containarium.dev` | `containarium.dev` |
| lab | `lab` | `containarium-lab.kafeido.app` | `lab.kafeido.app` |

Inbound SNI behavior on the prod sentinel:

| SNI | Match path | Forwards to |
|---|---|---|
| `containarium-prod.kafeido.app` | exact (Hostname) | prod backend |
| `api.kafeido.app` | exact (Aliases, if listed) | prod backend |
| `blog.containarium.dev` | suffix (`.containarium.dev`) | demo backend |
| `notebook.lab.kafeido.app` | suffix (`.lab.kafeido.app`) | lab backend — **NOT** prod (more-specific suffix wins) |
| `kafeido.app` (apex) | none → fallback | legacy backend |

The third row is the new capability; it removes the need to register `blog.containarium.dev` as an alias.

## Edge cases & failure modes

- **Overlapping base domains.** Two primaries register with `BaseDomain=kafeido.app` and `BaseDomain=lab.kafeido.app`. `notebook.lab.kafeido.app` matches both. **Resolution**: longest-suffix wins (the more-specific one). Implement by sorting candidates by `len(BaseDomain)` desc and returning the first match. Document that ambiguity ladder explicitly.
- **Identical base domains across pools.** Two primaries register with `BaseDomain=kafeido.app` — a misconfiguration. **Resolution**: `LookupByBaseDomainSuffix` returns nil and logs a warning rather than picking arbitrarily. Fail closed.
- **Suffix collides with an exact alias on a different primary.** E.g. prod's `Aliases=[blog.containarium.dev]` plus demo's `BaseDomain=containarium.dev`. **Resolution**: exact match wins (precedence step 1 runs before step 2). Operator's explicit choice overrides the implicit suffix routing.
- **Tunneled primary disconnects.** Same as today — `UnregisterByBackendID` removes the entry, suffix lookups stop matching, suffix-matched SNI falls through to the legacy fallback. No new failure mode.
- **PROXY-v2 framing.** Suffix-matched destinations go through the same dial-or-yamux path as exact matches, so the existing `m.config.ProxyProtocol` handling still applies. No new code needed.

## Operational additions

These are required regardless of the code design — listed here so the work isn't a surprise during rollout:

1. **DNS.** `*.containarium.dev` A record → prod sentinel IP. Cloudflare-managed (separate provider from `kafeido.app`).
2. **ACME for the second domain.** Each backend's Caddy ACMEs its own subdomains, so `--base-domain=containarium.dev` triggers DNS-01 against the containarium.dev provider. That means the **demo backend's daemon** needs DNS-01 creds for the containarium.dev provider in its environment, not the sentinel. Existing kafeido.app DNS-01 setup on the prod backend is untouched.
3. **GLB cert SAN.** If the GLB does TLS termination (which prod does not — it's TCP passthrough — but confirm), add `*.containarium.dev` to the managed cert. For passthrough mode, no change.

## What this does NOT change

- ACME on the sentinel itself (sentinel doesn't terminate TLS for app traffic; passthrough only).
- Caddy on any backend (each backend continues to own its own `--base-domain`; this design just makes the sentinel aware of that value).
- The `--public-aliases` flag (still works for explicit per-domain routing; suffix match is additive).
- Pool-aware container placement ([added in feat(api): --pool selector](../proto/containarium/v1/container.proto)) — that's the input side; this is the output side.

## Test plan

- Unit: `LookupByBaseDomainSuffix` returns nil for empty hostname, exact match, no-suffix, ambiguous (two equal-length matches), and picks longest suffix when nested base domains exist.
- Unit: `buildSNIRoutingHandler` precedence — exact > suffix > fallback. Use the existing `httptest`/loopback patterns in `internal/sentinel/`.
- Integration (real Caddy): two primaries registered with different `BaseDomain`, SNI for each routes to the correct one. The Real Caddy wire-compat e2e job in CI is the right home.
- Manual: prod sentinel + a second backend with `--public-base-domain=containarium.dev`, `curl --resolve` a fake subdomain → confirm the right backend's logs see the request.

## Rollout

1. Land the proto + registry + SNI matcher changes behind the (default-empty) `--public-base-domain` flag. Zero behavior change for any existing deployment.
2. Demo backend joins the prod sentinel with `--pool=demo --public-base-domain=containarium.dev`.
3. DNS for `*.containarium.dev` cuts over.
4. Verify with `curl --resolve` (no DNS dependency for the test).
5. Demo container migration follows ([plan in Phase 4](MULTI-POOL.md#operator-workflow-adding-a-new-pool)).

## Alternatives considered

- **Push container hostnames to sentinel on every `expose_port`.** Workable but couples the route store to a remote API call on every mutation. Adds latency to route creation and a new failure mode (sentinel unreachable → can't expose a port). Suffix match keeps the contract one-way (daemon → sentinel at registration time, never per-route).
- **Wildcard aliases (`*.containarium.dev` as an alias entry).** Same effect but harder to reason about: aliases are also matched against `Hostname` for non-wildcards, and mixing wildcards into a list invites accidental over-matching. A separate `BaseDomain` field makes the intent explicit.
- **Caddy on the sentinel.** Would centralize routing but adds TLS termination on the sentinel (vs. today's passthrough), which breaks per-backend ACME, complicates client IP recovery, and adds another component to keep alive. Not worth it for this use case.
