# BYOC public HTTP ingress (design)

Status: draft / unapproved. Target: make a tenant box that runs on a
tunnel-joined BYOC host reachable on a public `*.example.com` subdomain
through the cloud edge — the same way a region-backend box already is.

## Problem

A box deployed onto a BYOC host (a tunnel-joined machine, reached via the
sentinel peer-proxy) runs fine and is fully reachable on its own host's LAN,
but its **public subdomain does not work**:

- The cloud mints `<box>-<org>.example.com` and `GetWorkspaceAccess` hands it
  back. DNS (wildcard) resolves it to the **sentinel/edge**.
- The edge has **no path to a box living on the BYOC host** (the host is behind
  NAT, connected only by its outbound tunnel). The edge returns an empty `200`.
- Only the **control path** is wired today: `/peer/<backend-id>/…` on the
  sentinel forwards the *daemon API* to the host. There is no **data path** for
  public app traffic (the box's HTTP port) to the box.

A region-backend box works because the edge *is* its backend; a BYOC box is one
tunnel hop away and nothing carries public HTTP across it.

## What already exists (the building blocks)

The tunnel data-path is **already capable** — this design is mostly routing
metadata, not new transport.

- **Tunnel multiplexes arbitrary ports.** The BYOC host dials the sentinel
  outbound (yamux over `:443`); the sentinel can open a stream to any forwarded
  port on the host. (`internal/sentinel/tunnel_client.go`,
  `internal/sentinel/tunnel_server.go`.)
- **The sentinel SNI router already forwards public HTTPS into a tunnel** — for
  hosts *promoted to primary*: it peeks the TLS SNI and, when the backend is a
  tunnel, does `tunnelRegistry.DialTunnel(spotID, port)`
  (`internal/sentinel/manager.go`, ~L865). This is the exact primitive BYOC
  ingress needs; today it just isn't reachable for a non-primary BYOC box.
- **The BYOC host's daemon already runs Caddy and already gets the box route.**
  The cloud's subdomain-route reconciler resolves the per-host (BYOC) driver and
  calls `AddRoute` through the peer-proxy; the host's `RouteSyncJob` writes it
  into the host's Caddy, with TLS. (`internal/app/route_sync.go`,
  `internal/app/proxy.go`; cloud
  `internal/sweeper/subdomain_route_reconciler.go`.) So the host's Caddy can
  terminate TLS and reverse-proxy the subdomain to the box **once traffic
  arrives**.

## The missing links

1. **The sentinel doesn't know `subdomain → BYOC host`.** Its SNI router
   resolves a hostname to a *region primary* or a *promoted primary*. A BYOC
   box's subdomain matches neither, so it falls through to the default (empty
   `200`).
2. **The tunnel must forward the host's HTTPS port** (the host Caddy's `:443`)
   so the sentinel can `DialTunnel(spotID, 443)`.
3. **TLS / cert ownership.** Either the BYOC host's Caddy terminates TLS for the
   subdomain (needs a cert for `*.example.com` on the host), or the sentinel
   terminates and forwards plaintext (needs an HTTP layer on the sentinel, which
   it doesn't have today).
4. **The cloud-minted subdomain must match the route on the host.** The host's
   daemon currently also mints its *own* `<box>-workspace.example.com` route;
   the cloud mints `<box>-<org>.example.com`. The route the reconciler pushes
   must be the cloud-minted name (verify the reconciler targets the BYOC driver
   for workspace subdomains).

## Chosen approach: SNI pass-through to the host's Caddy

Reuse the promoted-primary path. The sentinel peeks SNI; if the hostname maps to
a BYOC host, it `DialTunnel(spotID, 443)` and **passes the raw TLS bytes
through** to the host's Caddy, which terminates TLS and reverse-proxies to the
box. No TLS work on the sentinel, no new HTTP layer — identical to how a
tunnel-promoted primary is already served.

```
client ──TLS──> sentinel:443
                  │ peek SNI = <box>-<org>.example.com
                  │ lookup → BYOC host spotID  (NEW: authoritative map)
                  ▼
            DialTunnel(spotID, 443)  ──yamux──> BYOC host Caddy:443
                                                   terminates TLS (cert for the name)
                                                   reverse_proxy → box:<port> (wsauth → app)
```

### The authoritative `subdomain → host` map (link 1)

The **cloud is the authority** (it knows box → host placement); the host must
**not** self-announce subdomains (a compromised/abusive host could otherwise
hijack another tenant's hostname). So:

- The cloud pushes BYOC subdomain bindings (`hostname → backend-id`) to the
  sentinel as they're created/torn down — a small, defined API (proto-first,
  per the API convention), not a hand-rolled handler. The sentinel keeps an
  in-memory `byocRoute[hostname] = spotID` consulted by the SNI router before
  the default fallback.
- Idempotent + reconciled (same shape as the existing route reconciler), so a
  sentinel restart re-syncs.

### Tunnel forwards `:443` (link 2) — already satisfied

`pool join` defaults to `--ports 22,8080,443` (`internal/cmd/pool_join.go`), so
the host Caddy's HTTPS port is **already** carried by the tunnel —
`DialTunnel(spotID, 443)` will connect with no host-side change. (`8080` is also
forwarded, which enables the plaintext-forward cert variant in Phase 2.)

### Cert strategy (link 3) — phased

- **Phase 1 (operator-owned host, validate the path):** give the BYOC host's
  Caddy DNS-01 capability for the wildcard (the same mechanism the edge uses),
  so it serves a trusted cert for `<box>-<org>.example.com`. Acceptable when the
  host is operator-owned (e.g. the lab GPU host). **Not** acceptable for a true
  third-party BYOC host — handing it the DNS provider token is a credential leak.
- **Phase 2 (third-party BYOC):** the cloud mints the cert centrally and syncs
  it to the host (a cert-push over the control channel), or the sentinel
  terminates TLS with the wildcard it already holds and forwards **plaintext**
  to the box port over the tunnel (`DialTunnel(spotID, <box-port>)`, Host header
  preserved). The plaintext-forward variant removes all cert handling from the
  host but requires the sentinel to grow an HTTP reverse-proxy for tenant
  subdomains — a larger sentinel change, deferred.

### Cloud expose for BYOC (link 4)

Confirm the subdomain-route reconciler, for a workspace/box on a BYOC host,
pushes the **cloud-minted** hostname (`<box>-<org>.example.com`) to the host's
daemon via the per-host driver (so the host Caddy terminates the right name).
The reconciler already resolves the BYOC driver for control ops; this is mostly
ensuring the workspace subdomain flows through the same path.

## Security

- **No host self-announce.** Only cloud-pushed mappings are honored; the
  sentinel never trusts a host's claim to serve a hostname (anti-hijack).
- **Egress + cert.** In Phase 1 the operator host holds a DNS token — operator
  hosts only. Phase 2 removes that for third-party hosts.
- **Isolation unchanged.** The box's own in-box auth proxy (basic-auth +
  cookie) still gates access; ingress only carries traffic to it.

## Phases

1. **Path-only validation (operator host).** Phase-1 cert on the BYOC host +
   manually register one `subdomain → spotID` mapping on the sentinel + ensure
   the tunnel forwards `:443`. Confirm the workspace subdomain serves end to end
   to a box on the lab host. Proves the SNI pass-through + tunnel:443 + host
   Caddy chain with zero new control APIs.
2. **Authoritative map sync.** Define the cloud→sentinel binding-push API
   (proto-first) + the sentinel `byocRoute` registry + SNI-router lookup. Wire
   the cloud subdomain manager to push/retract on bind/unbind.
3. **Cloud expose alignment.** Ensure BYOC workspace subdomains push the
   cloud-minted name through the per-host driver; reconcile on a loop.
4. **Third-party cert story (Phase 2 cert).** Central cert mint + sync, or
   sentinel TLS-terminate + plaintext forward. Decision gated on whether
   third-party BYOC ingress is in scope.

## Validation target

A throwaway box on the lab BYOC host, deployed from the console, reachable at
its `<box>-<org>.example.com` URL from a browser (the workspace iframe embeds),
with TLS valid and the in-box auth gate intact. Tear down after.

## Open questions

- ~~Default `pool join` forwarded-port set — does it already include `:443`?~~
  **Resolved: yes** (`22,8080,443`).
- Phase-1 vs Phase-2 cert: is third-party BYOC public ingress actually in scope,
  or is operator-owned BYOC (lab/GPU hosts) enough for now? That decides whether
  we need the central-cert/plaintext-forward work at all.
- Wildcard scope: one `*.example.com` cert on each BYOC host vs per-name certs.
