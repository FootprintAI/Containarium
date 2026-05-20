# Zero-Trust Remediation TODO

Tracks remediation of findings from [ZERO-TRUST-AUDIT.md](./ZERO-TRUST-AUDIT.md).

**Legend:** `[ ]` pending · `[~]` in progress · `[x]` done · `[-]` won't fix (with rationale)

---

## Phase 0 — Stop-the-bleed (Critical, week 1)

These are exploitable today by anyone with a valid token, or by anyone
on the internal network. Land them first.

- [x] **0.1** Subject validation in secrets API
      — `internal/server/secrets_server.go:26-49,56-74,78-96,102-118,124-142`
      — Reject when `claims.Subject != req.Username` (admin role excepted).
      — Tracks finding **A-CRIT-1**.
      — Implemented via new `auth.AuthorizeTenant` helper in `internal/auth/authz.go`
        (with subject/role propagation through `annotateContext` in gateway).
        Tests in `internal/auth/authz_test.go`.
- [x] **0.2** Subject validation in container API
      — `internal/server/container_server.go:114-120` and siblings.
      — Same pattern as 0.1, applied to every handler accepting `username`.
      — Tracks finding **A-CRIT-2**.
      — Applied to: CreateContainer, ListContainers (rewrite-empty-to-subject for
        non-admin), GetContainer, DeleteContainer, StartContainer, StopContainer,
        ResizeContainer, CleanupDisk, InstallStack, AdoptMigratedContainer,
        ToggleMonitoring, ToggleAutoSleep, AddSSHKey, RemoveSSHKey, GetMetrics
        (same rewrite pattern), AddCollaborator/RemoveCollaborator/ListCollaborators
        (via OwnerUsername), MoveContainer, DebugContainer; AppService
        (DeployApp, ListApps, GetApp, StopApp, StartApp, RestartApp, DeleteApp,
        GetAppLogs); NetworkService (GetRoutes, GetContainerACL, UpdateContainerACL).
      — `auth.ContextWithSystemIdentity` added for internal/system callers
        (autosleep). Regression tests in `internal/server/tenant_isolation_test.go`.
- [x] **0.3** Pin JWT algorithm to HS256
      — `internal/auth/token.go:74-79`. Explicit `Alg() != "HS256"` reject.
      — Sanitize error returned to client (no algorithm name leak — fixes **A-MED-7**).
      — Tracks finding **A-CRIT-3** (and A-MED-7).
      — Validator pinned to `jwt.SigningMethodHS256.Alg()`; HS384/HS512/RS256/none
        all rejected by tests in `internal/auth/alg_pinning_test.go`. HTTP
        middleware now returns generic `"invalid token"` to clients.
- [x] **0.4** Authenticate `/authorized-keys` and `/certs` endpoints
      — `internal/gateway/gateway.go:627, 630-631`.
      — Sentinel-signed request OR loopback-bind + firewall.
      — Tracks findings **A-CRIT-4**, **A-HIGH-2**.
      — HMAC-SHA256 over `method\npath\ntimestamp` with shared secret
        `CONTAINARIUM_SENTINEL_AUTH_SECRET` (≥32 bytes). Fail-closed:
        unconfigured secret returns 401 for every request, no silent
        passthrough. Replay protection via ±5min timestamp window.
        Helper in `internal/auth/sentinel_hmac.go`, middleware applied
        in `gateway.go`, sentinel-side signing in
        `internal/sentinel/sentinel_auth.go`. Forward-compatible with
        Phase 0.5 peer mTLS (the HMAC layer can stay or be removed once
        mTLS is in place). Tests cover sign+verify roundtrip, tamper
        cases, replay window, and fail-closed middleware behavior.
- [x] **0.5** TLS + mTLS for peer-to-peer
      — `internal/server/peer.go:69-72, 295, 305`.
      — Sentinel-issued peer certs with short TTL, pinned CA.
      — Tracks finding **C-CRIT-1**.
      — Design: single operator-managed RSA key on the sentinel,
        self-signed CA generated at runtime from that key, 7-day
        leaf TTL.
        New `pkg/core/pki` provisioner; sentinel loads CA from
        `CONTAINARIUM_CA_KEY_FILE`, exposes HMAC-gated
        `/sentinel/ca` + `/sentinel/peer-cert`, and runs an HTTPS
        binary-server listener alongside the existing HTTP one.
        Daemon bootstraps its leaf cert at PeerPool startup,
        background loop renews at 1/3 of TTL remaining. Plain HTTP
        remains the default during rollout; flipping a daemon to
        HTTPS is `CONTAINARIUM_SENTINEL_URL=https://…`.
        Full operator docs in a follow-up PR.
- [x] **0.6** Response signing for `/sentinel/peers` poll
      — `internal/server/peer.go:109-199`.
      — Tracks finding **C-CRIT-2**.
      — HMAC-SHA256 over `body\ntimestamp` using
        `CONTAINARIUM_SENTINEL_AUTH_SECRET` (the same secret as 0.4).
        Sentinel `PeersHandler` writes `X-Containarium-Sentinel-{Ts,Sig}`
        headers; daemon `discover()` verifies before updating the peer
        map. **Rollout-friendly fail mode:** with the secret unset the
        daemon logs a loud warning and accepts unsigned responses
        (audit-grade flagged); once 100% of fleets carry the secret,
        the rollout branch should be removed so the daemon is
        unconditionally fail-closed. New helpers
        `auth.SignSentinelResponse` / `auth.VerifySentinelResponse`;
        tests in `internal/auth/sentinel_hmac_test.go` and
        `internal/sentinel/peers_signed_test.go`. TLS confidentiality
        for the discovery channel itself rolls in with Phase 0.5.

---

## Phase 1 — Identity & authorization hardening (weeks 2-4)

- [x] **1.1** Validate JWT `iss` and `aud` claims — `internal/auth/token.go:73-91` (**A-HIGH-1**)
      — `ValidateToken` now passes `jwt.WithIssuer` + `jwt.WithAudience` parser options;
        `GenerateToken` stamps both. Default audience `containarium-api`
        (overridable via `CONTAINARIUM_JWT_AUDIENCE`).
- [x] **1.2** Add `jti` and a revocation list — `internal/auth/token.go` (**A-MED-1**)
      — Every issued token now carries a 128-bit base64url
        `jti` claim (`crypto/rand`-backed; collision-free in
        practice). `RevocationStore` interface + Postgres-
        backed `PgRevocationStore` keyed on jti with the
        original `exp` for cleanup. `ValidateToken` consults
        the store on every authenticated request — fail-open
        on store error (kill-switch, not primary gate);
        documented inline. `TokenManager.RevokeToken(claims)`
        is the admin-facing API for logout / compromise flows.
        Daemon launches a 1h cleanup goroutine in
        `runRevocationCleanup`; one pass on startup catches
        rows orphaned by a prior daemon lifetime. 13 new tests
        in `revocation_test.go`.
      — **Admin UX landed.** New `TokensService.RevokeToken`
        RPC + REST endpoint (`POST /v1/tokens/revoke`) +
        `containarium token revoke --jti <id>` CLI verb.
        Admin-only; idempotent; reason field for forensics;
        optional `expires_at` controls the cleanup horizon.
        Implementation in
        `proto/containarium/v1/tokens.proto`,
        `internal/server/tokens_server.go`, and
        `internal/cmd/token.go`. 10 server-side tests.
      — **MCP wrapper landed.** New `revoke_token` tool in
        `internal/mcp/tools.go`; thin wrapper over
        `Client.RevokeToken` which POSTs the same REST
        endpoint as the CLI. Requires admin role on the
        server and the new `tokens:write` scope, so an
        agent token without explicit grant can't kill
        other tokens. Server-side test confirms
        admin-without-scope is rejected.
- [x] **1.3** Require min 32-byte JWT secret in `NewTokenManager` — `internal/auth/token.go:24-45` (**A-MED-2**)
      — `NewTokenManager` now returns `(*TokenManager, error)` and refuses
        secrets shorter than 32 bytes. Fail-closed at daemon startup.
- [x] **1.4** Per-RPC role enforcement (RBAC interceptor) — `internal/auth/`, all handlers (**A-MED-4**)
      — **Cluster-level ops done.** New `auth.RequireRole(ctx, role)`
        helper applied to GetSystemInfo, MoveContainer,
        AdoptMigratedContainer, and the `/v1/backends` HTTP
        handler — all admin-only. Tests in
        `internal/auth/require_role_test.go` and
        `internal/server/admin_only_handlers_test.go`.
      — **Second wave landed.** Admin-only gates applied to
        the entire ZapServer (7 RPCs), AlertServer (8 RPCs),
        PentestServer (8 RPCs), NetworkServer route/topology
        mutations (8 RPCs), and SecurityServer cluster-wide
        reads (2 RPCs). 30 new tests in
        `internal/server/rbac_phase_1_4_test.go`. Read-only
        config endpoints (`GetZapConfig`, `GetPentestConfig`,
        `GetAlertingInfo`, `ListDefaultAlertRules`,
        `ListACLPresets`) intentionally remain
        any-authenticated — they expose feature toggles,
        no tenant data.
      — **Tenant-scoped follow-up landed.** New helper
        `auth.AuthorizeContainerAccess(ctx, containerName)`
        derives the owner from the `<username>-container`
        naming convention (`auth.OwnerFromContainerName`) and
        applies AuthorizeTenant-style semantics — admin
        bypass, tenant on own container only, system
        containers admin-only. Wired into TrafficServer's 4
        RPCs (`GetConnections`, `GetConnectionSummary`,
        `QueryTrafficHistory`, `GetTrafficAggregates`),
        TrafficServer's streaming `SubscribeTraffic` (blank
        name = admin-only), and `security_server`'s
        `ListClamavReports` + `TriggerClamavScan` (blank
        name = cluster-wide, admin-only; named =
        owner-scoped). Tests in
        `internal/auth/container_owner_test.go` and
        `internal/server/rbac_phase_1_4_tenant_test.go`.
- [x] **1.5** Drop query-string token support; Authorization header only — `internal/gateway/gateway.go:392,512`, `audit_handler.go:19` (**A-MED-3**)
      — **Audit endpoint done** — `/v1/audit/logs` now requires
        `Authorization: Bearer ...` and explicitly rejects `?token=`.
        Tests in `internal/gateway/audit_handler_test.go`.
      — **Terminal WebSocket done** — auth via
        `Sec-WebSocket-Protocol: containarium.bearer, <jwt>`.
        Helper `auth.ExtractBearerForUpgrade` checks subprotocol
        first, then Authorization, then legacy `?token=` (which
        emits a deprecation WARNING). `TerminalHandler.upgrader`
        advertises the subprotocol so gorilla acks it correctly.
        `proxyWebSocket` forwards the token via the same
        subprotocol form to the peer hop. webui terminal client
        updated (`TerminalDialog.tsx`).
      — **Events SSE done (server side)** — same extraction
        helper; `?token=` warned. The browser `EventSource` API
        can't attach headers, so the webui still uses `?token=`
        for SSE — follow-up to rewrite with `fetch` +
        `ReadableStream` is tracked under [1.6 / refresh tokens].
- [x] **1.6** Short-lived access tokens + refresh tokens — `internal/auth/token.go:14` (**C-MED-8**)
      — **Part A landed.** New `tt` claim (access | refresh)
        on JWTs. Generators `GenerateAccessToken`
        (15min default) + `GenerateRefreshToken` (30d
        default). `ValidateAccessToken` is now the HTTP
        middleware path — it REJECTS refresh tokens, so a
        stolen refresh token can't authenticate to any API
        surface (gateway, terminal, audit, SSE). Pre-1.6
        tokens (no tt claim) are still accepted as access
        for backwards compat. CLI gains `--token-type
        access|refresh|''` to choose at issuance time.
      — **Part B landed.** `TokensService.RefreshToken` RPC
        + `POST /v1/tokens/refresh` REST + `containarium
        token refresh` CLI verb. Mints a new (access,
        refresh) pair from a valid refresh token; revokes
        the prior refresh jti so refresh tokens are
        SINGLE-USE (rotation). Replay → Unauthenticated.
        The refresh endpoint is intentionally
        unauthenticated (the refresh token in the body IS
        the credential) — `unauthPaths` map in
        `middleware.go` carries the path allowlist.
      — `1.6` story now complete. Operators can mint a
        short-lived access + long-lived refresh, store
        refresh securely, and rotate via the endpoint.
        Stolen refresh tokens get one shot at exchange
        before the legitimate holder's next rotation
        revokes them — and they can't be used directly on
        the API surface at all.
- [x] **1.7** Per-tool scopes for MCP — `internal/mcp/tools.go`, `internal/mcp/client.go`
      — New `scopes` claim on JWTs (variadic
        `GenerateToken(..., scopes...)`) + OAuth2-style
        taxonomy in `internal/auth/scopes.go`
        (`containers:read|write`, `secrets:read|write`,
        `routes:read|write`, `security:read|write`,
        `code:write`, `ssh:write`, plus `*` wildcard).
        Backwards-compat: nil/missing scopes claim →
        unrestricted (existing tokens unaffected).
      — Every MCP tool now carries a `RequiredScope`
        (assigned in one auditable table in
        `tools.go:toolScopeAssignments`). The MCP server
        filters `tools/list` to the JWT's effective scope
        set and rejects `tools/call` for tools the token
        can't satisfy — fast local rejection before the
        request even hits the network. Daemon-side checks
        remain authoritative; this is defense in depth.
      — CLI: `containarium token generate --scopes
        containers:read,secrets:read` mints a
        least-privilege token (e.g. for handing to an LLM
        agent). Empty `--scopes` flag preserves pre-1.7
        unrestricted issuance.
      — Tests: `scopes_test.go` (HasScope semantics),
        `scope_filter_test.go` (MCP JWT decode + per-tool
        gating). `TestEveryToolHasScope` is a guard rail:
        adding a new MCP tool without a scope assignment
        fails CI.
      — **1.7b daemon-side enforcement landed.** New
        `auth.RequireScope(ctx, scope)` mirrors
        `RequireRole` semantics. JWT `scopes` claim now
        propagates through the HTTP middleware AND the
        gateway annotator (`MDKeyScopes` metadata key,
        comma-joined). Hot-path handlers gated:
        `ContainerServer.{Create,List,Get,Delete,Start,
        Stop,Resize,ToggleMonitoring,ToggleAutoSleep,
        AddSSHKey,RemoveSSHKey}` (containers:read|write
        + ssh:write), `SecretsServer.{Set,Get,List,Delete,
        Refresh}Secret` (secrets:read|write), and
        `NetworkServer.{Get,Add,Update,Delete}Route`
        (routes:read|write). Backwards-compat preserved:
        absent scopes claim → nil grants → unrestricted.
        Tests in `internal/auth/require_scope_test.go` +
        `internal/server/scope_gate_test.go`.
      — **1.7b pass 2 landed.** Same RequireScope pattern
        applied to ZapServer (7 RPCs, security:read|write),
        PentestServer (8 RPCs, security:read|write),
        SecurityServer ClamAV (4 RPCs, security:read|write),
        AlertServer (8 RPCs, alerts:read|write), and
        TrafficServer (5 RPCs, traffic:read). New scopes:
        alerts:read, alerts:write, traffic:read.
        15 new tests in `scope_gate_pass2_test.go`.
- [x] **1.8** Refuse JWT token files with mode > 0600 — `internal/mcp/client.go:57-78` (**C-HIGH-7**)
      — `readToken` `os.Stat`s the file and refuses if any non-owner
        read/write bit is set. Error message tells the operator the
        actual mode so they can `chmod 0600` without guessing.
- [x] **1.9** Lock down `/wake/` and `/` (Caddy-only assumption) — `internal/gateway/gateway.go:480-491,641-643` (**A-MED-5**)
      — `WakeProxy.ServeHTTP` now refuses requests whose
        `RemoteAddr` isn't loopback or in the
        `CONTAINARIUM_WAKE_TRUSTED_PROXIES` allowlist (CIDR or
        bare IP, comma-separated). 403 is returned before any
        route lookup or wake side-effect. Wildcard `/0` prefixes
        are explicitly refused — defeating the gate would be
        worse than turning it off. Empty allowlist preserves the
        pre-1.9 behavior with a startup WARNING — the rollout
        switch is operator-set, not flipped silently.
- [x] **1.10** Auth wrap on internal proxies (grafana/alertmanager/guacamole) — `internal/gateway/gateway.go:543-601` (**A-MED-6**)
      — Each proxy now requires a valid JWT before forwarding.
        Backend's own auth still applies on top (defense in depth).
        Wiring extracted into `mountInternalProxies` in
        `internal/gateway/internal_proxies.go`; tests in
        `internal_proxies_test.go` cover unauth rejection, valid-
        token forwarding, and the no-slash redirect staying open.

---

## Phase 2 — Transport security & network segmentation (weeks 4-6)

- [x] **2.1** Fail-closed mTLS on gRPC (refuse plaintext fallback) — `internal/mtls/loader.go:14-51` (**C-HIGH-2**)
      — New `auth.RequireMTLSUnaryInterceptor` /
        `RequireMTLSStreamInterceptor` inspect `peer.AuthInfo` on
        every call and reject anything that isn't a verified mTLS
        connection with a client cert. Wired in when
        `EnableMTLS=true`. The old JWT-passthrough interceptor
        that accepted plaintext is gone from the mTLS path. Tests
        in `internal/auth/mtls_interceptor_test.go`.
- [x] **2.2** MCP client requires HTTPS + CA pinning — `internal/mcp/client.go:46-48,82` (**C-HIGH-1**)
      — `NewClient` refuses an `http://` baseURL by default; the
        escape hatch is `CONTAINARIUM_MCP_ALLOW_INSECURE=true`
        for dev/test. CA pinning via
        `CONTAINARIUM_MCP_TRUSTED_CA_FILE` (PEM bundle, e.g. the
        sentinel-issued CA from Phase 0.5). Refusal happens at
        construction; every doRequest call returns the stashed
        error so the failure is visible upstream. Tests in
        `internal/mcp/client_tls_test.go`.
- [x] **2.3** Tighten SSH-port default in terraform — `terraform/modules/containarium/sentinel.tf:104-106` (**C-HIGH-3**)
      — New variable `allowed_management_sources` defaulting to
        RFC-1918 (10/8 + 172.16/12 + 192.168/16). Applied to
        operator-only ports: jump-server SSH :22, gRPC :50051,
        sentinel management SSH :2222. `allowed_ssh_sources`
        stays at 0.0.0.0/0 for user-facing services on the
        sentinel (sshpiper :22, HTTP :80, HTTPS :443) — those
        legitimately need to accept user traffic.
- [x] **2.4** Explicit firewall rule for REST gateway (sentinel-only) — `terraform/modules/containarium/main.tf:65-73` (**C-HIGH-4**)
      — Sentinel→spot rule split: user traffic (22/80/443) and
        the REST API (:8080) are now separate firewall resources
        with distinct descriptions. An operator can't widen API
        exposure by editing the user-traffic rule without seeing
        the implication.
- [~] **2.5** OTel collector: loopback bind + auth on OTLP — `internal/server/core_otel_collector.go` (**C-HIGH-5**)
      — **Bind address now configurable.** New env var
        `CONTAINARIUM_OTEL_COLLECTOR_BIND` (default `0.0.0.0` for
        backwards compatibility). Operators in paranoid setups
        can pin to a specific bridge IP. Applied to all three
        receivers (OTLP HTTP :4318, OTLP gRPC :4317, health-check
        :13133). Tests in `internal/server/otel_bind_test.go`.
      — **Bearer-token auth is a follow-up** — requires plumbing
        a shared token to every container's OTEL_EXPORTER_OTLP_HEADERS.
        Audit's full closure deserves its own PR.
- [x] **2.6** PROXY v2 trust list required at startup — `internal/server/dual_server.go` (**C-MED-1**)
      — New `validateProxyProtocolTrusted` rejects empty, wildcard
        (`0.0.0.0/0`, `::/0`), or malformed CIDR entries before
        the daemon binds anything. Mirrors the lazy check in
        `internal/app/l4_proxy.go` so failure is visible at boot
        rather than at first Caddy reconfigure. Tests in
        `internal/server/proxy_protocol_trusted_test.go`.
- [x] **2.7** Pin Caddy to TLS 1.3, restrict ciphers — `internal/hosting/caddy.go` (**C-MED-2**)
      — Caddyfile template now sets global `servers { protocols
        tls1.2 tls1.3 }` and per-site `ciphers` lists only AEAD
        suites (CHACHA20-POLY1305 + AES-GCM, no CBC). TLS 1.0/1.1
        rejected at the protocol level. `curves` restricted to
        modern ECC.
- [x] **2.8** App-layer rate limit on auth endpoints — `internal/auth/`, gateway (**C-MED-3**)
      — New `AuthFailureLimiter` (per-IP token bucket, 10 burst /
        6 per-minute refill, 30-minute idle eviction). Wired into
        the HTTP auth middleware on failed JWT validations only —
        successful requests don't consume tokens, so legitimate
        traffic stays unthrottled at any rate. Failed-burst
        attackers get 429 after the initial burst. Tests in
        `internal/auth/rate_limit_test.go`.

---

## Phase 3 — Input validation & resource boundary (weeks 6-8)

- [~] **3.1** Image-registry allowlist + digest pinning — `internal/server/container_server.go:160` (**B-HIGH-1**)
      — **Allowlist done.** New `CONTAINARIUM_ALLOWED_IMAGE_REGISTRIES`
        env var (comma-separated). CreateContainer rejects images
        whose registry prefix isn't in the allowlist. Empty allowlist
        = pre-Phase-3 behavior with startup WARNING. Tests in
        `internal/server/image_allowlist_test.go`.
      — Digest pinning is a follow-up — would require image-pull
        side checks for SHA-256 manifests.
- [x] **3.2** Split `enable_podman` from `enable_privileged`; gate latter on role — `internal/server/container_server.go:164`, `pkg/core/incus/client.go:458-459` (**A-HIGH-3**)
      — New `CONTAINARIUM_PRIVILEGED_PODMAN_POLICY` env var with
        three modes: `all` (default, backwards-compat), `admin-only`
        (require admin role to enable podman), `disabled` (refuse
        privileged regardless of role). Tests in
        `internal/server/privileged_policy_test.go`. Proto contract
        unchanged — server-side gate, not a wire-level split.
- [x] **3.3** Cap `ssh_keys` length — `proto/.../container.proto:210` (**B-MED-1**)
      — Server-side bounds in `internal/server/create_bounds.go`:
        max 32 keys, each ≤ 8 KiB. Enforced at the top of
        CreateContainer (after the tenant check, before any
        allocation-heavy work). Tests in
        `internal/server/create_bounds_test.go`.
- [x] **3.4** Cap `stack_parameters` and `labels` size — `proto/.../container.proto:4,13` (**B-MED-2**, **B-LOW-1**)
      — Same module as 3.3. `stack_parameters`: max 64 entries,
        keys ≤ 256 chars, values ≤ 4 KiB. `labels`: max 64 entries,
        keys/values ≤ 256 chars. Error messages name the offending
        field so callers can fix without guessing.
- [x] **3.5** Explicit newline-rejection in SSH key validation — `pkg/core/container/ssh_validate.go:35` (**B-MED-3**)
      — `ValidateSSHPublicKey` now does `ContainsAny(key, "\r\n")`
        before any other check. Previously rejection was incidental
        (the base64 decoder happened not to tolerate CR/LF); the
        explicit check makes the intent load-bearing. Tests cover
        LF / CR / CRLF injection vectors, plus that the newline
        check beats the placeholder check (more-dangerous vector
        wins).

---

## Phase 4 — Secrets, audit & operational hardening (ongoing)

- [ ] **4.1** Envelope encryption via external KMS (GCP KMS / Vault) — `pkg/core/secrets/crypto.go` (**C-HIGH-6** is partially addressed by 4.2 below)
- [x] **4.2** Stat-check master-key file permissions at load — `pkg/core/secrets/crypto.go:47,109` (**C-HIGH-6**)
      — `LoadOrCreateMasterKey` now stats the file before reading
        and refuses if any non-owner bit is set (`mode & 0o077 != 0`).
        Catches umask drift, ownership change, and backup-tool
        side effects. Error message names the actual mode so the
        operator can `chmod 0400` without guessing. Tests in
        `pkg/core/secrets/master_key_perms_test.go`.
- [ ] **4.3** Document container env-var introspection risk; explore tmpfs-mount alternative — `internal/server/secrets_server.go:133-155` (**C-MED-4**)
- [x] **4.4** Audit-log redaction policy + enforcement — `internal/audit/store.go:53-74` (**C-MED-5**)
      — New `audit.Redact` / `audit.SanitizeDetail` scrubs JWTs
        (with or without Bearer prefix), password/api_key/secret
        env vars, AWS access key IDs, and PEM private-key blocks.
        8 KiB length cap on detail; truncation marker preserved.
        HTTP audit middleware runs SanitizeDetail on every entry.
        Tests in `internal/audit/redact_test.go`.
- [x] **4.5** Audit-log tamper-evidence (hash chain or append-only sink) — `internal/audit/store.go`
      — Each row carries `row_hash` (SHA-256 over its fields plus
        the previous row's hash) and `prev_hash` (previous row's
        row_hash). A single edit anywhere in `audit_logs` is
        detectable by re-walking the chain — both the edited row's
        row_hash and every subsequent row's prev_hash break. Insert
        path is inside a transaction with `SELECT … FOR UPDATE` on
        the tail row so concurrent appenders serialize. New
        `Store.VerifyChainSinceID(ctx, fromID, limit)` walks the
        chain forward and returns the first tampered row's ID
        (0 = intact). Schema migration via `ADD COLUMN IF NOT
        EXISTS`. Tests in `internal/audit/hash_chain_test.go`.
      — Detects modification + insertion. Deletion of a contiguous
        suffix isn't detected by the chain alone — that needs an
        append-only external sink (e.g. periodic push of the tail
        hash to GCS object versioning). Tracked as a follow-up.
- [x] **4.6** Request-correlation IDs propagated end-to-end — `internal/audit/middleware.go:63-128`, `internal/server/peer.go`
      — `X-Request-ID` honored from inbound (if shape-valid) or
        minted as 128-bit hex. Echoed in response, attached to
        `r.Context()` via `audit.ContextWithRequestID`, recorded
        in audit detail as `request_id=<id>`. Tests in
        `internal/audit/request_id_test.go`.
- [ ] **4.7** Postgres credentials via secret manager / unix-socket auth — `internal/server/dual_server.go` (**C-MED-6**)
- [x] **4.8** Stat-check TLS key directory at startup — `internal/hosting/caddy.go` (**C-MED-7**)
      — `/var/lib/caddy` created at 0750 (was 0755); existing
        directory chmod-tightened to 0750 idempotently. New
        `CheckStorageDirPerms` runs at `EnableAndStartCaddy` and
        refuses world-readable bits — TLS private keys live
        under here. Tests in `internal/hosting/storage_perms_test.go`.

---

## Phase 5 — Lower priority / process

- [x] **5.1** Gate `/swagger-ui/` behind admin role — `internal/gateway/gateway.go:535-540` (**A-LOW-1**)
      — Both `/swagger-ui/` and `/swagger.json` now run
        through `HTTPMiddleware` (auth gate) +
        `requireAdminFromContext` (role gate). Non-admin
        callers see 403; unauthenticated callers see 401
        from the prior middleware step. Tests in
        `internal/gateway/swagger_gate_test.go`.
- [x] **5.2** Add `gosec`, `govulncheck`, `trivy` to CI
      — Already in place; workflow lives at
        `.github/workflows/security.yml`. All three run on
        push to `main`, on every PR, and weekly. SARIF
        results upload to GitHub code scanning. govulncheck
        fails the build when a known-fixed vuln is
        detected.
- [x] **5.3** Publish `SECURITY.md` with vulnerability-disclosure policy
      — Added at repo root. Covers: how to report
        (private GitHub advisory + email fallback),
        acknowledgement SLA (3 business days), substantive
        response SLA (10 business days), 90-day coordinated
        disclosure window, supported versions, out-of-scope
        cases, automated scanning summary, and an audit-
        history pointer back to this doc.
- [ ] **5.4** Abuse-case test suite: oversized payloads, replayed tokens, wrong-tenant access — all must fail closed

---

## How to update this file

When you start a task: change `[ ]` → `[~]` and note the PR/branch in the line.
When you finish: change `[~]` → `[x]` and add the merged-PR link.
When you decide not to fix: change `[ ]` → `[-]` and document the rationale.
