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
- [ ] **1.2** Add `jti` and a revocation list — `internal/auth/token.go` (**A-MED-1**)
- [x] **1.3** Require min 32-byte JWT secret in `NewTokenManager` — `internal/auth/token.go:24-45` (**A-MED-2**)
      — `NewTokenManager` now returns `(*TokenManager, error)` and refuses
        secrets shorter than 32 bytes. Fail-closed at daemon startup.
- [~] **1.4** Per-RPC role enforcement (RBAC interceptor) — `internal/auth/`, all handlers (**A-MED-4**)
      — **Cluster-level ops done.** New `auth.RequireRole(ctx, role)`
        helper applied to GetSystemInfo, MoveContainer,
        AdoptMigratedContainer, and the `/v1/backends` HTTP
        handler — all admin-only. Tests in
        `internal/auth/require_role_test.go` and
        `internal/server/admin_only_handlers_test.go`.
      — Full per-RPC RBAC (every privileged handler explicitly
        gated) is the remaining work. The pattern is now in place;
        applying it to AddSSHKey/RemoveSSHKey, DeleteContainer,
        and similar is a mechanical follow-up.
- [~] **1.5** Drop query-string token support; Authorization header only — `internal/gateway/gateway.go:392,512`, `audit_handler.go:19` (**A-MED-3**)
      — **Audit endpoint done** — `/v1/audit/logs` now requires
        `Authorization: Bearer ...` and explicitly rejects `?token=`.
        Tests in `internal/gateway/audit_handler_test.go`.
      — Terminal + events/subscribe (WebSocket endpoints) still
        accept query-string tokens — those need the WebSocket
        Sec-WebSocket-Protocol subprotocol auth or a short-lived
        ticket exchange. Tracked as a follow-up.
- [ ] **1.6** Short-lived access tokens + refresh tokens — `internal/auth/token.go:14` (**C-MED-8**)
- [ ] **1.7** Per-tool scopes for MCP — `internal/mcp/tools.go`, `internal/mcp/client.go`
- [x] **1.8** Refuse JWT token files with mode > 0600 — `internal/mcp/client.go:57-78` (**C-HIGH-7**)
      — `readToken` `os.Stat`s the file and refuses if any non-owner
        read/write bit is set. Error message tells the operator the
        actual mode so they can `chmod 0600` without guessing.
- [ ] **1.9** Lock down `/wake/` and `/` (Caddy-only assumption) — `internal/gateway/gateway.go:480-491,641-643` (**A-MED-5**)
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
- [ ] **2.6** PROXY v2 trust list required at startup — `internal/server/dual_server.go` (**C-MED-1**)
- [ ] **2.7** Pin Caddy to TLS 1.3, restrict ciphers — `internal/hosting/caddy.go` (**C-MED-2**)
- [ ] **2.8** App-layer rate limit on auth endpoints — `internal/auth/`, gateway (**C-MED-3**)

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
- [ ] **4.4** Audit-log redaction policy + enforcement — `internal/audit/store.go:53-74` (**C-MED-5**)
- [ ] **4.5** Audit-log tamper-evidence (hash chain or append-only sink) — `internal/audit/store.go`
- [ ] **4.6** Request-correlation IDs propagated end-to-end — `internal/audit/middleware.go:63-128`, `internal/server/peer.go`
- [ ] **4.7** Postgres credentials via secret manager / unix-socket auth — `internal/server/dual_server.go` (**C-MED-6**)
- [ ] **4.8** Stat-check TLS key directory at startup — `internal/hosting/caddy.go` (**C-MED-7**)

---

## Phase 5 — Lower priority / process

- [ ] **5.1** Gate `/swagger-ui/` behind admin role — `internal/gateway/gateway.go:535-540` (**A-LOW-1**)
- [ ] **5.2** Add `gosec`, `govulncheck`, `trivy` to CI
- [ ] **5.3** Publish `SECURITY.md` with vulnerability-disclosure policy
- [ ] **5.4** Abuse-case test suite: oversized payloads, replayed tokens, wrong-tenant access — all must fail closed

---

## How to update this file

When you start a task: change `[ ]` → `[~]` and note the PR/branch in the line.
When you finish: change `[~]` → `[x]` and add the merged-PR link.
When you decide not to fix: change `[ ]` → `[-]` and document the rationale.
