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

- [ ] **1.1** Validate JWT `iss` and `aud` claims — `internal/auth/token.go:73-91` (**A-HIGH-1**)
- [ ] **1.2** Add `jti` and a revocation list — `internal/auth/token.go` (**A-MED-1**)
- [ ] **1.3** Require min 32-byte JWT secret in `NewTokenManager` — `internal/auth/token.go:24-45` (**A-MED-2**)
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
- [ ] **1.5** Drop query-string token support; Authorization header only — `internal/gateway/gateway.go:392,512`, `audit_handler.go:19` (**A-MED-3**)
- [ ] **1.6** Short-lived access tokens + refresh tokens — `internal/auth/token.go:14` (**C-MED-8**)
- [ ] **1.7** Per-tool scopes for MCP — `internal/mcp/tools.go`, `internal/mcp/client.go`
- [ ] **1.8** Refuse JWT token files with mode > 0600 — `internal/mcp/client.go:57-78` (**C-HIGH-7**)
- [ ] **1.9** Lock down `/wake/` and `/` (Caddy-only assumption) — `internal/gateway/gateway.go:480-491,641-643` (**A-MED-5**)
- [ ] **1.10** Auth wrap on internal proxies (grafana/alertmanager/guacamole) — `internal/gateway/gateway.go:543-601` (**A-MED-6**)

---

## Phase 2 — Transport security & network segmentation (weeks 4-6)

- [ ] **2.1** Fail-closed mTLS on gRPC (refuse plaintext fallback) — `internal/mtls/loader.go:14-51` (**C-HIGH-2**)
- [ ] **2.2** MCP client requires HTTPS + CA pinning — `internal/mcp/client.go:46-48,82` (**C-HIGH-1**)
- [ ] **2.3** Tighten SSH-port default in terraform — `terraform/modules/containarium/sentinel.tf:104-106` (**C-HIGH-3**)
- [ ] **2.4** Explicit firewall rule for REST gateway (sentinel-only) — `terraform/modules/containarium/main.tf:65-73` (**C-HIGH-4**)
- [ ] **2.5** OTel collector: loopback bind + auth on OTLP — `internal/server/core_otel_collector.go` (**C-HIGH-5**)
- [ ] **2.6** PROXY v2 trust list required at startup — `internal/server/dual_server.go` (**C-MED-1**)
- [ ] **2.7** Pin Caddy to TLS 1.3, restrict ciphers — `internal/hosting/caddy.go` (**C-MED-2**)
- [ ] **2.8** App-layer rate limit on auth endpoints — `internal/auth/`, gateway (**C-MED-3**)

---

## Phase 3 — Input validation & resource boundary (weeks 6-8)

- [ ] **3.1** Image-registry allowlist + digest pinning — `internal/server/container_server.go:160` (**B-HIGH-1**)
- [ ] **3.2** Split `enable_podman` from `enable_privileged`; gate latter on role — `internal/server/container_server.go:164`, `pkg/core/incus/client.go:458-459` (**A-HIGH-3**)
- [ ] **3.3** Cap `ssh_keys` length — `proto/.../container.proto:210` (**B-MED-1**)
- [ ] **3.4** Cap `stack_parameters` and `labels` size — `proto/.../container.proto:4,13` (**B-MED-2**, **B-LOW-1**)
- [ ] **3.5** Explicit newline-rejection in SSH key validation — `pkg/core/container/ssh_validate.go:35` (**B-MED-3**)

---

## Phase 4 — Secrets, audit & operational hardening (ongoing)

- [ ] **4.1** Envelope encryption via external KMS (GCP KMS / Vault) — `pkg/core/secrets/crypto.go` (**C-HIGH-6** is partially addressed by 4.2 below)
- [ ] **4.2** Stat-check master-key file permissions at load — `pkg/core/secrets/crypto.go:47,109` (**C-HIGH-6**)
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
