# Containarium Zero-Trust Security Audit

**Audit date:** 2026-05-20
**Scope:** Whole-codebase audit against zero-trust principles
(no implicit trust, per-resource authorization, short-lived attributable
credentials, defense in depth, fail-closed defaults).
**Outcome:** 36 findings (5 Critical, 12 High, 17 Medium, 2 Low).

This document captures the **findings**. The remediation work is
tracked separately in [ZERO-TRUST-TODO.md](./ZERO-TRUST-TODO.md).

---

## Executive summary

Containarium today is built on a **perimeter trust model**: a valid JWT
grants effectively unlimited access, and components on the "internal"
side of the sentinel are assumed safe by virtue of network position.
That assumption fails the moment any single component is compromised,
which is the exact scenario zero-trust is designed to survive.

The four unifying zero-trust violations are:

1. **Implicit network trust.** Peer-to-peer RPC, sentinel→daemon poll,
   and several "VPC-only" endpoints all run on plaintext HTTP with no
   per-call authentication. Compromise of any one host or MITM on the
   internal network compromises the whole platform.
2. **No per-resource authorization.** Every API handler that takes a
   `username` reads it from the request body and never compares it to
   the authenticated JWT subject. Any token holder can act as any
   tenant.
3. **Long-lived static credentials.** 30-day JWTs, a single static
   master key encrypting every tenant's secrets, and no rotation path
   for either.
4. **Validation gaps at the resource boundary.** Container image URLs
   accepted unvalidated (SSRF + supply-chain risk), Podman flag
   silently grants host-root via privileged LXC, several proto fields
   unbounded.

---

## Methodology

Three parallel audits, each focused on one attack surface:

- **AuthN / AuthZ** — JWT validation, subject confusion, role
  enforcement, MCP scope, peer trust.
- **Input validation / injection** — command injection, path
  traversal, SSRF, container escape paths, SSH key injection, proto
  field bounds.
- **Transport / network / secrets** — TLS verification, mTLS
  enforcement, firewall rules, master-key handling, audit-log
  integrity, secret material in logs.

Every finding below cites `file:line` so it can be re-verified. Areas
that came back clean are listed at the end of each section — that's
useful signal too.

---

## Findings

### A. Authentication & authorization

#### A-CRIT-1 — IDOR in secrets API
**Severity:** Critical
**Location:** `internal/server/secrets_server.go:26-49, 56-74, 78-96, 102-118, 124-142`
**Description:** `SetSecret`, `GetSecret`, `ListSecrets`, `DeleteSecret`, and
`RefreshSecrets` all accept `req.Username` from the request body and
use it directly. There is no comparison against the JWT subject in
`ctx`. Any token holder can read, modify, or delete any other
tenant's secrets.
**Zero-trust principle violated:** Per-resource authorization.

#### A-CRIT-2 — IDOR in container API
**Severity:** Critical
**Location:** `internal/server/container_server.go:114-120` and every
sibling handler that accepts a `username` field.
**Description:** Same pattern as A-CRIT-1 — request-body `username`
treated as authoritative resource owner. Token for tenant A can
create/start/stop/delete containers owned by tenant B.
**Zero-trust principle violated:** Per-resource authorization.

#### A-CRIT-3 — JWT algorithm not pinned to HS256
**Severity:** Critical
**Location:** `internal/auth/token.go:74-79`
**Description:** Validation accepts any HMAC variant
(`SigningMethodHMAC` interface check). Combined with future library
bugs or key-confusion attacks, this widens the attack surface
unnecessarily. The signing algorithm in tokens we issue is fixed
(HS256), so validation should pin it.
**Zero-trust principle violated:** Fail-closed defaults.

#### A-CRIT-4 — `/authorized-keys` endpoints unauthenticated
**Severity:** Critical
**Location:** `internal/gateway/gateway.go:630-631`
**Description:** `/authorized-keys` and `/authorized-keys/sentinel` are
registered outside the auth middleware and documented as "VPC-only"
without any enforcement. If the daemon's REST port is ever reachable
from outside the VPC (firewall misconfiguration, VPC peering, IAP
gap), an attacker can enumerate every container's SSH public keys.
**Zero-trust principle violated:** Don't trust the network.

#### A-HIGH-1 — JWT `iss`/`aud` not validated
**Severity:** High
**Location:** `internal/auth/token.go:73-91`
**Description:** Issuer is set at generation time but never validated
on parse. No audience claim used at all. A token signed by the same
key for a different deployment (or different intended audience)
would be accepted.
**Zero-trust principle violated:** Validate credentials at the
resource boundary.

#### A-HIGH-2 — Cert export endpoint `/certs` unauthenticated
**Severity:** High
**Location:** `internal/gateway/gateway.go:627`
**Description:** Serves TLS certificates with no auth, comment claims
"VPC-only". Same exposure-on-misconfig risk as A-CRIT-4. Leaked
Caddy certs enable MITM of app traffic.

#### A-HIGH-3 — Privileged Podman is a single flag, no separate gate
**Severity:** High
**Location:** `internal/server/container_server.go:164`,
`pkg/core/incus/client.go:458-459`
**Description:** Setting `enable_podman=true` unconditionally
configures `security.privileged=true` and
`lxc.apparmor.profile=unconfined` on the LXC. There is no separate
authorization to grant privileged execution; any caller that can
create containers can become root-equivalent on the host.

#### A-MED-1 — JWT has no `jti` / no revocation
**Severity:** Medium
**Location:** `internal/auth/token.go`
**Description:** Tokens have no unique ID. A leaked token is valid for
its full TTL (up to 30 days) and cannot be revoked without rotating
the signing key (which invalidates every token).

#### A-MED-2 — No minimum JWT secret length
**Severity:** Medium
**Location:** `internal/auth/token.go:24-45`
**Description:** `NewTokenManager` accepts any secret length. HS256
requires ≥32 bytes for the security level it claims; weaker keys
are brute-forceable.

#### A-MED-3 — Tokens accepted in URL query strings
**Severity:** Medium
**Location:** `internal/gateway/gateway.go:392, 512`,
`internal/gateway/audit_handler.go:19`
**Description:** Endpoints (`/v1/containers/{name}/terminal`,
`/v1/events/subscribe`, `/v1/audit/logs`) accept `?token=…`. Query
strings get logged by every reverse proxy, load balancer, and
browser history mechanism in the request path.

#### A-MED-4 — RBAC roles defined but never enforced
**Severity:** Medium
**Location:** `internal/auth/token.go:18-19` and every handler in
`internal/server/`.
**Description:** `Claims.Roles` is parsed and added to context, but
no handler checks for required roles before performing privileged
operations.

#### A-MED-5 — Wake-on-HTTP `/wake/` and root `/` bypass auth middleware
**Severity:** Medium
**Location:** `internal/gateway/gateway.go:480-491, 641-643`
**Description:** Registered outside `corsHandler` (which wraps auth).
Documented assumption: only Caddy reaches these paths. If anything
else can, no JWT is required.

#### A-MED-6 — Internal proxies `/grafana/` `/alertmanager/` `/guacamole/` unauthenticated
**Severity:** Medium
**Location:** `internal/gateway/gateway.go:543-601`
**Description:** Reverse-proxied to internal services with no auth in
front. Each backend "handles its own" auth, but the daemon makes no
attempt to assert identity.

#### A-MED-7 — Algorithm name leaked in error message
**Severity:** Medium (reconnaissance aid)
**Location:** `internal/auth/token.go:77`
**Description:** Error response includes the offending `alg` value.
Returned verbatim to the HTTP client by the middleware. Useful for
fingerprinting in attack reconnaissance.

#### A-LOW-1 — `/health`, `/swagger-ui/`, `/webui/` unauthenticated
**Severity:** Low
**Location:** `internal/gateway/gateway.go:535-546`
**Description:** Acceptable for `/health`; consider gating
`/swagger-ui/` behind admin role to reduce API surface enumeration.

#### Clean (auth)

- Session/cookie handling — stateless JWT, no Set-Cookie issued.
- CSRF — no cookie auth, so no CSRF vector.
- MCP server `cmd/mcp-server/main.go:23-26` correctly requires a JWT
  from env or file and re-reads it on each call (rotation friendly).

---

### B. Input validation & injection

#### B-HIGH-1 — Container image URL accepted unvalidated
**Severity:** High
**Location:** `internal/server/container_server.go:160`
**Description:** `req.Image` flows directly to the runtime with no
registry allowlist, no digest pinning. A caller can pull from any
registry the daemon can reach, opening SSRF (registry URL points
at internal services) and supply-chain (typosquatted image)
attacks.

#### B-MED-1 — Unbounded `ssh_keys` array
**Severity:** Medium (DoS)
**Location:** `proto/containarium/v1/container.proto:210`,
`internal/server/container_server.go:151`
**Description:** No cap on the repeated field; caller can submit
arbitrarily many keys.

#### B-MED-2 — Unbounded `stack_parameters` map
**Severity:** Medium (DoS, env-var overflow)
**Location:** `proto/containarium/v1/container.proto:13`
**Description:** No key/value length or map-cardinality limits.

#### B-MED-3 — SSH key newline rejection is implicit
**Severity:** Medium (design fragility)
**Location:** `pkg/core/container/ssh_validate.go:35`
**Description:** Newline characters in keys are rejected only because
`ssh.ParseAuthorizedKey` happens to reject them. A future
refactor that loosens parsing (e.g., a `TrimSpace` upstream) would
re-enable `\ncommand="evil"` injection into the authorized_keys
file written at `pkg/core/container/jump_server.go:995-996`.

#### B-LOW-1 — Unbounded `labels` map
**Severity:** Low
**Location:** `proto/containarium/v1/container.proto:4`

#### Clean (input)

- **SQL injection** — `internal/audit/store.go`,
  `internal/secrets/store.go` use parameterized queries exclusively.
- **Path traversal** — `internal/gateway/keys_handler.go:139,144` and
  `pkg/core/container/jump_server.go:966-967` correctly contain
  filenames within base directories and validate usernames upstream.
- **Command injection** — every `exec.Command` invocation uses
  positional args (no shell concat, no `sh -c`).
- **YAML deserialization** — only embedded/internal config is
  unmarshaled, never user input.
- **HTTP header injection / open redirect** — no user input flows to
  response headers or `http.Redirect` Location.
- **Template injection** — server-side templates are pre-compiled
  with internal-only data.

---

### C. Transport, network & secrets

#### C-CRIT-1 — Peer-to-peer over plaintext HTTP
**Severity:** Critical
**Location:** `internal/server/peer.go:69-72, 295, 305`
**Description:** Bare `http.Client`, hardcoded `http://` URLs,
Bearer token sent in the clear. Any attacker with passive access to
the internal network harvests admin credentials.

#### C-CRIT-2 — Sentinel `/sentinel/peers` poll over plaintext HTTP, response unsigned
**Severity:** Critical
**Location:** `internal/server/peer.go:109-199`
**Description:** Compromised sentinel (or active MITM on the path)
injects attacker-controlled peer URLs; daemon then forwards
container management traffic to them.

#### C-HIGH-1 — MCP client uses bare `http.Client`, no TLS pinning
**Severity:** High
**Location:** `internal/mcp/client.go:46-48, 82`
**Description:** Tolerates `http://` baseURL, performs no
certificate pinning. If `baseURL` is misconfigured, JWT travels
in cleartext.

#### C-HIGH-2 — mTLS optional on gRPC, silent plaintext fallback
**Severity:** High
**Location:** `internal/mtls/loader.go:14-51` + server bootstrap
**Description:** If certificate loading fails, gRPC falls back to
plaintext. Comment in `internal/auth/middleware.go:72-74` says
"rely on mTLS" but the interceptor is a passthrough that doesn't
check whether mTLS was actually used.

#### C-HIGH-3 — SSH port 22 firewall default `0.0.0.0/0`
**Severity:** High
**Location:** `terraform/modules/containarium/sentinel.tf:104-106`
**Description:** Default opens sshpiper to the public internet.
Sensible defaults should narrow this to a known CIDR and require
explicit opt-in for wide exposure.

#### C-HIGH-4 — REST gateway (8080) firewall not explicitly pinned
**Severity:** High
**Location:** `terraform/modules/containarium/main.tf:65-73`
**Description:** Daemon REST exposure depends on GCE defaults. If a
future change loosens those, the API becomes internet-reachable.

#### C-HIGH-5 — OTel collector binds `0.0.0.0` with no auth
**Severity:** High
**Location:** `internal/server/core_otel_collector.go`
**Description:** OTLP receivers on ports 4317/4318 accept anonymous
push. Cardinality DoS and metrics pollution are trivial.

#### C-HIGH-6 — Master-key file permissions not re-checked at load
**Severity:** High
**Location:** `pkg/core/secrets/crypto.go:47, 109`
**Description:** Generated with mode 0400, but no `stat()` on load
to confirm the file is still 0400 and owned by root. Umask drift,
ownership change, or backup-tool side effects could widen
permissions silently.

#### C-HIGH-7 — JWT token file (`CONTAINARIUM_JWT_TOKEN_FILE`) loaded with no permission check
**Severity:** High
**Location:** `internal/mcp/client.go:57-78`
**Description:** Any process readable by the same UID gets the
token. The file is often deployed via Terraform/ansible without a
strict mode.

#### C-MED-1 — PROXY-protocol trust list not enforced
**Severity:** Medium
**Location:** `internal/server/dual_server.go`
**Description:** PROXY v2 headers should be trusted only from the
sentinel's IP; the trust list is configurable but not
required-non-empty at startup.

#### C-MED-2 — Caddy minimum TLS version / cipher suites unaudited
**Severity:** Medium
**Location:** `internal/hosting/caddy.go`
**Description:** Caddy's defaults are sensible but the generated
config does not explicitly pin TLS 1.3 or restrict ciphers.

#### C-MED-3 — No app-layer rate limiting on auth endpoints
**Severity:** Medium
**Location:** `internal/auth/`, gateway
**Description:** Defense-in-depth gap. `fail2ban` mitigates at the
host level but the daemon should rate-limit failed JWT validations
per source IP.

#### C-MED-4 — Container env-var introspection exposes secrets
**Severity:** Medium
**Location:** `internal/server/secrets_server.go:133-155`
**Description:** Secrets are stamped into LXC env vars. Anyone with
`incus exec <name> env` (operator or container-internal process)
sees every secret in plaintext.

#### C-MED-5 — Audit log `detail` field has no redaction policy
**Severity:** Medium
**Location:** `internal/audit/store.go:53-74`
**Description:** Schema is free-text TEXT column. Future handlers
that log request bodies could persist secrets in the audit table.

#### C-MED-6 — Postgres URL in env var
**Severity:** Medium
**Location:** `internal/server/dual_server.go`
**Description:** Visible via `ps`, `docker inspect`, error logs.

#### C-MED-7 — TLS private key directory permissions unverified
**Severity:** Medium
**Location:** `internal/hosting/caddy.go`
**Description:** Daemon doesn't refuse to start if Caddy's cert
storage is world-readable.

#### C-MED-8 — 30-day max token expiry, no short-lived option
**Severity:** Medium
**Location:** `internal/auth/token.go:14`
**Description:** Long-lived tokens magnify breach impact. No
issuance path for short-lived (≤1h) access tokens + refresh tokens
exists.

#### Clean (transport / secrets)

- **AES-256-GCM secrets encryption** with random 12-byte nonces and
  AAD binding `(username, 0x00, name)` is implemented correctly.
  `pkg/core/secrets/crypto.go:146-150, 179-185`.
- **Secret values are never logged.**
  `internal/server/secrets_server.go:40, 69`.
- **Audit logs capture identity + action + resource** for non-trivial
  endpoints (`internal/audit/middleware.go:76-128`).

---

## Summary by severity

| Severity | Count |
|---|---|
| Critical | 5 |
| High | 12 |
| Medium | 17 |
| Low | 2 |
| **Total** | **36** |

Remediation tracking is in [ZERO-TRUST-TODO.md](./ZERO-TRUST-TODO.md).
