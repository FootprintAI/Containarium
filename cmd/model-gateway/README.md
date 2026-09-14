# model-gateway

The agent model gateway described in `docs/AGENT-MODEL-GATEWAY-DESIGN.md`. It
can run standalone — no LXC daemon required — which is what
`ghcr.io/footprintai/containarium-model-gateway` (published per release,
`images/model-gateway/Dockerfile`) packages for exactly that: running as a
plain pod in front of an agent sandbox.

The gateway is the **single egress point** that holds the real provider API
keys. Agent boxes present short-lived, scoped **gateway tokens** (HS256 JWTs
signed with the same shared secret as the platform JWT). The gateway verifies
the token, injects the real key, proxies to the provider, and meters per-tenant
token usage. The real key never leaves the gateway process and never touches a
box. An operator can revoke an issued token before its TTL runs out (`revoke
--jti`, below) — the kill-switch a year-long recipe-box token's safety
depends on.

## Quick start

```bash
# Build
make build-model-gateway-linux

# Run (reads provider keys from env; --admin-token-file is optional — omit it
# and POST /__gateway/revoke simply doesn't exist)
GEMINI_API_KEY=<key> \
  model-gateway serve \
    --addr :8866 \
    --secret-file /etc/containarium/jwt.secret \
    --admin-token-file /etc/containarium/gateway-admin.token

# Mint a test token (stands in for provisionSkillBox in production)
model-gateway mint \
  --secret-file /etc/containarium/jwt.secret \
  --tenant acme \
  --provider gemini \
  --skill hello-agent \
  --allowed-models gemini-2.5-flash \
  --ttl 1h \
  --print-jti   # prints "jti: <id>" to stderr; the token itself stays on stdout

# Revoke it before its TTL — the same call the daemon makes when a run ends
model-gateway revoke \
  --admin-url http://localhost:8866 \
  --admin-token-file /etc/containarium/gateway-admin.token \
  --jti <id from --print-jti>
```

## Gateway routes

| Path | Purpose |
|---|---|
| `POST /v1/model/<provider>/...` | Proxy to the upstream provider |
| `GET /__gateway/usage` | In-memory usage rollup (JSON) |
| `GET /__gateway/policy` | Per-tenant enforcement state (JSON) |
| `GET /__gateway/status` | Request-lifecycle gauge (JSON) |
| `GET /__gateway/healthz` | Health probe |
| `POST /__gateway/revoke` | Revoke a gateway token by jti. Only registered when `--admin-token-file` is set — the route otherwise doesn't exist (404, not 401) |

The `<provider>` segment must match a registered provider name
(`anthropic`, `openai`, or `gemini`). The rest of the path is forwarded
to the upstream as-is (the `/v1/model/<provider>` prefix is stripped).

### Revoking a token

```
POST /__gateway/revoke
Authorization: Bearer <admin token>
Content-Type: application/json

{"jti": "<id>", "expires_at": "2026-01-01T00:00:00Z", "reason": "leaked"}
```

`expires_at` is optional: omit it (the CLI's default) and the revocation
never expires. Passing it only makes sense when the caller actually knows
the token's real expiry — it just lets the in-memory store reclaim the entry
once that passes; it does not shorten how long the revocation itself is
honored, and guessing a shorter value than the token's real TTL would
silently let the token start working again once your guess elapses.

`204` on success, `401` for a wrong or missing bearer (compared in constant
time), `400` for a malformed body or a non-empty `expires_at` that fails to
parse. Standalone runs keep revocations in memory (`MemRevocations`, swept
once each entry's non-empty `expires_at` passes); the daemon wires the same
Postgres-backed store it already uses for platform JWTs, so this is the
identical revocation list a platform-JWT `revoke` hits — no second store, no
drift between the two.

## Auth

The box presents the gateway token in the same header the provider SDK uses:

| Provider | Header |
|---|---|
| Anthropic / OpenAI | `Authorization: Bearer <token>` |
| Gemini | `x-goog-api-key: <token>` |

The gateway strips the inbound credential before proxying and injects the real
provider key instead.

## Agent-runtime integration

### Gemini engine

Set two env vars on the agent box (via secrets or the daemon's seed):

```
CONTAINARIUM_MODEL_GATEWAY_URL=http://model-gateway:8866
CONTAINARIUM_GATEWAY_TOKEN=<gateway-token>
```

When both are set the Gemini engine routes through the gateway instead of
hitting `generativelanguage.googleapis.com` directly. The real `GEMINI_API_KEY`
stays in the gateway only.

### Claude (Anthropic) engine

The Anthropic SDK already honours `ANTHROPIC_BASE_URL` and
`ANTHROPIC_AUTH_TOKEN`. Point them at the gateway:

```
ANTHROPIC_BASE_URL=http://model-gateway:8866/v1/model/anthropic
ANTHROPIC_AUTH_TOKEN=<gateway-token>
```

### OpenAI / Codex engine

The OpenAI SDK honours `OPENAI_BASE_URL` and `OPENAI_API_KEY`:

```
OPENAI_BASE_URL=http://model-gateway:8866/v1/model/openai
OPENAI_API_KEY=<gateway-token>
```

## Token claims

```json
{
  "tenant": "acme",
  "skill_id": "hello-agent",
  "run_id": "run-abc123",
  "provider": "gemini",
  "allowed_models": ["gemini-2.5-flash"],
  "iss": "containarium-model-gateway",
  "exp": 1750000000
}
```

`allowed_models` is optional (empty = any). For Gemini the model is in the
request path, so the gateway enforces it before proxying. For Anthropic /
OpenAI the model is in the request body — body enforcement is a planned
fast-follow.

## Production wiring

In production `provisionSkillBox` mints the gateway token alongside the
platform JWT, using the same shared HMAC secret (`jwt.secret`). The `mint`
subcommand is a development shortcut; `revoke` is the same operation a
production daemon performs against its own admin-token-guarded gateway when a
run ends (`runlease.End`) or an operator kills a leaked credential.
