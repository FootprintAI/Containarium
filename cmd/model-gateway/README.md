# model-gateway

A prototype of the agent model gateway described in
`docs/AGENT-MODEL-GATEWAY-DESIGN.md`.

The gateway is the **single egress point** that holds the real provider API
keys. Agent boxes present short-lived, scoped **gateway tokens** (HS256 JWTs
signed with the same shared secret as the platform JWT). The gateway verifies
the token, injects the real key, proxies to the provider, and meters per-tenant
token usage. The real key never leaves the gateway process and never touches a
box.

## Quick start

```bash
# Build
make build-model-gateway-linux

# Run (reads provider keys from env)
GEMINI_API_KEY=<key> \
  model-gateway serve \
    --addr :8866 \
    --secret-file /etc/containarium/jwt.secret

# Mint a test token (stands in for provisionSkillBox in production)
model-gateway mint \
  --secret-file /etc/containarium/jwt.secret \
  --tenant acme \
  --provider gemini \
  --skill hello-agent \
  --allowed-models gemini-2.5-flash \
  --ttl 1h
```

## Gateway routes

| Path | Purpose |
|---|---|
| `POST /v1/model/<provider>/...` | Proxy to the upstream provider |
| `GET /__gateway/usage` | In-memory usage rollup (JSON) |
| `GET /__gateway/healthz` | Health probe |

The `<provider>` segment must match a registered provider name
(`anthropic`, `openai`, or `gemini`). The rest of the path is forwarded
to the upstream as-is (the `/v1/model/<provider>` prefix is stripped).

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
subcommand is a development shortcut only.
