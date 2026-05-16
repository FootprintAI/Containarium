# Secrets management — design

**Status:** Draft
**Last updated:** 2026-05-16
**Related:**
- [`docs/SECURITY-ENCRYPTION-AT-REST.md`](SECURITY-ENCRYPTION-AT-REST.md) — encryption posture this builds on
- [`docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md`](ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md) — the per-tenant-key story this composes with
- [`docs/PLATFORM-SIDECAR-DESIGN.md`](PLATFORM-SIDECAR-DESIGN.md) — the sidecar primitive a v2 secret-resolver could ride on
- [`docs/OTEL-COLLECTOR-DESIGN.md`](OTEL-COLLECTOR-DESIGN.md) — env-var stamping pattern this mirrors

## Context

Every Containarium user — single-tenant self-hoster or multi-tenant cloud tenant — needs somewhere to put API keys, database passwords, JWT signing secrets, OAuth tokens, etc. Today the only options are:

1. Plaintext in the LXC's docker-compose `environment:` block (lands in the user's git history).
2. Manual `incus config set <ct> environment.OPENAI_API_KEY=…` (operator-only, not tenant-discoverable, no rotation, no audit).
3. Bring-your-own secret-store: HashiCorp Vault, Doppler, etc. — works, but adds a separate service to operate and another set of credentials to bootstrap.

None of these is acceptable as the platform default. This doc designs a daemon-managed secrets API that ships in OSS, mirrors the per-container scope the rest of Containarium uses, and earns cloud-product value-add (managed KMS, per-secret ACL, structured audit) by layering on the same wire surface.

## Goals / non-goals

**Goals**

- A first-class daemon API: `SetSecret`, `GetSecret`, `ListSecrets`, `DeleteSecret`. CLI, REST, gRPC, MCP — same surface every other platform operation has.
- Encryption at rest with a master key the daemon holds — secrets in the database are ciphertext.
- Per-container scope by default: secret `OPENAI_API_KEY` owned by `alice` is reachable inside `alice-container` and nowhere else.
- Stamped into the LXC as env vars on container create + toggle, so apps inside docker get them via the same `${VAR}` compose interpolation pattern OTel uses (`docs/OTEL-AGENT-RELAY-DESIGN.md`).
- Rotation is `containarium secrets set <user> <key> <new-value>`; cleanly replays into the LXC env on next container restart.
- Plumbed through CLI + MCP from day one — agents can set tenant secrets the same way a human can.

**Non-goals (for v1)**

- Cross-container shared secrets. Per-secret ACLs (e.g. one DB password readable by `frontend` and `worker` containers) is v2.
- KMS-backed master key. v1 uses a file-on-disk; v2 layers GCP KMS / Vault behind the same wire surface (mirrors the ZFS-keyfile → KMS evolution path).
- Live (no-restart) secret refresh in running containers. v1 stamps env vars at create / toggle / start time; changes need a restart. v2 may add a sidecar resolver that fetches on demand.
- Structured audit events. v1 logs `SetSecret / GetSecret / DeleteSecret` lines to the daemon journal; v2 routes them into the future `audit-sidecar` pipeline.
- Cross-VM secret federation. `MoveContainer` does NOT carry secrets across daemons in v1 — the destination's tenant re-sets. (See "MoveContainer interaction" below.)
- Secret rotation policies, expiry, time-bounded credentials. v1 is "operator/agent rotates by calling Set with the new value." Policy automation is cloud-product territory.

## Architecture

```
┌────────────────── one Containarium daemon (single VM) ────────────────────┐
│                                                                           │
│   /etc/containarium/secrets.key   (32-byte raw, mode 0400, root-owned)    │
│              │                                                            │
│              │ AES-256-GCM key                                            │
│              ▼                                                            │
│   ┌──────────────────────────┐                                            │
│   │ daemon                   │   POST /v1/secrets   { username, name,      │
│   │  encrypt with master key │ ◄─ value }                                  │
│   │  store ciphertext in PG  │   GET  /v1/secrets/{username}/{name}        │
│   │  audit-log line          │   GET  /v1/secrets/{username}               │
│   └────────────┬─────────────┘   DELETE /v1/secrets/{username}/{name}      │
│                │                                                          │
│                │ INSERT / SELECT (encrypted payload)                      │
│                ▼                                                          │
│   ┌──────────────────────────┐                                            │
│   │ containarium-core-postgres │                                           │
│   │  secrets table             │  schema:                                  │
│   │   (id, username, name,     │   id uuid, username text, name text,      │
│   │    nonce, ciphertext,      │   nonce bytea (12B), ciphertext bytea,    │
│   │    version, …)             │   version int, created_at, updated_at,    │
│   │                            │   PRIMARY KEY (username, name)            │
│   └──────────────────────────┘                                            │
│                │                                                          │
│                │ on container create / toggle / start:                    │
│                │   for each secret in SELECT username=… → decrypt → stamp │
│                │   environment.<NAME>=<value> on the LXC                  │
│                ▼                                                          │
│   ┌──────────────────────────┐                                            │
│   │ alice-container (LXC)    │   apps read via:                            │
│   │  environment.OPENAI_API_KEY=sk-…   • LXC processes: $OPENAI_API_KEY    │
│   │  environment.DATABASE_URL=postgres… • compose: ${OPENAI_API_KEY}       │
│   └──────────────────────────┘                                            │
└───────────────────────────────────────────────────────────────────────────┘
```

Same env-stamping pattern as `--monitoring`: the daemon owns the source of truth (Postgres); the LXC env is a cached, decryption-resolved view; apps inside docker access via compose `${VAR}` interpolation.

## Detailed design

### 1. The proto surface

```proto
service SecretsService {
  rpc SetSecret(SetSecretRequest) returns (SetSecretResponse);
  rpc GetSecret(GetSecretRequest) returns (GetSecretResponse);
  rpc ListSecrets(ListSecretsRequest) returns (ListSecretsResponse);
  rpc DeleteSecret(DeleteSecretRequest) returns (DeleteSecretResponse);
}

message SetSecretRequest {
  string username = 1;
  string name = 2;       // uppercase ASCII + digits + '_' (env-var compatible)
  string value = 3;      // up to 64 KiB; the daemon enforces
}
```

HTTP mapping:

```
POST   /v1/secrets                          (body: {username, name, value})
GET    /v1/secrets/{username}/{name}        → {value} (decrypted)
GET    /v1/secrets/{username}               → [{name, version, updated_at}, …]   (metadata only)
DELETE /v1/secrets/{username}/{name}
```

`ListSecrets` returns metadata only — names and versions — never the values. Reading a value is always per-name + audit-logged.

### 2. Storage schema

```sql
CREATE TABLE secrets (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username     text NOT NULL,
  name         text NOT NULL,
  nonce        bytea NOT NULL,    -- 12 bytes (AES-GCM)
  ciphertext   bytea NOT NULL,    -- includes 16-byte GCM auth tag
  version      int  NOT NULL DEFAULT 1,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (username, name)
);
```

`version` bumps on every `SetSecret` for the same `(username, name)` — useful for rotation diagnostics and as the v2 trigger for live-refresh ("LXC's stamped env says version=3 but DB says version=4, restart needed").

### 3. Master key custody

v1: a 32-byte raw key in `/etc/containarium/secrets.key`, mode `0400`, root-owned. Generated by the daemon on first start if missing (same pattern as the ZFS keyfile from PR #177). The daemon reads it at startup, holds in process memory, never logs it.

Loss of the keyfile = all stored secrets are unrecoverable ciphertext. Operators MUST back it up off-host. Documented loudly in install scripts + daemon startup log.

The keyfile lives on the boot disk, the Postgres data lives on the data disk — so an attacker who exfils only the data disk gets ciphertext + nonces with no key (same defense-in-depth pattern as the ZFS-keyfile-on-boot vs encrypted-pool-on-data layout).

### 4. Encryption scheme

**AES-256-GCM**, the NIST-recommended AEAD. Each secret:

1. Generate a fresh 12-byte random nonce.
2. `ciphertext, tag = AES-GCM(key=master, nonce=random, plaintext=value, AAD=username+name)` — using `username+name` as Additional Authenticated Data binds the ciphertext to its intended slot (a forged tuple of `(username, name, ciphertext, nonce)` from one user can't be replayed under a different name).
3. Store `nonce || ciphertext_with_tag` in the `secrets` row.

Standard Go `crypto/aes` + `crypto/cipher` — no external library, no novel crypto.

### 5. Env-var stamping flow

When `SetSecret` succeeds, the daemon does **not** push the env into running containers — the value applies on next container start. Three triggers in practice:

| Trigger | What the daemon does |
|---|---|
| `CreateContainer` (sync or async) | After Incus create, SELECT all secrets WHERE username=req.Username, decrypt, `incus config set environment.<name>=<value>` for each |
| `StartContainer` | Same as above — refresh from the current DB state in case secrets changed while the container was stopped |
| `RestartSecretsEnv <user>` (new RPC, see below) | Same SELECT-decrypt-stamp loop without restarting the container; tenant calls this after rotation if they want the next process they exec to see the new value |

Decoupling the secret store from the LXC env means the canonical state lives in one place (Postgres). Tenants who want a live-refresh path that survives without daemon restart get it via `RestartSecretsEnv` (v1 — no LXC restart) or eventually via the v2 sidecar resolver (no env stamping at all).

### 6. CLI / MCP surface

```bash
# Set / rotate (idempotent)
containarium secrets set alice OPENAI_API_KEY sk-abc...
containarium secrets set alice OPENAI_API_KEY sk-def...   # rotation

# List (metadata only)
containarium secrets list alice

# Read (for debug / migration; audit-logged)
containarium secrets get alice OPENAI_API_KEY

# Delete
containarium secrets delete alice OPENAI_API_KEY

# Re-stamp the LXC env without restarting (post-rotation)
containarium secrets refresh alice
```

MCP tools mirror exactly: `set_secret`, `get_secret`, `list_secrets`, `delete_secret`, `refresh_secrets`.

A `get_secret` MCP call returns the decrypted value to the agent. That's a deliberate design choice — if you give the agent the ability to write secrets, you give it the ability to read them (otherwise it can't sanity-check what it just wrote). Cloud-product audit picks up the read events; OSS users see them in `journalctl -u containarium`.

### 7. MoveContainer interaction

Secrets are tied to the **source daemon's Postgres** and master key — they do not travel with `MoveContainer`. Two reasons:

1. Cross-daemon secret transfer needs a key-exchange protocol that v1 doesn't have.
2. The destination's master key is different — re-encryption would have to happen at the API layer, not the storage layer.

v1 behavior: `MoveContainer` proceeds normally; the LXC arrives at the destination with whatever env vars were stamped at last start (which keep working until rotation). After the move, the tenant re-sets each secret on the destination daemon. Documented as a known limitation.

v2: a shared-backend mode (HashiCorp Vault, GCP KMS Secret Manager, etc.) makes secrets host-independent, and `MoveContainer` "just works."

### 8. Failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| Master keyfile missing at daemon startup | Daemon refuses to start with a loud error pointing at the recovery doc. | Daemon never auto-generates a new key after the first install — that would silently invalidate every existing ciphertext. |
| Master keyfile corrupted / wrong key | Decrypt fails with auth-tag mismatch. Daemon logs the corruption + refuses to stamp env vars (better to fail a container start than ship empty/garbled secrets to the app). | Operator restores from off-host backup. |
| Postgres unreachable | `SetSecret` / `GetSecret` return Unavailable. `CreateContainer` and `StartContainer` fall back to "stamp no secret env vars" + log a warning (containers without secrets still start). | Daemon retries Postgres connection on backoff; alerting on connection failure is via the existing alert pipeline. |
| Agent reads many secrets in a tight loop (DoS / exfil) | The audit log grows; the master key stays decrypted in daemon memory. No rate limit in v1. | v2 adds per-tenant rate limit on `GetSecret`. v1 mitigation: operator monitors the journal. |
| Secret stamped into LXC env then container stops mid-handling | Env is in the Incus config, which persists across LXC restarts. The plaintext appears in `incus config show` to anyone with daemon-host root. | Documented: the env-stamping model trades disk-resident plaintext (in Incus config) for tenant ergonomics. Operators who want stricter isolation use the v2 sidecar resolver (secret fetched on demand, never written to disk). |
| `containarium-core-postgres` migrated to a new host | Standard Postgres backup/restore. Master key + ciphertexts move together; nothing special. | Routine. |

### 9. Cloud value-add (v2 sketch)

- **KMS-backed master key**: same API, daemon proxies through GCP KMS / Vault instead of file. Encrypt/decrypt latency goes from microseconds to ~10ms — acceptable for create-time stamping.
- **Per-secret ACL**: `SetSecret` takes a `readable_by: [username, …]` list; `GetSecret` checks the caller's identity.
- **Sidecar resolver**: `secrets-sidecar` image that the tenant composes in; their app emits `${secret:OPENAI_API_KEY}` references; sidecar fetches on demand, never stores plaintext in the LXC env. Pairs with rotation without restart.
- **Audit pipeline**: structured events to the planned `audit-sidecar`; SOC 2 / ISO 27001-ready evidence collection.
- **Rotation policies**: cloud schedules rotation maintenance windows by tenant policy.

## Open questions

| # | Question | Why it matters | Proposed answer |
|---|---|---|---|
| 1 | Secret name charset / validation? | Names become Incus env-config keys; Linux env vars are uppercase ASCII + digits + `_`. | Enforce `^[A-Z_][A-Z0-9_]*$` at the API layer, max length 128. Reject everything else with InvalidArgument. |
| 2 | Max secret value size? | TLS cert blobs and SSH keys are bigger than typical API keys but still bounded; Postgres BYTEA holds gigabytes, Incus env-config keys cap somewhere ~1MB. | 64 KiB hard cap in v1. Big enough for any reasonable cert/key; small enough to keep Incus env config sane. |
| 3 | Should `GetSecret` require an LXC-bound caller token (only the matching container can read its own secrets) or an admin-bound JWT? | Tenant ergonomics vs. defense in depth. | Admin-JWT in v1 (same auth model as every other Containarium API). Per-LXC tokens are v2; they need a separate identity rollout. |
| 4 | What happens to secrets when the container is deleted? | Secrets in Postgres are tenant-scoped, not container-scoped — they survive container recreate by design. | Survive. `containarium secrets delete` is the explicit way to remove them. Deleting an LXC does NOT cascade-clean secrets. |
| 5 | First-install keyfile generation: auto or operator-prompted? | Same trade-off as ZFS keyfile (PR #177). | Auto-generate on first start if missing (32 bytes from `crypto/rand`, mode 0400). Log a loud warning telling the operator to back it up. |
| 6 | Secrets exposed to MCP `get_secret` — gate on a flag, or always? | Some operators want agent-write-only secrets ("the agent can rotate but never read"). | v1: always exposed. v2: a per-secret `read_via_api: bool` flag covers the write-only-rotation case. |

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **0. RFC accepted** | this doc + decisions on the 6 open questions | (you) |
| **1. Proto + crypto helper** | `proto/containarium/v1/secrets.proto`, `pkg/core/secrets/` package with AES-GCM helpers, unit tests | ~½ day |
| **2. Postgres migrations + store** | `secrets` table, `internal/secrets/store.go` CRUD, encryption boundary at the store level | ~½ day |
| **3. SecretsService server impl** | `internal/server/secrets_server.go` with the four RPCs | ~½ day |
| **4. Env-var stamping wiring** | hook into CreateContainer / StartContainer to SELECT + decrypt + `incus config set` | ~½ day |
| **5. CLI subcommands + remote-mode** | `containarium secrets {set,get,list,delete,refresh}` | ~½ day |
| **6. MCP tools** | `set_secret`, `get_secret`, `list_secrets`, `delete_secret`, `refresh_secrets` | ~½ day |
| **7. RefreshSecrets RPC** | re-stamp env on a running container without restart (calls into Incus directly, no LXC stop/start) | ~½ day |
| **8. Tests + docs** | unit (crypto helper, store), integration (full create-with-secrets flow), docs/SECRETS-MANAGEMENT.md operator runbook | ~1 day |

**Total: ~4.5 days OSS** for the file-keyfile / Postgres / env-stamping path. Cloud value-add (KMS, ACL, sidecar resolver, audit pipeline) layers on top via the same wire surface.

## History

| Date | Author | Change |
|---|---|---|
| 2026-05-16 | hsinhoyeh, drafted with Claude | Initial draft. Daemon-managed secrets API with file-based master key, AES-256-GCM in Postgres, env-var stamping at container start, per-container scope. Status: Draft. |
