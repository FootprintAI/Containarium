# Operator Security Runbook

A "what do I do when X" reference for operators running Containarium
in production. Engineering-facing detail lives in
[ZERO-TRUST-AUDIT.md](ZERO-TRUST-AUDIT.md) and
[ZERO-TRUST-TODO.md](ZERO-TRUST-TODO.md); this file is the
operational counterpart — short procedures, the exact commands, and
the rationale in one or two sentences.

If you find yourself doing something here more than once, automate it.
If a procedure here is wrong, update it.

## Table of contents

- [Token lifecycle](#token-lifecycle)
- [Suspected credential leak](#suspected-credential-leak)
- [Issuing least-privilege tokens for agents](#issuing-least-privilege-tokens-for-agents)
- [Rotating the JWT signing secret](#rotating-the-jwt-signing-secret)
- [Rotating Postgres credentials](#rotating-postgres-credentials)
- [Switching Postgres to unix-socket auth (no password on the wire)](#switching-postgres-to-unix-socket-auth-no-password-on-the-wire)
- [Enabling KMS envelope encryption for secrets](#enabling-kms-envelope-encryption-for-secrets)
- [Pinning and verifying container image digests](#pinning-and-verifying-container-image-digests)
- [Locking down `/wake/` to a known load balancer](#locking-down-wake-to-a-known-load-balancer)
- [Pinning per-tenant network policy](#pinning-per-tenant-network-policy)
- [Auditing recent administrative actions](#auditing-recent-administrative-actions)
- [Verifying the audit-log hash chain](#verifying-the-audit-log-hash-chain)

---

## Token lifecycle

Containarium issues JWTs in three forms (Phase 1.6):

| Form          | `tt` claim   | Default TTL | What it can do                 |
| ------------- | ------------ | ----------- | ------------------------------ |
| **access**    | `access`     | 15 min      | Authenticate to the API        |
| **refresh**   | `refresh`    | 30 days     | Exchange at `/v1/tokens/refresh` for a new access + refresh pair |
| **legacy**    | (omitted)    | 24h (CLI default) | Behaves as access on the API surface — kept for backwards compat |

A refresh token **cannot** authenticate to any API surface. Stealing
one only buys the attacker one rotation cycle before the legitimate
holder's next exchange revokes it.

### Mint an operator access token (interactive)

```bash
containarium token generate \
    --username "$YOUR_USERNAME" --roles admin \
    --token-type access --expiry 8h \
    --secret-file /etc/containarium/jwt.secret
```

15-minute defaults are aimed at agents. For an operator session,
`--expiry 8h` is reasonable; the access token cannot be revoked
mid-session except via the kill-switch below.

### Mint a long-lived refresh + short-lived access pair

```bash
# Mint the refresh; store it somewhere only you can read.
containarium token generate \
    --username "$YOUR_USERNAME" --roles admin \
    --token-type refresh --expiry 720h \
    --secret-file /etc/containarium/jwt.secret \
    --raw > ~/.containarium/refresh
chmod 0600 ~/.containarium/refresh

# Whenever you need a fresh access token (e.g. on session start):
containarium token refresh \
    --refresh-token-file ~/.containarium/refresh \
    --server https://<cluster>.example.com
```

`token refresh` prints the new access token (use for the next ~15
minutes) and a new refresh token (replaces the old one — the prior
file's contents are now revoked server-side).

---

## Suspected credential leak

You believe a JWT, refresh token, or operator credential has been
exposed (pushed to a public gist, leaked via a tenant logfile,
present in a screen recording, …).

### Step 1 — Find the `jti`

Every authenticated request the leaked token made was audit-logged
with its `jti` claim. Pull it from the audit log:

```bash
containarium audit query \
    --username "$LEAKED_USERNAME" \
    --from "2026-05-20T00:00:00Z" \
    --limit 50
```

Each row carries the `jti` in the detail column. If you have the raw
JWT, the `inspect` subcommand decodes it for you (no daemon contact
required):

```bash
containarium token inspect "$LEAKED_TOKEN"

# Or for scripting:
containarium token inspect "$LEAKED_TOKEN" --raw | jq -r .jti
```

Optionally pass `--secret-file /etc/containarium/jwt.secret` to also
validate the signature (confirms the token was genuinely issued by
this daemon and hasn't expired).

### Step 2 — Revoke

```bash
containarium token revoke \
    --jti "$JTI" \
    --reason "leaked_to_public_gist_$(date -u +%Y%m%d)" \
    --server https://<cluster>.example.com \
    --token "$ADMIN_TOKEN"
```

Idempotent — running it twice with the same `jti` preserves the first
reason. From this point on, any request bearing the revoked token
gets `401 invalid token`.

Confirm the revoke landed (admin + `tokens:write` scope required):

```bash
containarium token list-revoked \
    --jti-prefix "$JTI_FIRST_CHARS" \
    --server https://<cluster>.example.com \
    --token "$ADMIN_TOKEN"
```

Pass `--include-expired` to enumerate the full history (forensic).

### Step 3 — If the leaked token was a refresh token

The exchange endpoint won't accept it once revoked, BUT the
attacker may already have exchanged it for a fresh pair before you
caught the leak. To be safe:

1. Revoke every refresh-token jti the user issued in the suspicious
   window (filter audit by `action=token_refresh`).
2. Force the user to re-mint at the daemon (`containarium token
   generate --token-type refresh`).

### Step 4 — Look for lateral movement

```bash
# Anything the leaked user did between issuance and revocation
containarium audit query --username "$LEAKED_USERNAME" --from "$ISSUE_TIME"
```

Triage by action type: container create/delete, secret read,
`expose_port`, `toggle_monitoring` — anything write-shaped is worth
manual review.

---

## Issuing least-privilege tokens for agents

LLM agents (Claude, Cursor, etc.) consuming the MCP server should
NOT be carrying admin-role unrestricted tokens. The Phase 1.7 scope
model (`internal/auth/scopes.go`) lets you mint narrow tokens:

```bash
# Read-only agent — can list and inspect, can't mutate
containarium token generate \
    --username "agent-claude-readonly" --roles user \
    --scopes containers:read,secrets:read,routes:read \
    --token-type access --expiry 24h \
    --secret-file /etc/containarium/jwt.secret

# Container-ops agent — can lifecycle containers but not touch secrets
containarium token generate \
    --username "agent-claude-ops" --roles user \
    --scopes containers:read,containers:write,routes:read,routes:write,ssh:write \
    --token-type access --expiry 24h \
    --secret-file /etc/containarium/jwt.secret
```

Available scopes (full list in `internal/auth/scopes.go`):

| Scope                | Tools                                                |
| -------------------- | ---------------------------------------------------- |
| `containers:read`    | list/get/debug containers, metrics, system info      |
| `containers:write`   | create/delete/start/stop/resize/move containers      |
| `secrets:read`       | get/list secrets                                     |
| `secrets:write`      | set/delete/refresh secrets                           |
| `routes:read`        | list routes                                          |
| `routes:write`       | expose ports                                         |
| `security:read`      | view findings                                        |
| `security:write`     | trigger scans, remediate                             |
| `alerts:read`        | view alert rules + webhook deliveries                |
| `alerts:write`       | create/update/delete alert rules, webhook config     |
| `traffic:read`       | query traffic history + subscribe to events          |
| `ssh:write`          | add/remove SSH keys, sync ssh-config                 |
| `code:write`         | `push`, `sync` developer-loop tools                  |
| `tokens:write`       | revoke other JWTs                                    |
| `*`                  | wildcard — everything (avoid for agent tokens)       |

The MCP server filters `tools/list` to scopes the JWT grants and
rejects out-of-scope `tools/call` locally before the request hits the
network. The daemon enforces the same gates on REST/gRPC, so a
non-MCP REST caller using a scoped token gets the same restrictions.

---

## Rotating the JWT signing secret

The signing secret lives at `/etc/containarium/jwt.secret` (mode
`0600`). Rotating it invalidates **every** issued token — operators
included — so plan the cutover.

```bash
# 1. Generate a new secret (>=32 bytes for HMAC-SHA256 floor)
openssl rand -base64 48 | sudo tee /etc/containarium/jwt.secret.new
sudo chmod 0600 /etc/containarium/jwt.secret.new
sudo chown root:root /etc/containarium/jwt.secret.new

# 2. Swap atomically
sudo mv /etc/containarium/jwt.secret.new /etc/containarium/jwt.secret

# 3. Restart the daemon (token validation reads on each call but
#    the secret is captured at NewTokenManager time, so a restart
#    is required to pick it up)
sudo systemctl restart containarium

# 4. Re-mint your own admin token immediately (use the new secret)
containarium token generate --username "$YOUR_USERNAME" --roles admin \
    --token-type access --expiry 8h \
    --secret-file /etc/containarium/jwt.secret
```

The audit-log entry for the restart will be missing the daemon's
self-issued system token (which is re-minted on startup against the
new secret); that's expected.

---

## Rotating Postgres credentials

Containarium reads Postgres credentials from (in order):
`CONTAINARIUM_POSTGRES_URL_FILE` → `CONTAINARIUM_POSTGRES_URL` →
auto-detect with password from `CONTAINARIUM_POSTGRES_PASSWORD_FILE` /
`CONTAINARIUM_POSTGRES_PASSWORD` / compiled-in dev default.

### Recommended deployment shape

```bash
sudo install -m 0600 -o root -g root \
    <(echo -n "$NEW_PG_PASSWORD") \
    /etc/containarium/postgres.password
```

Set in the daemon's systemd unit:

```ini
Environment="CONTAINARIUM_POSTGRES_PASSWORD_FILE=/etc/containarium/postgres.password"
```

To rotate, update the file in place and restart the daemon. No code
or config change required:

```bash
echo -n "$NEW_PG_PASSWORD" | sudo tee /etc/containarium/postgres.password > /dev/null
sudo chmod 0600 /etc/containarium/postgres.password
sudo systemctl restart containarium
```

The daemon refuses to start if the file is world-readable — same
contract as the JWT token file (Phase C-HIGH-7).

---

## Switching Postgres to unix-socket auth (no password on the wire)

Phase 4.7 deeper half. The daemon's Postgres driver (`pgx`)
already supports unix-socket connections out of the box —
this is purely an operator-configuration change to remove
the password from the connection string entirely, replacing
network authentication with Postgres's filesystem-permission-
based `peer` auth.

Why bother:

- **No shared secret on the wire.** Even with TLS, a
  password is one substitution away from a credential leak;
  unix-socket peer auth removes the secret entirely.
- **Local-only by definition.** Anything that can reach
  `/var/run/postgresql/.s.PGSQL.5432` is already root or in
  the `postgres` group on the host — you've already lost.
- **No password to rotate.** The deeper half of Phase 4.7
  is just: don't have one.

This only applies when Postgres runs **on the same host as
the daemon**. Network-attached Postgres (managed RDS, Cloud
SQL with a sidecar, etc.) keeps the password path.

### Configure Postgres for peer auth

Edit `pg_hba.conf` to permit peer auth from the daemon's
Linux user:

```
# TYPE  DATABASE      USER          ADDRESS  METHOD
local   containarium  containarium           peer
```

Then in `postgresql.conf` confirm the socket directory:

```
unix_socket_directories = '/var/run/postgresql'
```

Restart Postgres to pick up the change:

```bash
sudo systemctl restart postgresql
```

Confirm peer auth works for the daemon's user before
flipping the daemon over:

```bash
sudo -u containarium psql -d containarium -c 'SELECT 1'
```

If that succeeds with no password prompt, peer auth is
live.

### Switch the daemon's connection string

The daemon's connection string DSN supports the
`host=/path` keyword that pgx routes to a unix socket
instead of TCP. Two equivalent forms work:

```bash
# URI form — pass host as a query parameter
CONTAINARIUM_POSTGRES_URL='postgres://containarium@/containarium?host=/var/run/postgresql&sslmode=disable'

# Keyword form
CONTAINARIUM_POSTGRES_URL='user=containarium dbname=containarium host=/var/run/postgresql sslmode=disable'
```

`sslmode=disable` is correct for a unix socket — TLS over
a local filesystem socket is decorative; the socket itself
is the authentication boundary.

Apply via the daemon's systemd `Environment=`:

```ini
Environment="CONTAINARIUM_POSTGRES_URL=postgres://containarium@/containarium?host=/var/run/postgresql&sslmode=disable"
```

Drop any `CONTAINARIUM_POSTGRES_URL_FILE` /
`CONTAINARIUM_POSTGRES_PASSWORD_FILE` from the unit — they
override the URL and would re-add the password path.

Restart:

```bash
sudo systemctl restart containarium
```

Daemon startup log should show:

```
[postgres] DSN source: env
Detected PostgreSQL at: <auto-detect skipped, URL was provided>
```

If you see `Detected PostgreSQL at: 10.100.0.2 (password
source: default)` instead, the URL didn't take — check the
unit for stray `CONTAINARIUM_POSTGRES_*` overrides.

### Verify the password is no longer on the wire

A short loopback `tcpdump` confirms the daemon isn't
opening TCP connections to port 5432:

```bash
sudo tcpdump -i lo -nn -c 5 'tcp port 5432'
# Should produce 0 packets after the daemon has been
# restarted and made a few queries. If it does produce
# packets, the daemon is still using a TCP DSN somewhere.
```

The daemon's queries should now show up as unix-socket
file accesses instead — verifiable via `strace -e connect`
on the daemon PID.

### Rolling back

If anything misbehaves, the rollback is symmetric: restore
the password-bearing URL (or `_FILE`) in the systemd unit,
restart, and Postgres serves both paths concurrently while
`pg_hba.conf` still has the `peer` line. Drop the `peer`
line from `pg_hba.conf` and reload Postgres if you want
to definitively cut off unix-socket access.

---

## Enabling KMS envelope encryption for secrets

Phase 4.1 (audit C-HIGH-6). By default the daemon encrypts
tenant secrets with the master key at
`/etc/containarium/secrets.key`. That's enough for many
deployments but leaves the secret data exposed to anyone
who can read the keyfile (root on the host, backup tapes,
forensic dumps). Envelope encryption moves the protection
into an external KMS — the daemon performs cryptographic
operations through Vault / GCP KMS / etc., never seeing
the master key material directly.

Pick a backend via `CONTAINARIUM_KMS_BACKEND`. Supported:

| Value      | What it does                                     |
| ---------- | ------------------------------------------------ |
| `none`     | Default. No KMS; behaves identically to pre-4.1. |
| `inproc`   | In-process wrap under the master key. Dev/test mostly — protection level is unchanged from legacy, but it writes envelope-shaped rows so a future cutover to a real KMS doesn't re-touch every row. |
| `vault`    | Vault Transit secret engine over HTTP. See setup below. |
| `gcp`      | Google Cloud KMS via the REST API. See setup below. |
| `aws`      | AWS KMS via the REST API (SigV4-signed). See setup below. |

### Vault Transit setup

```bash
# 1. In Vault, mount the transit engine and create a key.
vault secrets enable transit
vault write -f transit/keys/containarium-secrets

# 2. Mint a policy that only allows encrypt + decrypt against
#    the containarium-secrets key — narrowest possible token
#    surface.
cat > containarium-kms-policy.hcl <<EOF
path "transit/encrypt/containarium-secrets" {
  capabilities = ["update"]
}
path "transit/decrypt/containarium-secrets" {
  capabilities = ["update"]
}
EOF
vault policy write containarium-kms containarium-kms-policy.hcl

# 3. Issue a token bound to that policy. For long-lived
#    daemons, prefer Vault Agent (auto-renews) over a static
#    token here.
vault token create -policy=containarium-kms -ttl=720h -format=json | jq -r .auth.client_token \
    | sudo install -m 0600 -o root /dev/stdin /etc/containarium/vault.token

# 4. Configure the daemon. Add to systemd Environment=:
CONTAINARIUM_KMS_BACKEND=vault
CONTAINARIUM_VAULT_ADDR=https://vault.internal:8200
CONTAINARIUM_VAULT_TOKEN_FILE=/etc/containarium/vault.token
CONTAINARIUM_VAULT_TRANSIT_KEY=containarium-secrets
# Optional: CONTAINARIUM_VAULT_TRANSIT_MOUNT=transit (default)
# Optional: CONTAINARIUM_VAULT_TIMEOUT=5s

# 5. Restart the daemon. Confirm the startup log shows:
#    Secrets store ready (file-keyed AES-256-GCM, envelope: vault transit (...))
sudo systemctl restart containarium
```

### Migrating existing legacy rows to envelope

New writes after the daemon restart are envelope-shaped.
Existing legacy rows (`wrapped_dek IS NULL`) still decrypt
fine via the master-key fallback, but should be migrated
so the master key can eventually be retired:

```bash
# Dry run — verifies every legacy row would migrate cleanly
CONTAINARIUM_KMS_BACKEND=vault \
CONTAINARIUM_VAULT_ADDR=https://vault.internal:8200 \
CONTAINARIUM_VAULT_TOKEN_FILE=/etc/containarium/vault.token \
CONTAINARIUM_VAULT_TRANSIT_KEY=containarium-secrets \
containarium secrets migrate-to-envelope --dry-run

# Real run
containarium secrets migrate-to-envelope

# Check progress
containarium secrets envelope-coverage
```

Output of `envelope-coverage` reports total / legacy /
envelope counts. When `legacy = 0`, every row has been
re-wrapped and the master key is no longer required for
decryption (Phase E master-key retirement is then a safe
operator decision).

### Retiring the master key (Phase E)

Once `envelope-coverage` reports `legacy = 0` and the
daemon's reads have run cleanly for long enough to be
confident, the master key file (`/etc/containarium/secrets.key`)
is no longer used for any production decrypt. Phase E
gates the cutover so the legacy path can't accidentally be
re-touched.

```bash
# 1. Confirm 100% envelope coverage. Repeat over a few
#    minutes if writes are ongoing; the count should
#    stabilize at legacy=0.
containarium secrets envelope-coverage

# 2. Add to the daemon's systemd Environment=:
CONTAINARIUM_REQUIRE_ENVELOPE=true

# 3. Restart the daemon. The startup log line now ends
#    "[legacy-rejected]" — that's the confirmation the
#    gate is on.
sudo systemctl restart containarium

# 4. Smoke-test a Get; any legacy row that slipped through
#    the migration surfaces here as an error rather than
#    silently decrypting under the master key.
containarium secrets get <user> <name>

# 5. After a soak period (24h+ recommended for production),
#    remove the master key file. The daemon still loads it
#    at startup — Phase E doesn't yet remove the dependency
#    — but every decrypt path goes through the KMS, so
#    losing the file no longer means losing the data. Keep
#    a backup off-host in case envelope-coverage was wrong.
sudo mv /etc/containarium/secrets.key /etc/containarium/secrets.key.retired
```

If a row WAS missed (because the migrator ran with
`--max-rows` and a chunk was forgotten, or because of a
race during migration), Phase E rejects it with:

```
secret <user>/<name> is legacy-encrypted but
require_envelope=true (run `containarium secrets
migrate-to-envelope` before retiring the master key)
```

Re-run the migration, then retry the Get.

### Rotating the Vault Transit key

```bash
vault write -f transit/keys/containarium-secrets/rotate
```

Existing wrapped DEKs reference the prior key version
(encoded in the `vault:v<n>:...` blob); Vault transparently
decrypts under whichever version each row was wrapped
against. To force re-wrap under the new version:

```bash
# Re-wrap every envelope row through the latest key.
# Idempotent — already-current rows are skipped.
containarium secrets migrate-to-envelope
```

(Rewrap support is a future enhancement; today the migrator
only converts legacy → envelope.)

### GCP Cloud KMS setup

Cloud KMS exposes per-key encrypt / decrypt REST endpoints;
the named CryptoKey is the KEK. The key material never
leaves Google's HSM-backed boundary — the daemon submits
the plaintext DEK and gets back an opaque ciphertext.

```bash
# 1. Create the keyring + key in Cloud KMS. Pick a location
#    in the same region as your daemon to minimize call
#    latency. Algorithm `google-symmetric-encryption` is the
#    one Cloud KMS exposes via :encrypt / :decrypt; rotated
#    versions remain transparently decryptable.
gcloud kms keyrings create containarium \
    --location=us-west1
gcloud kms keys create secrets \
    --location=us-west1 \
    --keyring=containarium \
    --purpose=encryption

# 2. Grant the daemon's service account the narrow IAM role
#    that allows encrypt + decrypt against that one key
#    (NOT Encrypter/Decrypter at project scope — the
#    blast-radius matters).
gcloud kms keys add-iam-policy-binding secrets \
    --location=us-west1 \
    --keyring=containarium \
    --member="serviceAccount:containarium-daemon@$PROJECT.iam.gserviceaccount.com" \
    --role=roles/cloudkms.cryptoKeyEncrypterDecrypter

# 3. Set up token delivery. The daemon expects a static
#    bearer token in CONTAINARIUM_GCP_KMS_TOKEN_FILE; a tiny
#    sidecar refreshes it periodically. On GCE/GKE with
#    workload identity, the metadata server is the source:
#
#    while true; do
#      curl -sH 'Metadata-Flavor: Google' \
#        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
#        | jq -r .access_token \
#        | install -m 0600 /dev/stdin /etc/containarium/gcp-kms.token
#      sleep 1800
#    done
#
#    Off-cloud: have an operator run
#    `gcloud auth print-access-token | sudo tee /etc/containarium/gcp-kms.token`
#    every ~50 minutes (gcloud tokens last 1h). Long-lived
#    deployments should prefer Workload Identity Federation
#    so the file is never stale.

# 4. Configure the daemon. Add to systemd Environment=:
CONTAINARIUM_KMS_BACKEND=gcp
CONTAINARIUM_GCP_KMS_KEY_NAME=projects/$PROJECT/locations/us-west1/keyRings/containarium/cryptoKeys/secrets
CONTAINARIUM_GCP_KMS_TOKEN_FILE=/etc/containarium/gcp-kms.token
# Optional: CONTAINARIUM_GCP_KMS_ENDPOINT (override for
#           private endpoint deployments).
# Optional: CONTAINARIUM_GCP_KMS_TIMEOUT=5s

# 5. Restart the daemon. Confirm the startup log shows:
#    Secrets store ready (file-keyed AES-256-GCM, envelope: gcp cloud kms (key=...))
sudo systemctl restart containarium
```

Migration and Phase E retirement work the same as the Vault
path — `containarium secrets migrate-to-envelope` re-wraps
legacy rows under the GCP KEK; `envelope-coverage` reports
progress; `CONTAINARIUM_REQUIRE_ENVELOPE=true` rejects any
remaining legacy rows.

### Rotating the GCP Cloud KMS key

```bash
gcloud kms keys versions create \
    --location=us-west1 \
    --keyring=containarium \
    --key=secrets \
    --primary
```

Existing wrapped DEKs reference the prior key version (the
version is baked into the ciphertext); Cloud KMS
transparently decrypts under whichever version each row
was wrapped against. To force re-wrap under the new
primary:

```bash
containarium secrets migrate-to-envelope
```

### AWS KMS setup

```bash
# 1. Create a symmetric KMS key and a friendly alias. The
#    key never leaves AWS; the daemon only ever calls
#    Encrypt/Decrypt against it.
KEY_ID=$(aws kms create-key \
    --description "containarium secrets KEK" \
    --query KeyMetadata.KeyId --output text)
aws kms create-alias \
    --alias-name alias/containarium-secrets \
    --target-key-id "$KEY_ID"

# 2. Grant the daemon's IAM principal the narrowest policy:
#    kms:Encrypt + kms:Decrypt against THIS key only (not a
#    wildcard resource — the blast radius matters). Attach
#    to the IAM user / role the daemon runs as, e.g.:
#    {
#      "Effect": "Allow",
#      "Action": ["kms:Encrypt", "kms:Decrypt"],
#      "Resource": "arn:aws:kms:us-west-2:<acct>:key/<KEY_ID>"
#    }

# 3. Deliver credentials. The daemon signs requests with
#    SigV4 from an access-key / secret pair (+ optional
#    session token for STS temp creds). The secret is the
#    sensitive part — keep it 0600 and out of the env where
#    practical:
#
#    On EC2/EKS, an IRSA or IMDS sidecar refreshes temp creds
#    into files the daemon reads:
#      aws sts assume-role ... | jq -r .Credentials.SecretAccessKey \
#        | sudo install -m 0600 /dev/stdin /etc/containarium/aws-kms.secret
#      (and likewise the SessionToken file)
#    Off-cloud: a static IAM user's secret in the file, no
#    session token.

# 4. Configure the daemon. Add to systemd Environment=:
CONTAINARIUM_KMS_BACKEND=aws
CONTAINARIUM_AWS_KMS_REGION=us-west-2
CONTAINARIUM_AWS_KMS_KEY_ID=alias/containarium-secrets
CONTAINARIUM_AWS_ACCESS_KEY_ID=AKIA...
CONTAINARIUM_AWS_SECRET_ACCESS_KEY_FILE=/etc/containarium/aws-kms.secret
# Optional: CONTAINARIUM_AWS_SESSION_TOKEN_FILE=/etc/containarium/aws-kms.session
#           (required when the access key is an STS temp cred)
# Optional: CONTAINARIUM_AWS_KMS_ENDPOINT (override for a
#           VPC endpoint / air-gapped deployment).
# Optional: CONTAINARIUM_AWS_KMS_TIMEOUT=5s

# 5. Restart the daemon. Confirm the startup log shows:
#    Secrets store ready (file-keyed AES-256-GCM, envelope: aws kms (region=... key=...))
sudo systemctl restart containarium
```

Migration and Phase E retirement work the same as the Vault
and GCP paths — `containarium secrets migrate-to-envelope`
re-wraps legacy rows under the AWS KEK; `envelope-coverage`
reports progress; `CONTAINARIUM_REQUIRE_ENVELOPE=true`
rejects any remaining legacy rows.

### Rotating the AWS KMS key

```bash
# Enable annual automatic rotation (recommended):
aws kms enable-key-rotation --key-id alias/containarium-secrets
```

Existing wrapped DEKs reference the prior key material (the
version is baked into the CiphertextBlob); AWS KMS
transparently decrypts under whichever backing key each row
was wrapped against. To force re-wrap under the new primary:

```bash
containarium secrets migrate-to-envelope
```

## Pinning and verifying container image digests

Audit B-HIGH-1. By default Containarium accepts any image
reference the operator passes — including a bare tag like
`images:ubuntu/24.04` that the registry can quietly
re-publish under different bytes tomorrow. Two layered
environment toggles harden that:

| Env var                              | Default | What it does                                                                 |
| ------------------------------------ | ------- | ---------------------------------------------------------------------------- |
| `CONTAINARIUM_REQUIRE_IMAGE_DIGEST`  | `false` | Refuse any image reference that doesn't end with `@sha256:<64 lowercase hex>`. Syntax gate. |
| `CONTAINARIUM_VERIFY_IMAGE_DIGEST`   | `false` | Resolve the alias in the registry's simplestreams index and refuse if the operator-supplied digest doesn't appear there. Content gate. |

The two gates are independent — you can require digests
(syntax) without verifying them (content), but verifying
without requiring is pointless because non-digest
references trivially skip verification. Recommended
deployment: turn on REQUIRE first, soak, then add VERIFY.

The daemon logs a `WARNING` at startup when VERIFY is on
but REQUIRE is off, so this misconfiguration is loud
rather than silent. The configuration is still allowed
(some operators legitimately want "verify when pinned,
but pinning optional"), just flagged.

### Step 1 — find a published digest for an image

`containarium audit` doesn't help here; the digest lives
in the registry's simplestreams index. The handful of
ways to fetch it:

```bash
# A. Curl the simplestreams index directly. Search for
#    the alias under products, then read the per-item
#    sha256 fields. Returns multiple digests per version
#    (rootfs, metadata, combined); ANY of them is
#    acceptable as the operator-supplied digest.
curl -sL https://images.linuxcontainers.org/streams/v1/images.json \
    | jq -r '.products
            | to_entries[]
            | select(.value.aliases | split(",") | map(ltrimstr(" ") | rtrimstr(" ")) | contains(["ubuntu/24.04"]))
            | .value.versions
            | to_entries[]
            | .value.items
            | to_entries[]
            | "\(.value.ftype)\t\(.value.sha256)"'

# B. If you already have a known-good pull on a dev host,
#    read the fingerprint Incus computed.
incus image list --format=json \
    | jq -r '.[] | select(.aliases[]?.name=="ubuntu/24.04") | .fingerprint'
#    Note: Incus's fingerprint is the sha256 of the unified
#    image; it should appear in the simplestreams index
#    above as one of the per-item digests.

# C. From the release-notes / signed digest record the
#    image publisher posts out-of-band. Always the
#    strongest source — the bytes the publisher meant.
```

### Step 2 — turn on REQUIRE

Update each container-create call to pin a digest:

```bash
# Before
containarium create-container --image="images:ubuntu/24.04" ...

# After
containarium create-container \
    --image="images:ubuntu/24.04@sha256:<digest>" \
    ...
```

Then flip the gate in the daemon's systemd
`Environment=`:

```
CONTAINARIUM_REQUIRE_IMAGE_DIGEST=true
```

Restart the daemon. The startup log line includes:

```
[image-digest] required: every CreateContainer must name a `@sha256:<64hex>` digest (audit B-HIGH-1 follow-up)
```

Any operator who tries to create a container without a
digest now gets an InvalidArgument with the exact
malformed image string.

### Step 3 — soak

Watch the daemon log for `image-digest` lines for a
day or two. The common failure modes:

| Error                             | What happened                  | Fix                              |
| --------------------------------- | ------------------------------ | -------------------------------- |
| "missing a digest"                | An automation forgot to pin    | Pin it; re-run                   |
| "invalid digest"                  | Hand-typed typo                | Re-copy the 64-hex string        |
| "expected `sha256:` + 64 lowercase hex" | Uppercase / wrong algo  | Lowercase; ensure sha256 not sha384/sha512 |

When the log is quiet of these for a soak period, you're
ready for content verification.

### Step 4 — turn on VERIFY

Add to the daemon's systemd `Environment=`:

```
CONTAINARIUM_VERIFY_IMAGE_DIGEST=true
```

Restart. The startup log line includes:

```
[image-digest] registry verification ENABLED: every `@sha256:` digest is checked against the registry's published index before pull (audit B-HIGH-1 Phase B)
```

From this point, every CreateContainer with a digest
will:

1. Resolve the (server, alias) from the image string.
2. Fetch `streams/v1/images.json` from the registry.
3. Match the supplied digest against the union of all
   per-item sha256 values published for the alias.
4. Reject with FailedPrecondition if no match.

Pre-pull, fail-fast, no bandwidth wasted, no partial
container state to clean up.

### Soak-mode rollout pattern (optional but recommended)

Production deployments serving real tenants should
**not** flip from "off" to "on" in one step — a typo in
a single CreateContainer payload becomes a tenant
outage. Instead:

1. **Audit-only soak.** Leave VERIFY off; periodically
   re-resolve every tenant's pinned digest against the
   registry index via a small script (cron + the
   `curl | jq` recipe above) and alert on misses. Run
   for 1-2 weeks.
2. **Single-tenant pilot.** Flip VERIFY on for a single
   non-critical tenant's dedicated daemon. Confirm pulls
   still work end-to-end.
3. **Fleet rollout.** Roll the gate out one daemon at a
   time, watching the daemon log for `registry digest
   verification` errors.

### Troubleshooting

```
registry digest verification: fetch https://images.linuxcontainers.org/streams/v1/images.json for "ubuntu/24.04": ... (timeout|conn refused|TLS error)
```

The registry index is unreachable. The gate fails closed
(rejects the create) rather than skipping verification.
Diagnose:

```bash
# Is the daemon's network path to the registry healthy?
sudo -u containarium curl -fsSI \
    https://images.linuxcontainers.org/streams/v1/images.json
```

Temporary mitigations:
- Flip VERIFY off in systemd Environment and restart while
  you fix DNS / TLS / network — REQUIRE stays on, so
  operators still need to pin a digest.

```
registry digest verification: alias "ubuntu/24.04" not found in https://images.linuxcontainers.org/streams/v1/images.json
```

The alias doesn't resolve to any product in the index.
Causes:
- Typo (the alias is case-sensitive)
- Recently-removed product (registry retired the alias)
- Stale index cache somewhere up the network path

Diagnose: re-run the Step 1 curl recipe and look for the
alias under `aliases:`.

```
registry digest verification: image "..." declares <X> but the registry at <server> publishes a different set of digests for alias "..."
```

The alias resolves but the digest doesn't. This is the
case the gate exists to catch:
- The image was re-published with new bytes; your pinned
  digest is stale. Update to the current digest if you
  trust the new bytes.
- The registry has been compromised. **DO NOT** update
  the pin until you've independently verified the new
  bytes (e.g. from the release-notes record).
- The daemon's view of the registry has been MITM'd.
  Investigate TLS / DNS for the daemon's outbound path.

### Index caching

The resolver caches each registry's `streams/v1/images.json`
for 5 minutes by default. A fleet rollout that creates
50 containers against `images.linuxcontainers.org` in
quick succession collapses into a single index fetch.

The TTL is short enough that a freshly-published image
becomes verifiable within one pull cycle. If you've just
published a new image and want the daemon to see it
immediately, restart the daemon (clears the in-process
cache).

### Post-pull defense-in-depth (Phase C)

When VERIFY is on, Containarium also re-checks the image
*after* the pull. It reads the Incus-computed fingerprint
from `volatile.base_image` and asserts it matches the
operator's declared digest (with a registry-side
"two faces of the same image" reconciliation step for the
common case where the operator pinned one item type and
Incus stored a different one).

A mismatch deletes the just-created container and returns
`FailedPrecondition` — the attacker's payload doesn't get
to run.

Practically: Phase B (pre-pull) catches a compromised
registry; Phase C (post-pull) catches local-store
tampering between pull and start. Both run for free when
VERIFY is on.

### Limits
- The combined gates do NOT catch registry-account
  compromise where the attacker pushes new bytes AND
  updates the index. Only out-of-band digest custody
  (signed release records, the publisher's own
  announcement) catches that class.
- Containers created via non-simplestreams paths (e.g.,
  snapshot copy, image import) have no
  `volatile.base_image` and skip the Phase C check;
  Phase B still runs if VERIFY is on and the image string
  carries a `@sha256:`.

## Locking down `/wake/` to a known load balancer

The wake-on-HTTP handler (Phase 1.9) is reachable on the daemon's
public HTTP port. Without an explicit allowlist, any source can
trigger a container wake by crafting the `Host` header. In production
where Caddy lives on the same host as the daemon, loopback is always
trusted — but operators with off-host Caddy / GLB / sentinel paths
should pin the source:

```bash
# Set in the daemon's systemd Environment=
CONTAINARIUM_WAKE_TRUSTED_PROXIES=10.0.0.0/8,192.168.1.5,fd00::/8
```

The handler rejects any source not in the allowlist with `403 wake:
source not permitted`. Wildcard `/0` prefixes are explicitly refused
at load — defeating the gate would be worse than turning it off.

If `CONTAINARIUM_WAKE_TRUSTED_PROXIES` is unset and Caddy is NOT on
the same host, you'll see the startup `WARNING` log line and every
non-loopback source will be accepted (pre-1.9 behavior). Setting the
env var is the safe default.

---

## Pinning per-tenant network policy

Per-tenant network isolation (eBPF, #315) fences what a tenant's containers can
reach: deny-by-default container-to-container traffic plus an egress allow-list
by CIDR and domain, enforced at each container's host veth. Design detail:
[`NETWORK-ISOLATION-DESIGN.md`](NETWORK-ISOLATION-DESIGN.md). It is **off unless
you opt in**, and dropping is a **second** opt-in on top of that — so rolling it
out can never silently cut a tenant off.

### The two opt-ins

```bash
# Set in the daemon's systemd Environment= (or EnvironmentFile), then restart.

# 1. Enable the enforcer — OBSERVE only. Resolves policies, attaches the BPF
#    program, audits would-deny flows. Drops NOTHING.
CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=/etc/containarium/netpolicy.bpf.o

# 2. Arm enforcement — only now does `--mode enforce` actually drop. Without
#    this, a stored enforce policy stays observation-only.
CONTAINARIUM_NETWORK_POLICY_ENFORCE=1
```

Build the object once per backend (kernel ≥ 6.6 for TCX) from
`experimental/ebpf-phaseA/netpolicy.bpf.c`:

```bash
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
    -c netpolicy.bpf.c -o /etc/containarium/netpolicy.bpf.o
```

### Authoring a policy

```bash
# Allow only the listed egress; deny everything else (incl. other tenants).
containarium network-policy set alice \
    --egress-cidr 10.0.0.0/8 \
    --egress-domain api.github.com \
    --allow-intra-tenant \
    --mode log_only          # start in log_only — see the soak workflow below

containarium network-policy get alice
containarium network-policy list
```

A container is matched to its tenant by the `<tenant>-container` name; a
container whose tenant has **no** policy is left in log_only (never dropped), so
enabling enforcement only affects tenants you've written a policy for.

### Soak before you arm (the safe rollout)

Enforcement is only as good as the allow-list, and an allow-list that forgets a
dependency will **break the tenant** once armed. So soak first:

1. Set the policy with `--mode log_only` and enable opt-in #1 (not #2).
2. Run the tenant's normal workload and watch the daemon log for the flows that
   *would* be denied:
   ```bash
   journalctl -u containarium -f | grep '\[netpolicy\] deny:'
   # deny: tenant="alice" src=… dst=140.82.112.3 proto=6 dport=443 log_only (not dropped)
   ```
   These are also audit rows — `action=network_policy.deny_logged`:
   ```bash
   containarium audit query --action network_policy.deny_logged --limit 200
   ```
3. For every legitimate destination, add it to the allow-list (`--egress-cidr` /
   `--egress-domain`). **Include the tenant's DNS resolver / bridge gateway** —
   an enforce policy that omits its resolver blackholes the container (name
   resolution itself is egress). Re-run `set` until the would-deny stream is
   empty for normal operation.
4. Flip the policy to `--mode enforce` and set opt-in #2. Denied flows now drop,
   audited as `action=network_policy.deny_dropped`:
   ```bash
   containarium audit query --action network_policy.deny_dropped --limit 200
   ```

`--mode enforce` and `--mode log_only` can be flipped per tenant at any time; you
can keep some tenants observing while others enforce.

### Cloud metadata is denied by default

The metadata service (`169.254.169.254`) hands out instance credentials and is
**denied even if your egress allow-list would otherwise cover it** (including a
broad `0.0.0.0/0`). A tenant that genuinely needs instance metadata must opt in
explicitly:

```bash
containarium network-policy set alice --allow-metadata …
```

### Removing a policy

```bash
containarium network-policy delete alice
```

The container drops back to log_only on the next reconcile (≤ a few seconds);
the egress map entries are pruned automatically.

---

## Auditing recent administrative actions

Every authenticated request lands in the `audit_logs` table (Phase
4.5) with timestamp, username, action, resource, source IP, and
optional detail. The CLI can query directly:

```bash
# Everything an admin did in the last hour
containarium audit query \
    --username ops --from "$(date -u -d '1 hour ago' --iso-8601=seconds)" \
    --limit 100

# All token revocations this month
containarium audit query \
    --action token_revoke \
    --from "$(date -u -d '1 month ago' --iso-8601=seconds)" \
    --limit 200
```

The detail column carries the `jti`, request payload summary, and any
audit-relevant context. **Tenant secrets values are scrubbed** by the
`internal/audit/redact.go` redactor before write — operators reading
the table never see plaintext credentials.

---

## Verifying the audit-log hash chain

Each row's `row_hash` is a SHA-256 of its content + the previous
row's hash (Phase 4.5). A tampered or inserted row breaks the chain
at that point. The daemon does NOT auto-verify on every read; ops
runs the verifier when forensics are needed:

```bash
# Verify from the chain start
containarium audit verify

# Verify from a specific row ID (faster for large tables)
containarium audit verify --from-id 100000
```

The verifier reports the row ID where the chain breaks, or "intact"
when every row's `row_hash` recomputes to its stored value.

If the chain is broken:

1. Note the `firstBad` ID. Everything before it is trusted; the row
   at `firstBad` and everything after are suspect.
2. Pull recent operator-shell history on the daemon host — only
   someone with database write access to `audit_logs` can break the
   chain, and that's a small list.
3. Restore the table from the most recent verified backup (the
   chain root from the backup is the authoritative "good" state).

---

## References

- [Vulnerability disclosure policy](../../SECURITY.md)
- [Zero-trust audit findings](ZERO-TRUST-AUDIT.md) — engineering detail
- [Zero-trust remediation status](ZERO-TRUST-TODO.md) — phase tracker
- [Phase 0 operator runbook](PHASE-0-OPERATOR-RUNBOOK.md) — bootstrap
  steps for a fresh deployment (mTLS, sentinel HMAC, peer CA)
- [Container env-var introspection risk](SECRETS-ENV-VAR-RISK.md) —
  what stamping secrets via env actually exposes
