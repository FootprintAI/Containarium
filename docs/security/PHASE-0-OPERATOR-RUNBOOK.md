# Phase 0 Operator Runbook

This runbook covers the operational mechanics of the zero-trust
security layers shipped in PRs #227–230. It's the missing piece for
deploying, rotating, and troubleshooting those layers in
production.

If you're reading the audit doc and want to see *what* changed,
start with [ZERO-TRUST-AUDIT.md](./ZERO-TRUST-AUDIT.md) and the
phase-tracked [ZERO-TRUST-TODO.md](./ZERO-TRUST-TODO.md). This
document is *how* to operate them.

---

## What you've got

Four security layers, each with its own configuration knob and
failure mode. They stack — each builds on the previous.

| Layer | What it protects | Configured via | Default if unset |
|---|---|---|---|
| **JWT subject + role** (#227) | Per-tenant API authorization (IDOR fix) | Always on | n/a — code path is unconditional |
| **HMAC on sentinel endpoints** (#227 / 0.4) | `/authorized-keys`, `/certs`, `/sentinel/peers` signature | `CONTAINARIUM_SENTINEL_AUTH_SECRET` | endpoints return 401 (fail-closed); discovery accepts unsigned with WARNING (rollout) |
| **Peer-CA mTLS** (#229 / 0.5) | Peer-to-peer HTTPS confidentiality + integrity | `CONTAINARIUM_CA_KEY_FILE`  + `CONTAINARIUM_SENTINEL_URL=https://…:8889` | plain HTTP between peers |
| **Signed `/sentinel/peers`** (#228 / 0.6) | Peer-discovery response integrity | Uses `CONTAINARIUM_SENTINEL_AUTH_SECRET` | unsigned, daemons log WARNING and accept |

Terraform module variables (set in `terraform.tfvars`):

- `sentinel_auth_secret` (sensitive) — the shared HMAC secret. 32+
  bytes. Empty leaves the audit-known vulnerabilities open.
- `enable_peer_mtls` (bool, default `false`) — opt-in for Phase
  0.5. When `true`, sentinel auto-generates the CA key on first
  boot; spot daemons get a HTTPS sentinel URL.

---

## Bootstrap — fresh deployment

For a brand-new fleet (no daemons running yet).

### 1. Generate secrets

```bash
# Shared HMAC secret (used by all daemons + sentinel)
openssl rand -base64 48
# → e.g.  vQc4hC9D1nzM2Lo4...

# JWT signing secret (used by daemon to sign user tokens)
openssl rand -base64 48
# → distinct from the HMAC secret
```

Stash both in your secret manager (Vault, Doppler, env-encrypted
tfvars). Don't paste them into Slack or commit them.

### 2. Set tfvars

```hcl
# terraform.tfvars
sentinel_auth_secret = "vQc4hC9D1nzM2Lo4..."  # the HMAC secret
jwt_secret           = "h4Yj9...kWp+"        # the JWT secret
enable_peer_mtls     = true                  # turn on Phase 0.5

# Existing required fields stay as-is:
# project_id, instance_name, zone, etc.
```

### 3. Apply

```bash
terraform apply
```

What happens on the first boot:

1. **Sentinel VM startup script** (`startup-sentinel.sh`):
   - Writes `/etc/containarium/env.secrets` (mode 0600) containing
     `CONTAINARIUM_SENTINEL_AUTH_SECRET=<hmac>`.
   - Generates `/etc/containarium/ca.key` (RSA-4096, mode 0400)
     via `containarium pki generate-ca`.
   - Drops `/etc/systemd/system/containarium-sentinel.service.d/secrets.conf`
     with `EnvironmentFile=-/etc/containarium/env.secrets` and
     `Environment=CONTAINARIUM_CA_KEY_FILE=/etc/containarium/ca.key`.
   - Restarts `containarium-sentinel`.

2. **Spot daemon VM startup script** (`startup-spot.sh`):
   - Writes `/etc/containarium/env.secrets` with both the HMAC
     secret and `CONTAINARIUM_SENTINEL_URL=https://<sentinel-ip>:8889`.
   - Drops the systemd `secrets.conf` drop-in.
   - Restarts `containarium`.

3. **Daemon's `BootstrapPKI`** runs at startup:
   - HMAC-signed POST to `https://<sentinel>:8889/sentinel/peer-cert`
     (InsecureSkipVerify bootstrap, no CA yet).
   - Receives leaf cert + key + CA bundle; pins CA for future
     calls.
   - Logs `[peer-pki] bootstrap complete; <N> peer client(s) upgraded to HTTPS`.

4. **Renewal loop** starts a background watcher; renews at 1/3 of
   the 7-day leaf TTL (≈ every 2d 8h).

### 4. Verify (see "Verification" section below)

---

## Rollout — existing fleet upgrade

For a fleet already running an earlier daemon. Land the layers one
at a time so a single bad config doesn't blackhole the fleet.

### Step A: Enable HMAC only (Phase 0.4 / 0.6)

1. Set `sentinel_auth_secret` in tfvars. Leave `enable_peer_mtls = false`.
2. `terraform apply`. Sentinel + spot daemon both pick up the
   secret on next boot.
3. Daemons start logging signed-discovery activity; sentinel
   endpoints start returning 200 on signed requests.
4. **Watch the daemon logs** for `[peers] CONTAINARIUM_SENTINEL_AUTH_SECRET is unset` — those nodes need the env var rolled to them.

### Step B: Enable peer mTLS (Phase 0.5)

1. After all daemons report no "unset" warnings, flip
   `enable_peer_mtls = true` in tfvars.
2. `terraform apply`. Sentinel generates `ca.key` on its next
   boot; spot daemons get the HTTPS sentinel URL on theirs.
3. Daemon logs show `[peer-pki] bootstrap complete` after the
   sentinel is up and reachable on `:8889`.

### Step C: Retire the rollout fallbacks

Once 100% of nodes are on the new env, drop the rollout-friendly
branches in code that still accept unsigned responses:

- `internal/server/peer.go` `discover()` — the `else { log.Printf("rollout mode...") }` branch can become `return` (fail-closed).
- `internal/sentinel/binaryserver.go` — the HTTP listener on 8888 can be removed once nothing connects to it (track with `journalctl -u containarium-sentinel | grep 8888`).

These changes are separate PRs, intentionally deferred so an
operator can roll back at any step.

---

## Rotation

### Rotating the HMAC secret

The shared secret powers both directions: sentinel signs the
`/sentinel/peers` response with it; daemons sign their outbound
calls (`/authorized-keys`, `/certs`, `/sentinel/peer-cert`) with
it. A mismatched secret produces 401s on the daemon side and
"signature verify failed" on the sentinel side.

**Procedure** (rolling, ≈ 30 s of warnings):

```bash
# 1. Generate the new secret.
NEW_SECRET=$(openssl rand -base64 48)

# 2. Update tfvars + apply.
#    Terraform will rewrite /etc/containarium/env.secrets on both VMs
#    and restart the daemon + sentinel via the systemd drop-in.
terraform apply

# 3. Verify both sides on the new value.
gcloud compute ssh sentinel-vm -- 'sudo journalctl -u containarium-sentinel -n 50 | grep -i "sentinel auth\|hmac"'
gcloud compute ssh spot-vm     -- 'sudo journalctl -u containarium         -n 50 | grep -i "sentinel.*signed\|verify"'
```

Brief warnings during the rolling restart are expected — daemons on
the old secret call sentinel on the new (or vice versa) — but
should clear within a minute as both sides converge.

### Rotating the peer-CA (`ca.key`)

The CA key signs every peer leaf cert. Replacing it forces every
daemon to re-bootstrap and re-issue, which the renewal loop does
automatically within the 7-day leaf TTL window — but you can
shortcut to ≈ minutes by restarting daemons.

**Procedure**:

```bash
# 1. SSH into the sentinel.
gcloud compute ssh sentinel-vm

# 2. Move the old key aside (don't delete — emergency rollback).
sudo mv /etc/containarium/ca.key /etc/containarium/ca.key.prev
# 3. Generate a fresh one.
sudo /usr/local/bin/containarium pki generate-ca | sudo tee /etc/containarium/ca.key >/dev/null
sudo chmod 0400 /etc/containarium/ca.key
sudo chown root:root /etc/containarium/ca.key

# 4. Restart the sentinel so it builds a fresh CA cert from the new key.
sudo systemctl restart containarium-sentinel

# 5. (Optional) Force-renew daemon certs immediately by restarting them
#    in a controlled order — the renewal loop would do this on its own
#    within ≈ 2d 8h.
gcloud compute ssh spot-vm -- 'sudo systemctl restart containarium'
```

Back the new `ca.key` up to off-host storage **immediately**.
Losing it leaves your fleet stranded — without the key, the
sentinel can't issue replacement leaf certs after their 7-day TTL
elapses.

### Rotating the JWT signing secret

Same pattern as HMAC. Update tfvars, apply, restart. Note that
existing tokens issued under the old secret become invalid
instantly — coordinate with anyone holding long-lived tokens
(human operators, automated jobs).

---

## Verification

Run these to confirm each layer is actually on.

### 1. HMAC sentinel endpoints (Phase 0.4)

```bash
# Hit /authorized-keys WITHOUT a signature — must get 401.
curl -ksI https://sentinel:8889/authorized-keys | head -1
# Expect: HTTP/1.1 401 Unauthorized

# Hit it WITH a signature — use a signed test request from a daemon host:
gcloud compute ssh spot-vm -- 'curl -ksI \
  -H "X-Containarium-Sentinel-Ts: $(date +%s)" \
  -H "X-Containarium-Sentinel-Sig: $(echo -n "GET\n/authorized-keys\n$(date +%s)" | openssl dgst -sha256 -mac HMAC -macopt key:$(cat /etc/containarium/env.secrets | grep AUTH_SECRET | cut -d= -f2-) | cut -d" " -f2)" \
  https://sentinel:8889/authorized-keys' | head -1
# Expect: HTTP/1.1 200 OK
```

(In practice the daemon code does this signing for you — the
manual curl is just for verification.)

### 2. Peer-CA bootstrap (Phase 0.5)

```bash
# On the daemon VM, look for the bootstrap line in startup logs.
gcloud compute ssh spot-vm -- 'sudo journalctl -u containarium | grep peer-pki | head -5'
# Expect: [peer-pki] received leaf cert for "...", expires ... (in ...)
#         [peer-pki] bootstrap complete; N peer client(s) upgraded to HTTPS
#         [peer-pki] renewal watcher started; next cert expires ...

# Confirm cert files exist on the daemon (if PersistPeerPKI is in use):
gcloud compute ssh spot-vm -- 'sudo ls -la /etc/containarium/'
# Expect: ca.crt, peer.crt (rw-r--r--), peer.key (rw-------) — or in /tmp depending on config.
```

### 3. Signed `/sentinel/peers` response (Phase 0.6)

```bash
# Probe the sentinel's peers endpoint and inspect the signature headers.
curl -ks https://sentinel:8889/sentinel/peers -o /dev/null -D-
# Expect:
#   X-Containarium-Sentinel-Ts:  <unix-seconds>
#   X-Containarium-Sentinel-Sig: <64-hex-chars>
```

Daemon-side, look for the verify result:

```bash
gcloud compute ssh spot-vm -- 'sudo journalctl -u containarium | grep -i "discovery\|peers]"'
# Healthy:
#   [peers] discovered new peer: tunnel-... pool="..." via https://...
# Vulnerable (no HMAC secret configured on daemon):
#   [peers] CONTAINARIUM_SENTINEL_AUTH_SECRET is unset — accepting unsigned discovery response (vulnerable to C-CRIT-2 until configured)
# Bad (mismatched secret):
#   [peers] discovery signature verify failed; refusing to update peer map (set CONTAINARIUM_SENTINEL_AUTH_SECRET on the sentinel to match the daemon's)
```

---

## Troubleshooting

### Symptom: daemon won't start — `JWT secret is N bytes, want >=32`

Phase 1.3 fail-closed. The configured JWT secret is too short for
HMAC-SHA256. Regenerate with `openssl rand -base64 48` (which gives
~64 bytes after encoding) and update tfvars.

### Symptom: MCP client errors with `JWT file has insecure permissions 0644`

Phase 1.8 fail-closed. The JWT token file isn't mode 0600.

```bash
chmod 0600 /path/to/jwt-file
```

### Symptom: daemon log shows `[peer-pki] bootstrap failed (...)`

Common causes:

- **`HMAC secret unavailable`** — `CONTAINARIUM_SENTINEL_AUTH_SECRET` is unset on this daemon, or it's < 32 bytes. Fix the env file and `systemctl restart containarium`.
- **`POST /sentinel/peer-cert: ...connection refused`** — sentinel's HTTPS listener isn't up. Check `enable_peer_mtls = true` in tfvars and that `journalctl -u containarium-sentinel | grep HTTPS` shows the listener started.
- **`peer CA not configured on this sentinel`** (503) — sentinel saw `CONTAINARIUM_CA_KEY_FILE` unset or unreadable. SSH to sentinel and check `ls -la /etc/containarium/ca.key`. Regenerate if missing.
- **TLS handshake errors** — clock skew between sentinel and daemon > 5 min. NTP sync both VMs.

### Symptom: sentinel log shows `WARNING: CONTAINARIUM_CA_KEY_FILE=... is unreadable`

The file path is set but the file doesn't exist or perms are wrong.
Re-run the bootstrap step (`containarium pki generate-ca > /etc/containarium/ca.key; chmod 0400`) and restart sentinel.

### Symptom: daemon log shows `discovery signature verify failed`

HMAC mismatch between sentinel and this daemon. Make sure both
`/etc/containarium/env.secrets` files have the *same*
`CONTAINARIUM_SENTINEL_AUTH_SECRET` value. The Terraform module
guarantees this if both VMs read from the same `sentinel_auth_secret`
variable; manual drift indicates someone edited a file out-of-band.

### Symptom: existing tokens stop working after upgrade to PR #231

Phase 1.1 added `iss` + `aud` validation. Tokens minted with the
old binary don't carry these claims (well, they have `iss` but not
`aud`). Re-issue via `containarium token generate ...` — the new
binary stamps both. Old tokens stay rejected until they expire
naturally (30-day default).

### Symptom: token mismatch across staging/prod

Phase 1.1 ties each token to its issuing deployment's `iss` +
`aud`. A token from staging won't validate against prod. This is
intentional — defense against accidental cross-environment reuse.
If you need a cross-environment service token, override
`CONTAINARIUM_JWT_AUDIENCE` to a shared value on both sides
(rarely a good idea).

### Symptom: keysync / certsync errors after deploy

The sentinel's `keysync` and `certsync` use the HMAC infrastructure
to authenticate to the daemon. If you see 401s in
`containarium-sentinel` logs:

```bash
# Check both sides have the secret loaded.
gcloud compute ssh sentinel-vm -- 'sudo systemctl show containarium-sentinel | grep Environment'
gcloud compute ssh spot-vm     -- 'sudo systemctl show containarium         | grep Environment'
```

Both should reference `EnvironmentFile=-/etc/containarium/env.secrets`. If only one does, the systemd drop-in didn't get written on that VM — re-run the startup script or `terraform taint` the VM to force a rebuild.

---

## Disaster scenarios

### Lost the CA key

If `/etc/containarium/ca.key` is gone and there's no off-host
backup:

1. Sentinel restart still works (it'll log `CONTAINARIUM_CA_KEY_FILE
   is unset — Phase 0.5 HTTPS/mTLS disabled`).
2. Existing daemon leaf certs continue to work until their 7-day
   TTL expires.
3. When the TTL expires, daemons can't re-issue and peer-to-peer
   HTTPS breaks. Falls back to plain HTTP until a new CA is
   bootstrapped.
4. Mitigation: bootstrap a new CA (`containarium pki generate-ca`)
   and restart daemons to force re-bootstrap.

**Prevention**: write the CA key to an off-host secure store
(Vault, GCP Secret Manager) on first boot. The startup script can
optionally upload it.

### Compromised CA key

If you suspect `ca.key` has leaked:

1. Generate a new CA key (rotation procedure above).
2. Restart all daemons to force them to fetch new leaf certs
   under the new CA.
3. Old leaf certs signed by the previous CA stop being trusted as
   soon as daemons swap their pinned CA.
4. There's no CRL, so an attacker holding old leaf certs can't
   validate against the new CA. The window of validity for any
   leaked cert is bounded by the 7-day TTL.

### Compromised HMAC secret

1. Rotate immediately (rotation procedure above).
2. After rotation, any captured-but-not-yet-replayed signed
   requests become invalid (timestamp window is ±5 min, and the
   signature is over the new secret).
3. Consider also rotating the JWT secret if the HMAC secret was
   stored alongside it.

---

## Quick reference — env vars

| Variable | On | Purpose | Default |
|---|---|---|---|
| `CONTAINARIUM_SENTINEL_AUTH_SECRET` | sentinel + daemon | HMAC secret (Phase 0.4/0.6) | unset → audit-vulnerable |
| `CONTAINARIUM_CA_KEY_FILE` | sentinel | Path to peer-CA private key | unset → HTTPS off |
| `CONTAINARIUM_SENTINEL_URL` | daemon | Where the daemon reaches the sentinel | `http://<sentinel>:8888` |
| `CONTAINARIUM_SENTINEL_HTTPS_PORT` | sentinel | Override HTTPS listener port | port+1 (=8889) |
| `CONTAINARIUM_SENTINEL_CERT_SANS` | sentinel | Extra DNS SANs on sentinel server cert | localhost, containarium-sentinel |
| `CONTAINARIUM_JWT_TOKEN` / `CONTAINARIUM_JWT_TOKEN_FILE` | MCP client | JWT for REST calls | required for MCP |
| `CONTAINARIUM_JWT_AUDIENCE` | daemon | Override default token audience | `containarium-api` |
| `CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS` | daemon | Clamp on token TTL | 720 (30 days) |

---

## Quick reference — file paths

| File | Owner | Mode | Purpose |
|---|---|---|---|
| `/etc/containarium/ca.key` | root | 0400 | Peer-CA private key (RSA-4096) |
| `/etc/containarium/env.secrets` | root | 0600 | EnvironmentFile loaded by systemd |
| `/etc/containarium/jwt.secret` | root | 0600 | JWT signing secret |
| `/etc/systemd/system/containarium.service.d/secrets.conf` | root | 0644 | Loads env.secrets on daemon |
| `/etc/systemd/system/containarium-sentinel.service.d/secrets.conf` | root | 0644 | Loads env.secrets on sentinel |
