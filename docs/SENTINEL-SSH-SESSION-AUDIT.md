# Sentinel SSH session audit

Every SSH connection into the platform is accepted by the sentinel's `sshpiperd`, the only place a client's key or certificate is verified. This page covers how those logins reach the tamper-evident audit store, how long they are kept, how an operator sets it up, and the procedure an auditor can run to check them. It is the evidence behind ISO/IEC 27001:2022 A.8.15 in [ISO27001-COMPLIANCE.md](ISO27001-COMPLIANCE.md). The design is in [architecture/sentinel-ssh-session-audit-ingest.md](architecture/sentinel-ssh-session-audit-ingest.md).

## How it works

```
sshpiperd ──► ssh-session-plugin ──► /var/log/containarium/ssh-sessions.jsonl   (local, rotated)
                                              │
                          shipper (inside `containarium sentinel`)
                                              │  one batch per backend, only after OK
                                              ▼
                       backend: AuditService.IngestSSHSessionRecords
                                              │
                                  audit_logs (hash-chained, anchored)
```

- The plugin appends one JSON line when a session opens and one when it closes (client IP and port, login, routed target, credential identity, close reason). It records connection metadata only, never session content.
- With `ssh-authz-plugin --ssh-authz-enforce`, the authorization plugin routes the connection itself, so `ssh-session-plugin` never sees the credential. The authorization plugin then writes the `open` and `close` lines, with the same fields, to the same file, and `ssh-session-plugin` writes nothing for a connection whose credential it did not see. Each session is still recorded once. See [SENTINEL-SSH-AUTHZ.md](SENTINEL-SSH-AUTHZ.md).
- The shipper runs inside the sentinel process. It sends each record to the audit store of the **backend that the login was routed to**, because each backend owns its own audit database. It remembers its position in a checkpoint file and moves it forward only after the backend confirms a batch, so a crash or restart loses and duplicates nothing. The backend also deduplicates per session and phase.
- Rows are written as `ssh_session_open` and `ssh_session_close`, with `resource_type=ssh_session` and the session id as the resource id. They join the same hash chain and external anchoring (#1706) as every other audit row.

### SSH authorization metadata

Authorization denials use JSONL phase `denied`, wire phase
`SSH_SESSION_PHASE_DENIED`, and audit action `ssh_session_denied`.
Authorization metadata travels through the same shipper and ingest RPC as
the existing open/close records:

| Field | Meaning |
|-------|---------|
| `user_id` | Resolved user identity when known; distinct from the SSH target login |
| `authz_decision` | Typed `SSHAuthzDecision` value from the authorization check |
| `deny_reason` | Typed `SSHDenyReason` value, such as unknown key or inactive user |
| `enforced` | Whether `ssh-authz-plugin` ran in enforce mode for this record. An `open`/`close` row can carry `enforced=true` with an `UNSPECIFIED` decision for either of two reasons: (1) the plugin admitted the session without asking the daemon (a certificate); or (2) the session's pending decision was evicted from the plugin's bounded stash (10,000 entries) by a flood of routed queries between the connection's query and its pipe. Case 2 has an empty auth method and no credential, and its `target` is a fresh read of the sshpiper config, not the route taken at accept time. Neither reads as an allow: the decision is `UNSPECIFIED` (0), not `ALLOW`. The plugin logs `no pending decision (evicted from the bounded stash)` for case 2 |

The JSONL sink and audit detail encode the protobuf enums as numeric JSON
values; generated protobuf JSON transports may use the symbolic enum names.
For example, decision `2` is `SSH_AUTHZ_DECISION_DENY`, and reason `1` is
`SSH_DENY_REASON_UNKNOWN_KEY`.

In audit-only mode a denial decision does not necessarily block login. An
`open` record can therefore carry `DENY` with `enforced=false`. If a denied
record and an open record share a session id, both are retained: idempotency
is keyed on `(session_id, phase)`, not session id alone. Replaying the same
phase returns `DUPLICATE` without another audit row. The existing orphan-close
suffix is unchanged.

Pre-upgrade JSONL records without these fields remain readable and shippable.
Their user identity stays empty, authorization enums remain `UNSPECIFIED`,
and enforcement defaults to false. Those defaults mean the authorization
metadata was not recorded; they must not be interpreted as an explicit ALLOW.
Default-valued fields may be omitted from JSONL and audit detail.

### Failed authentications and bans

A failed login never opens a session, so it is not in the session records above. The sentinel's `ssh-ban-plugin` already counts failures per source IP for banning; with `--records-file` it also writes what it counts into the same JSONL sink, and the same shipper delivers it. (Terraform: `ssh_ban_audit_records = true`; see the rollout note below.)

| Audit action | Written | Detail |
|--------------|---------|--------|
| `ssh_auth_failed` | Once per source IP when its ban window ends with failures below the ban budget | `failure_count`, `ban_listener`; the source IP is the row's `source_ip` |
| `ssh_banned` | Once per ban, when the source reaches the budget | `failure_count`, `banned_until` (UTC), `ban_listener` |
| `ssh_auth_failed` with no source IP | At most once a minute, when the cap below was reached | `suppressed_count`: failures from other sources that were not written one by one |

These rows have no login, target or credential, because no session existed. They are never written for exempt sources (`--ignore-ip`).

- **Which backend gets them.** A failed attempt has no routed backend, so these records go to the sentinel's `--ssh-session-default-backend`, the same destination as any record whose login routes nowhere. **Without a default backend these records are skipped with a warning** (counted as unroutable), exactly like any other record whose login routes nowhere, so set it before enabling this.
- **Volume.** One record per source IP per window, not one per failure. At most `--audit-max-records-per-minute` (default 600) of those are written each minute; further sources in that minute are folded into the one overflow row, so a distributed scan stays visible as a count. Bans are never capped: each takes `--max-failures` failures from one source, so an attacker pays for every ban row. The plugin only enqueues from the authentication path and never waits on disk; if its queue fills, the dropped failures also count into the overflow row.
- **Timing.** The summary is written when the window ends (a timer ends finished windows once a minute even when no one connects), so it can lag the failures by up to the ban duration (5 minutes by default). A ban row is written as soon as the budget is reached.
- **Rotation.** The ban plugin reopens `--records-file` on `SIGHUP`, and the module's logrotate stanza signals it. `SIGHUP` still never clears bans.
- **Rollout.** Upgrade in this order: (1) the **backends** (the default backend at least), because an older backend rejects the new record types as invalid and the shipper then stops shipping to it, retrying and logging, until it is upgraded; (2) the sentinel's `containariumd`, because the `--records-file` flag exists only in a build that includes #2419 and an older binary rejects it, so `sshpiperd` would not start; (3) set the Terraform variable, which defaults to `false` for that reason.
- The existing journal line that fail2ban reads is unchanged.

## Retention

| What | Retention | Where it is set |
|------|-----------|-----------------|
| Local file on the sentinel VM | 90 days after rotation by default (daily rotation, compressed) | Terraform variable `ssh_session_log_retention_days`, or for the standalone gce script the instance metadata attribute `ssh-session-log-retention-days` |
| Rows in the backend's audit store | No automatic purge; kept until an operator removes them | Backend database |

The local file is only a buffer. The audit store is the record of truth.

## Operator setup

For each backend behind the sentinel:

1. On the **backend**, mint a token that can do one thing, append SSH session records:

   ```bash
   containarium token generate --username sentinel-shipper --roles service \
       --scopes audit:ingest --expiry 2160h --secret-file /etc/containarium/jwt.secret
   ```

2. Register it on the **sentinel**, keyed by the backend id the sentinel uses for that backend:

   ```bash
   containarium sentinel register-token --kind audit-ingest \
       --url http://<sentinel>:8888 --backend <backend-id> --token <jwt>
   ```

   The command authenticates with the sentinel admin secret. The token is stored in a root-only file and is picked up on the next shipper pass with no restart.

Until a backend has a registered token its records are **not skipped**. They stay in the local file and the shipper logs an error on a backoff that grows to once a minute. They ship as soon as the token is registered.

### Rotation and revocation

1. Mint a new token on the backend and register it for the same `--backend`. This replaces the old one.
2. Revoke the old token on the backend with `containarium token revoke --jti <old-jti>`.

Register before revoking, or the shipper is rejected until you do. The shipper logs a warning once a day when a token has fewer than 14 days left, even when idle. To stop shipping for a backend, run `containarium sentinel deregister-token --kind audit-ingest --backend <backend-id>`.

A stolen token can only append `ssh_session_*` rows to one backend. It cannot read the log, delete anything, or authenticate to any other backend.

### Backfill, replay and orphans

The standalone `ship` form sends every record to the one `--url` backend, so use it only for a sink that holds that backend's records. It keeps its own checkpoint (`standalone-checkpoint.json`) and must never share the sentinel's. Pass `--checkpoint-file` explicitly if you run several.

```bash
# one pass, non-zero exit if anything could not be shipped
containarium sentinel ssh-sessions ship --once --checkpoint-file <own-file> --url http://<backend>:8080 --token-file <file>

# sessions with an open and no close older than 24h (a plugin hard-kill leaves these)
containarium sentinel ssh-sessions ship --reconcile --orphan-after 24h --checkpoint-file <own-file> --url http://<backend>:8080 --token-file <file>
```

Re-running either adds no rows. `--reconcile` writes a `close_reason=unknown_orphan` row and never rewrites the local file. It is a heuristic: a genuinely long-lived session older than the threshold is reported too, and its real close is still recorded separately when it arrives.

## Auditor procedure

Run on each backend (these read the database directly, with `CONTAINARIUM_POSTGRES_URL` set):

```bash
# 1. The sessions in a period
containarium audit query --action ssh_session_open  --from 2026-01-01 --to 2026-02-01
containarium audit query --action ssh_session_close --from 2026-01-01 --to 2026-02-01

# 2. The chain is intact: any edited, inserted or deleted row fails here
containarium audit verify

# 3. The chain tip matches the externally anchored root, which catches a rewrite
#    that recomputes every hash
containarium audit verify-anchor
```

To trace one login, query by the session id (`resource_id`). Each row's detail is JSON with the routed target, the authentication method and the credential identity (certificate key id, serial and CA fingerprint, or a key fingerprint), plus the close reason on a close row.

## What this does not cover

- **Failures that do not reach the ban plugin** (for example a connection dropped before authentication starts) remain only in the sentinel's journal. Failed authentications and bans seen by the ban plugin are shipped when it is configured with `--records-file`, as described above; authorization denials are shipped as `denied` records.
- **Records not yet shipped** are lost if the sentinel VM is destroyed before the shipper catches up. This window is normally a few seconds, and grows while a backend is unreachable or has no token.
- **Audit store retention** is not enforced automatically.
- **SIEM forwarding and alerting** are tracked separately under A.8.16.
