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
| `enforced` | Whether the authorization decision was enforced for this record |

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

- **Other authentication failures and bans** logged only by `sshpiperd` and its ban plugin remain in the sentinel's journal and are not shipped. Authorization denials emitted as structured `denied` records are shipped as described above.
- **Records not yet shipped** are lost if the sentinel VM is destroyed before the shipper catches up. This window is normally a few seconds, and grows while a backend is unreachable or has no token.
- **Audit store retention** is not enforced automatically.
- **SIEM forwarding and alerting** are tracked separately under A.8.16.
