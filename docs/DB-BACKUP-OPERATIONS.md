# Database backups — operator runbook

**Related:**
- [`docs/DISASTER-RECOVERY.md`](DISASTER-RECOVERY.md) — host-loss recovery this complements (it recovers containers; this recovers their data).
- [`docs/SECRETS-OPERATIONS.md`](SECRETS-OPERATIONS.md) — the off-host backup pattern this mirrors (GCS / Vault / encrypted store).
- [`docs/SECURITY-ENCRYPTION-AT-REST.md`](SECURITY-ENCRYPTION-AT-REST.md) — the at-rest posture dumps inherit on disk and in GCS.

This is the operator's manual for **`containarium backup`** — logical
(`pg_dump`) backups of the databases running *inside* Containarium
containers, stored **off the database host**.

> **Why off-host, why logical.** A backup that shares a failure domain
> with the data it protects is not a backup. A raw snapshot of a *running*
> Postgres disk is crash-consistent at best — on restore you can get a
> corrupt cluster. So we take application-consistent logical dumps
> (`pg_dump -Fc`, custom format) and ship them to a store that survives
> host loss. Logical dumps are also small (MBs–low GBs), so daily — or
> more frequent — backups cost cents in object storage, which removes the
> usual "backups are too expensive to run often" objection.

## Architecture decision (the short version)

| Choice | What we do | Why |
|---|---|---|
| **Isolation** | one database per application/tenant container | a breach or restore touches one tenant, not all |
| **Backup method** | `pg_dump -Fc` (logical), not whole-disk image | application-consistent + selectively restorable + small |
| **Destination** | off-host: GCS (prod) or a host backup dir distinct from the data disk (dev/staging) | survives container, disk, and host loss |
| **Index** | a JSON sidecar per dump in the daemon's backup dir | `list` works even when the database being backed up is down |
| **Integrity** | SHA-256 recorded at dump time, verified before every restore | catches corruption or tampering before it overwrites a live DB |

Use a single shared multi-tenant Postgres only for non-sensitive,
cost-capped workloads — it trades the isolation column above for a lower
bill, and it is the destination most likely to produce a cross-tenant
disclosure finding.

## The CLI surface

All commands take the usual `--server <host>` (and `--http`/auth flags).
The daemon runs `pg_dump`/`pg_restore` *inside* the tenant's container
over loopback; the password, when needed, is passed via `PGPASSWORD`
inside the container and never appears on a command line or in a log.

```bash
# Create a backup to the local host backup dir (dev/staging).
containarium backup create <tenant> --database app --dest local --server <host>

# Create a backup to GCS (production — true off-host durability).
containarium backup create <tenant> --database app --dest gcs \
  --gcs-bucket gs://<your-backup-bucket>/pg \
  --db-password "$PGPW" --server <host>

# List (newest first). Admins see all tenants; a tenant token sees its own.
containarium backup list --server <host>

# Inspect one backup's metadata (size, checksum, location).
containarium backup get <tenant>-app-<timestamp> --server <host>

# Restore in place (DESTRUCTIVE with --clean: drops objects first).
containarium backup restore <tenant>-app-<timestamp> --clean --server <host>

# Delete a stored dump + its index entry (retention; see below).
containarium backup delete <tenant>-app-<timestamp> --server <host>
```

Connection defaults target a per-container local Postgres: user
`postgres`, host `127.0.0.1`, port `5432`. Override with
`--db-user/--db-host/--db-port` as needed.

The same operations are available as MCP tools (`create_backup`,
`list_backups`, `restore_backup`) and over REST (`/v1/backups`) — they
all call the one `BackupService`, so an agent, a human shell, and CI have
an identical surface.

## Scheduling (systemd timer — recommended)

v1 has no in-daemon scheduler — and for an audit that is a feature, not a
gap: a timer unit is an explicit, reviewable, timestamped artifact whose
history is preserved in the journal.

The repo ships three files under `scripts/`:

| File | Purpose |
|---|---|
| `scripts/backup-all-tenants.sh` | iterates `/etc/containarium/backup-tenants.conf`, one `backup create` per tenant |
| `scripts/containarium-backup.service` | oneshot service that runs the script |
| `scripts/containarium-backup.timer` | fires the service at 02:30 every night |

### Installation on the daemon host

```bash
# 1. Install the script.
cp scripts/backup-all-tenants.sh /usr/local/bin/
chmod +x /usr/local/bin/backup-all-tenants.sh

# 2. Install the systemd units.
cp scripts/containarium-backup.{service,timer} /etc/systemd/system/
systemctl daemon-reload

# 3. Create the environment file (mode 0600 — contains credentials).
cat > /etc/containarium/backup.env <<'ENV'
CONTAINARIUM_SERVER=localhost:8080
CONTAINARIUM_BACKUP_BUCKET=gs://<your-backup-bucket>/pg
# CONTAINARIUM_AUTH_TOKEN=<jwt>  # omit when running on the daemon host as root
ENV
chmod 0600 /etc/containarium/backup.env

# 4. Create the tenant config (one line per database to back up).
#    Format: <tenant>  <database>  [OPTIONAL_PASSWORD_ENV_VAR]
cat > /etc/containarium/backup-tenants.conf <<'CONF'
# tenant          database
<tenant-a>        app
<tenant-b>        app
CONF

# 5. Enable and start the timer.
systemctl enable --now containarium-backup.timer

# 6. Verify the timer is queued.
systemctl list-timers containarium-backup.timer
```

### Watching and alerting

```bash
# Tail the current run log.
journalctl -u containarium-backup -f

# Check the last run's exit status.
systemctl status containarium-backup.service

# Alert on absence: the service exits 1 if any tenant failed, which marks
# the unit as "failed". Wire this into your monitoring:
systemctl is-failed containarium-backup.service && alert "backup failed"
```

The service exits non-zero if **any** tenant fails, so a monitoring check on
`systemctl is-failed containarium-backup.service` catches both partial and
total failures. Alert on **absence** too — a timer that was disabled emits
no failure line, only silence.

For a tighter RPO than "nightly," add Postgres WAL archiving inside the
container (`archive_command` → GCS) on top of these base dumps; that gives
point-in-time recovery with an RPO of minutes, still cheaply.

## GCS bucket setup + retention lifecycle

Create a dedicated bucket with **object versioning** and a **lifecycle**
that enforces your retention window. The dumps are small, so a generous
window is cheap.

```bash
# One-time: create a regional bucket with versioning on.
gcloud storage buckets create gs://<your-backup-bucket> \
  --project=<your-gcp-project> --location=<region> \
  --uniform-bucket-level-access
gcloud storage buckets update gs://<your-backup-bucket> --versioning

# Apply a tiered retention lifecycle (30 daily / ~1y monthly, then delete).
cat > /tmp/lifecycle.json <<'JSON'
{
  "rule": [
    { "action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
      "condition": {"age": 30} },
    { "action": {"type": "SetStorageClass", "storageClass": "COLDLINE"},
      "condition": {"age": 90} },
    { "action": {"type": "Delete"},
      "condition": {"age": 400} }
  ]
}
JSON
gcloud storage buckets update gs://<your-backup-bucket> \
  --lifecycle-file=/tmp/lifecycle.json
```

Pair lifecycle pruning of the *objects* with `containarium backup delete`
for the *index entries* so `list` doesn't show dumps the lifecycle has
already removed. A simple retention cron:

```bash
# Prune index entries older than the lifecycle horizon (example: 400 days).
containarium backup list --server <host> --http \
  | awk 'NR>1 {print $1, $4}'   # ID, CREATED — feed IDs past your window to: backup delete
```

## Restore test — the control an auditor actually checks

ISO 27001 **A.8.13** does not credit untested backups. Run this on a
schedule (quarterly is typical) and keep the output as evidence.

```bash
# 1. Pick the latest backup for a tenant.
ID=$(containarium backup list <tenant> --server <host> | awk 'NR==2{print $1}')

# 2. Restore into a throwaway database, NOT the live one.
containarium backup restore "$ID" --database app_restore_test \
  --clean --server <host>

# 3. Inside the container, sanity-check row counts / a known invariant,
#    then drop the test database. Record PASS/FAIL + timestamp + ID.
```

Restore always verifies the dump's SHA-256 against the recorded checksum
before it touches the database — a mismatch aborts the restore with a
"integrity check failed" error rather than loading corrupt data.

## ISO 27001 control mapping

| Control | How this feature satisfies it |
|---|---|
| **A.8.13 Information backup** | Scheduled logical dumps, off-host, with documented retention and a tested-restore procedure. |
| **A.8.13 (tested)** | `backup restore` into a scratch DB + checksum verification; keep run output as evidence. |
| **A.5.30 / A.8.14 ICT readiness for continuity** | Off-host dumps + `DISASTER-RECOVERY.md` reconstitute service after host loss. |
| **A.8.24 Use of cryptography (at rest)** | Dumps inherit GCS default encryption (or CMEK); the host backup dir inherits disk encryption. |
| **A.8.12 / A.5.34 Data leakage / PII** | Per-tenant isolation bounds blast radius; `backups:read`/`backups:write` scopes gate access; `get_secret`-style passwords never hit argv or logs. |
| **A.8.15 Logging** | Every create/restore/delete is logged with id, tenant, db, size. |

## Threat model — what backup protects against

| Failure | Recovers? |
|---|---|
| Container/database corruption or accidental `DROP` | Yes — restore the latest dump |
| Container data disk loss | Yes — dumps live off the data disk |
| Daemon host loss (GCS destination) | Yes — restore on a fresh host from GCS |
| Daemon host loss (LOCAL destination) | **No** — LOCAL is dev/staging only; use GCS for durability |
| GCP project deleted | No — replicate the bucket cross-project if this is a real concern |
| Silent dump corruption / tampering | Caught at restore by the SHA-256 check; pick an earlier backup |
| Cross-tenant disclosure | Bounded — one database per container; one dump = one tenant |

## Quick reference

- **CLI**: `containarium backup create|list|get|restore|delete`
- **REST**: `/v1/backups` (`BackupService`, generated via grpc-gateway)
- **MCP tools**: `create_backup`, `list_backups`, `restore_backup`
- **Auth scopes**: `backups:read` (list/get), `backups:write` (create/restore/delete)
- **Dump format**: `pg_dump -Fc` (custom, compressed, selectively restorable)
- **Integrity**: SHA-256 recorded at create, verified at restore
- **Host backup dir**: `/var/lib/containarium/backups` (override with `CONTAINARIUM_BACKUP_DIR`)
- **GCS requirement**: the daemon host needs `gcloud` on `PATH`; without it the daemon serves LOCAL backups and rejects GCS with a clear error
- **Engine**: PostgreSQL (v1)
