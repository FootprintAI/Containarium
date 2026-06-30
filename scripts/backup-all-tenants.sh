#!/usr/bin/env bash
# Iterate the tenant config and create a GCS backup for each entry.
# Designed to be driven by containarium-backup.{service,timer}.
#
# One-copy policy: before creating a new backup the script deletes any
# existing backups for the same tenant, so there is always at most one dump
# per tenant in the index.  restore-tenant.sh relies on this invariant.
#
# Config file format (/etc/containarium/backup-tenants.conf):
#   # comment
#   <tenant>  <database>  [PASSWORD_ENV_VAR]
#
# The optional third field names an env variable whose value is passed as
# --db-password.  Omit it when the in-container Postgres uses peer/trust auth
# (the common default — pg_dump runs as root inside the container on loopback).
#
# Required environment variables (set in /etc/containarium/backup.env):
#   CONTAINARIUM_SERVER         daemon address, e.g. localhost:8080
#   CONTAINARIUM_BACKUP_BUCKET  GCS bucket prefix, e.g. gs://my-backups/pg
#
# Optional:
#   CONTAINARIUM_BACKUP_CONF  path to config file (default below)
#   CONTAINARIUM_BIN          path to containarium binary (default below)
#   CONTAINARIUM_AUTH_TOKEN   JWT for --token (omit when running on daemon host
#                             with a root service token or peer auth)

set -uo pipefail

CONF="${CONTAINARIUM_BACKUP_CONF:-/etc/containarium/backup-tenants.conf}"
SERVER="${CONTAINARIUM_SERVER:?CONTAINARIUM_SERVER must be set}"
BUCKET="${CONTAINARIUM_BACKUP_BUCKET:?CONTAINARIUM_BACKUP_BUCKET must be set}"
CTN="${CONTAINARIUM_BIN:-/usr/local/bin/containarium}"
TOKEN="${CONTAINARIUM_AUTH_TOKEN:-}"

if [[ ! -f "$CONF" ]]; then
  echo "[backup] config not found: $CONF" >&2
  exit 1
fi

auth_flags=()
if [[ -n "$TOKEN" ]]; then
  auth_flags=(--token "$TOKEN")
fi

failed=0
total=0

while IFS=$' \t' read -r tenant database pw_env _rest; do
  [[ -z "$tenant" || "$tenant" == \#* ]] && continue

  total=$((total + 1))

  pw_flags=()
  if [[ -n "${pw_env:-}" ]]; then
    pw_value="${!pw_env:-}"
    if [[ -z "$pw_value" ]]; then
      echo "[backup] WARNING: $pw_env is not set; attempting without password (tenant=$tenant db=$database)" >&2
    else
      pw_flags=(--db-password "$pw_value")
    fi
  fi

  # One-copy policy: delete any existing backup(s) for this tenant before
  # creating a fresh one.  This keeps the index lean and makes restore trivial
  # (the single record is always the current good dump).
  while IFS= read -r old_id; do
    [[ -z "$old_id" ]] && continue
    echo "[backup] prune  tenant=$tenant id=$old_id"
    "$CTN" backup delete "$old_id" \
        --server "$SERVER" \
        "${auth_flags[@]}" || true   # non-fatal: stale index entry, carry on
  done < <("$CTN" backup list "$tenant" \
      --server "$SERVER" \
      "${auth_flags[@]}" 2>/dev/null \
    | awk 'NR>1 {print $1}')

  echo "[backup] start  tenant=$tenant db=$database"
  if "$CTN" backup create "$tenant" \
      --database "$database" \
      --dest gcs \
      --gcs-bucket "$BUCKET" \
      --server "$SERVER" \
      "${auth_flags[@]}" \
      "${pw_flags[@]}"; then
    echo "[backup] ok     tenant=$tenant db=$database"
  else
    echo "[backup] FAIL   tenant=$tenant db=$database" >&2
    failed=$((failed + 1))
  fi
done < "$CONF"

if [[ "$total" -eq 0 ]]; then
  echo "[backup] no tenants configured in $CONF — nothing to do"
  exit 0
fi

if [[ "$failed" -gt 0 ]]; then
  echo "[backup] $failed/$total tenant(s) failed" >&2
  exit 1
fi

echo "[backup] all $total tenant(s) done"
