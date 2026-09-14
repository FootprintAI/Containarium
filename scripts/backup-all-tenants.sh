#!/usr/bin/env bash
# Iterate the tenant config and create a GCS backup for each entry, then
# prune each one to the newest N (#1839/#1840). Designed to be driven by
# containarium-backup.{service,timer}.
#
# Retention: after a successful create, the script prunes that (tenant,
# database) group to CONTAINARIUM_BACKUP_KEEP — deliberately AFTER, not
# before: a failed create never leaves zero backups for a tenant, because
# nothing old is removed until a new good one is already confirmed stored.
#
# Config file format (/etc/containarium/backup-tenants.conf), one of two
# line shapes per tenant:
#
#   # plain pg_dump mode — the common case (peer/trust auth on loopback)
#   <tenant>  <database>  [PASSWORD_ENV_VAR]
#
#   # hook mode (#1831) — for a database the platform can't reach directly,
#   # e.g. Postgres nested inside an in-container Docker/compose stack
#   <tenant>  --hook <in-container-hook-path>  [--label <label>]
#
# The optional third field of plain mode names an env variable whose value
# is passed as --db-password. Omit it when the in-container Postgres uses
# peer/trust auth (the common default — pg_dump runs as root inside the
# container on loopback). Hook mode never takes a password: the hook reaches
# its database under the container's own auth, so no credential crosses to
# the platform — see docs/DB-BACKUP-OPERATIONS.md#1831.
#
# Encryption (#1836) is NOT configured here: a tenant that has registered a
# CONTAINARIUM_BACKUP_AGE_RECIPIENT secret gets it automatically, with no
# flag needed from this script.
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
#   CONTAINARIUM_BACKUP_KEEP  newest backups to keep per (tenant, database)
#                             after each successful create (default: 7)

set -uo pipefail

CONF="${CONTAINARIUM_BACKUP_CONF:-/etc/containarium/backup-tenants.conf}"
SERVER="${CONTAINARIUM_SERVER:?CONTAINARIUM_SERVER must be set}"
BUCKET="${CONTAINARIUM_BACKUP_BUCKET:?CONTAINARIUM_BACKUP_BUCKET must be set}"
CTN="${CONTAINARIUM_BIN:-/usr/local/bin/containarium}"
TOKEN="${CONTAINARIUM_AUTH_TOKEN:-}"
KEEP="${CONTAINARIUM_BACKUP_KEEP:-7}"

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

while IFS= read -r line; do
  # shellcheck disable=SC2206 # deliberate word-splitting: config is whitespace-delimited by design
  words=($line)
  tenant="${words[0]:-}"
  [[ -z "$tenant" || "$tenant" == \#* ]] && continue

  total=$((total + 1))

  create_flags=()
  prune_database=""

  if [[ "${words[1]:-}" == "--hook" ]]; then
    # Hook mode: <tenant> --hook <path> [--label <label>]
    hook_path="${words[2]:-}"
    label=""
    if [[ "${words[3]:-}" == "--label" ]]; then
      label="${words[4]:-}"
    fi
    if [[ -z "$hook_path" ]]; then
      echo "[backup] WARNING: tenant=$tenant has --hook with no path; skipping" >&2
      failed=$((failed + 1))
      continue
    fi
    create_flags=(--hook "$hook_path")
    if [[ -n "$label" ]]; then
      create_flags+=(--label "$label")
      prune_database="$label"
    fi
    echo "[backup] start  tenant=$tenant hook=$hook_path"
  else
    # Plain mode: <tenant> <database> [PASSWORD_ENV_VAR]
    database="${words[1]:-}"
    pw_env="${words[2]:-}"
    if [[ -z "$database" ]]; then
      echo "[backup] WARNING: tenant=$tenant has no database (and is not --hook); skipping" >&2
      failed=$((failed + 1))
      continue
    fi
    create_flags=(--database "$database")
    prune_database="$database"
    if [[ -n "${pw_env:-}" ]]; then
      pw_value="${!pw_env:-}"
      if [[ -z "$pw_value" ]]; then
        echo "[backup] WARNING: $pw_env is not set; attempting without password (tenant=$tenant db=$database)" >&2
      else
        create_flags+=(--db-password "$pw_value")
      fi
    fi
    echo "[backup] start  tenant=$tenant db=$database"
  fi

  if "$CTN" backup create "$tenant" \
      "${create_flags[@]}" \
      --dest gcs \
      --gcs-bucket "$BUCKET" \
      --server "$SERVER" \
      ${auth_flags[@]+"${auth_flags[@]}"}; then
    echo "[backup] ok     tenant=$tenant"
  else
    echo "[backup] FAIL   tenant=$tenant" >&2
    failed=$((failed + 1))
    continue
  fi

  # Prune only after a successful create, and only when we know which
  # database/label group to scope it to — an empty prune_database means
  # "every database this tenant has", which is correct for a hook backup
  # with no --label (defaults to the hook's own basename) too.
  prune_args=(backup prune "$tenant" --keep "$KEEP" --server "$SERVER")
  if [[ -n "$prune_database" ]]; then
    prune_args=(backup prune "$tenant" --database "$prune_database" --keep "$KEEP" --server "$SERVER")
  fi
  prune_args+=(${auth_flags[@]+"${auth_flags[@]}"})
  if ! "$CTN" "${prune_args[@]}"; then
    echo "[backup] WARNING: prune failed for tenant=$tenant (backup itself succeeded; retention will catch up next run)" >&2
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
