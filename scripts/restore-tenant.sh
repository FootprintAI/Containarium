#!/usr/bin/env bash
# Restore a tenant's backup — the newest one by default (#1839: retention
# now keeps several, not just one, so "the current good dump" means "the
# newest", not "the only one").
#
# Usage:
#   restore-tenant.sh <tenant> [--database <name>] [--id <backup-id>] [--dry-run]
#
# --id targets a specific backup instead of the newest — use it to restore
# an older point in time. `containarium backup list <tenant>` shows what's
# available (newest first) with each id's timestamp.
#
# Required environment variables (same as backup-all-tenants.sh, loaded from
# /etc/containarium/backup.env by the operator or the calling shell):
#   CONTAINARIUM_SERVER  daemon address, e.g. localhost:8080
#
# Optional:
#   CONTAINARIUM_AUTH_TOKEN  JWT for --token
#   CONTAINARIUM_BIN         path to containarium binary

set -uo pipefail

usage() {
  echo "Usage: $0 <tenant> [--database <name>] [--id <backup-id>] [--dry-run]" >&2
  exit 1
}

[[ $# -eq 0 ]] && usage

TENANT="$1"; shift
SERVER="${CONTAINARIUM_SERVER:?CONTAINARIUM_SERVER must be set}"
CTN="${CONTAINARIUM_BIN:-/usr/local/bin/containarium}"
TOKEN="${CONTAINARIUM_AUTH_TOKEN:-}"
DATABASE=""
EXPLICIT_ID=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database) DATABASE="$2"; shift 2 ;;
    --id)       EXPLICIT_ID="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=1; shift ;;
    *) echo "[restore] unknown argument: $1" >&2; usage ;;
  esac
done

auth_flags=()
if [[ -n "$TOKEN" ]]; then
  auth_flags=(--token "$TOKEN")
fi

if [[ -n "$EXPLICIT_ID" ]]; then
  ID="$EXPLICIT_ID"
  echo "[restore] tenant=$TENANT id=$ID (explicit --id)"
else
  # `backup list` returns newest first (Manager.List sorts by CreatedAt
  # descending) — the first row is always "the current good dump" for
  # this tenant, however many older ones retention is keeping around.
  mapfile -t ids < <("$CTN" backup list "$TENANT" \
      --server "$SERVER" \
      ${auth_flags[@]+"${auth_flags[@]}"} 2>/dev/null \
    | awk 'NR>1 {print $1}')

  if [[ ${#ids[@]} -eq 0 ]]; then
    echo "[restore] no backup found for tenant=$TENANT" >&2
    exit 1
  fi

  ID="${ids[0]}"
  if [[ ${#ids[@]} -gt 1 ]]; then
    echo "[restore] tenant=$TENANT: ${#ids[@]} backups found, using the newest: $ID"
    echo "[restore] (pass --id <backup-id> to restore a different one — see 'containarium backup list $TENANT')"
  else
    echo "[restore] tenant=$TENANT id=$ID"
  fi
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[restore] dry-run: would run: containarium backup restore $ID --clean${DATABASE:+ --database $DATABASE}"
  exit 0
fi

db_flags=()
if [[ -n "$DATABASE" ]]; then
  db_flags=(--database "$DATABASE")
fi

echo "[restore] restoring (--clean: drops + recreates objects before loading)…"
"$CTN" backup restore "$ID" \
    --clean \
    --server "$SERVER" \
    ${auth_flags[@]+"${auth_flags[@]}"} \
    ${db_flags[@]+"${db_flags[@]}"}

echo "[restore] done tenant=$TENANT id=$ID"
