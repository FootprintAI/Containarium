#!/usr/bin/env bash
# Restore the single on-file backup for a tenant.
#
# Usage:
#   restore-tenant.sh <tenant> [--database <name>] [--dry-run]
#
# One-copy policy: backup-all-tenants.sh keeps at most one backup per tenant.
# This script locates that record, verifies exactly one exists, and runs
# `containarium backup restore` with --clean (drops + recreates objects before
# loading).
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
  echo "Usage: $0 <tenant> [--database <name>] [--dry-run]" >&2
  exit 1
}

[[ $# -eq 0 ]] && usage

TENANT="$1"; shift
SERVER="${CONTAINARIUM_SERVER:?CONTAINARIUM_SERVER must be set}"
CTN="${CONTAINARIUM_BIN:-/usr/local/bin/containarium}"
TOKEN="${CONTAINARIUM_AUTH_TOKEN:-}"
DATABASE=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database) DATABASE="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=1; shift ;;
    *) echo "[restore] unknown argument: $1" >&2; usage ;;
  esac
done

auth_flags=()
if [[ -n "$TOKEN" ]]; then
  auth_flags=(--token "$TOKEN")
fi

# Locate the single backup record for this tenant.
mapfile -t ids < <("$CTN" backup list "$TENANT" \
    --server "$SERVER" \
    "${auth_flags[@]}" 2>/dev/null \
  | awk 'NR>1 {print $1}')

if [[ ${#ids[@]} -eq 0 ]]; then
  echo "[restore] no backup found for tenant=$TENANT" >&2
  exit 1
fi

if [[ ${#ids[@]} -gt 1 ]]; then
  echo "[restore] ERROR: ${#ids[@]} backups found for tenant=$TENANT (expected 1)." >&2
  echo "[restore] Run 'containarium backup list $TENANT' and delete extras, then retry." >&2
  exit 1
fi

ID="${ids[0]}"
echo "[restore] tenant=$TENANT id=$ID"

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
    "${auth_flags[@]}" \
    "${db_flags[@]}"

echo "[restore] done tenant=$TENANT id=$ID"
