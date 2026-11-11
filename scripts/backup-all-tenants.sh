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
#   <tenant>  --hook <in-container-hook-path>  [--label <label>]  [--hook-format <fmt>]
#
# --hook-format (#2405) declares what the hook writes: `opaque` (the default
# when omitted) or `pg_custom` for a hook that emits a `pg_dump -Fc` archive,
# which makes the backup restore-testable. It is a promise about the hook's
# output; the daemon does not check it at create time. The options after the
# path may come in either order.
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
# flag needed from this script. Secrets are stored per daemon: a container
# copied to another host arrives WITHOUT its registered recipient. Run
# `containarium backup status` to list configured tenants that have none.
#
# Required environment variables (set in /etc/containarium/backup.env):
#   CONTAINARIUM_SERVER         daemon address, e.g. localhost:8080
#   CONTAINARIUM_BACKUP_BUCKET  GCS bucket prefix, e.g. gs://my-backups/pg
#
# Optional:
#   CONTAINARIUM_BACKUP_CONF  path to config file (default below)
#   CONTAINARIUM_BIN          path to containarium binary (default below)
#   CONTAINARIUM_JWT_SECRET_FILE  path to the daemon's JWT signing secret
#                             (e.g. /etc/containarium/jwt.secret). When set, each
#                             run mints its own 2h token (#2592) and any
#                             CONTAINARIUM_AUTH_TOKEN is ignored. If the mint
#                             fails the run exits non-zero; it never falls back
#                             to a static token. ON-HOST ONLY: root on the daemon
#                             host already holds this file (0600 root), so this
#                             adds no trust. NEVER copy the signing secret to a
#                             remote runner — those use CONTAINARIUM_AUTH_TOKEN.
#   CONTAINARIUM_AUTH_TOKEN   static JWT for --token, for remote runners that
#                             cannot read the secret. Tokens are capped at 30d
#                             (there are no non-expiring tokens): the owner must
#                             re-mint it before it lapses or every run fails
#                             with `invalid token`.
#   CONTAINARIUM_BACKUP_KEEP  newest backups to keep per (tenant, database)
#                             after each successful create (default: 7)
#   CONTAINARIUM_BACKUP_REQUIRE_ENCRYPTION  set to 1 to pass --require-encryption
#                             (#3169): a tenant with no age recipient (and no
#                             managed key on the daemon) then FAILS instead of
#                             being stored in plaintext, and no object is
#                             written. Recommended. Default: off.
#
# Exit status: 1 when any tenant failed; otherwise 3 when any tenant's dump
# was stored UNENCRYPTED (#3169) — every tenant is still backed up first,
# each such tenant is named on a `WARNING UNENCRYPTED` line and in the
# closing summary, and the non-zero status turns the unit result red;
# otherwise 0.

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

if [[ -n "${CONTAINARIUM_JWT_SECRET_FILE:-}" ]]; then
  # Mint a short-lived token for this run (#2592). A failure is fatal: falling
  # back to a static token would hide the very expiry this path exists to avoid.
  if ! TOKEN="$("$CTN" token generate \
      --username backup-scheduler --roles admin \
      --scopes backups:write,backups:read \
      --expiry 2h \
      --secret-file "$CONTAINARIUM_JWT_SECRET_FILE" --raw)" || [[ -z "$TOKEN" ]]; then
    echo "[backup] FATAL: could not mint a token from CONTAINARIUM_JWT_SECRET_FILE=$CONTAINARIUM_JWT_SECRET_FILE" >&2
    exit 1
  fi
fi

auth_flags=()
if [[ -n "$TOKEN" ]]; then
  auth_flags=(--token "$TOKEN")
fi

require_flags=()
if [[ "${CONTAINARIUM_BACKUP_REQUIRE_ENCRYPTION:-}" == "1" ]]; then
  require_flags=(--require-encryption)
fi

failed=0
total=0
unencrypted=()
create_out="$(mktemp)"
trap 'rm -f "$create_out"' EXIT

while IFS= read -r line; do
  # shellcheck disable=SC2206 # deliberate word-splitting: config is whitespace-delimited by design
  words=($line)
  tenant="${words[0]:-}"
  [[ -z "$tenant" || "$tenant" == \#* ]] && continue

  total=$((total + 1))

  create_flags=()
  prune_database=""

  if [[ "${words[1]:-}" == "--hook" ]]; then
    # Hook mode: <tenant> --hook <path> [--label <label>] [--hook-format <fmt>]
    hook_path="${words[2]:-}"
    label=""
    hook_format=""
    bad_option=""
    # Optional "--key value" pairs after the path, in any order.
    for ((i = 3; i < ${#words[@]}; i += 2)); do
      case "${words[i]}" in
        --label) label="${words[i + 1]:-}" ;;
        --hook-format) hook_format="${words[i + 1]:-}" ;;
        *) bad_option="${words[i]}" ;;
      esac
    done
    if [[ -z "$hook_path" ]]; then
      echo "[backup] WARNING: tenant=$tenant has --hook with no path; skipping" >&2
      failed=$((failed + 1))
      continue
    fi
    if [[ -n "$bad_option" ]]; then
      echo "[backup] WARNING: tenant=$tenant has unknown hook option '$bad_option'; skipping" >&2
      failed=$((failed + 1))
      continue
    fi
    create_flags=(--hook "$hook_path")
    if [[ -n "$label" ]]; then
      create_flags+=(--label "$label")
      prune_database="$label"
    fi
    if [[ -n "$hook_format" ]]; then
      # A promise about the hook's output (#2405); the CLI rejects an
      # unknown value, which counts as a failed tenant below.
      create_flags+=(--hook-format "$hook_format")
    fi
    echo "[backup] start  tenant=$tenant hook=$hook_path${hook_format:+ format=$hook_format}"
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
      ${require_flags[@]+"${require_flags[@]}"} \
      ${auth_flags[@]+"${auth_flags[@]}"} | tee "$create_out"; then
    echo "[backup] ok     tenant=$tenant"
    # #3169: encryption is opt-in per tenant; an unregistered recipient means
    # a plaintext object. Make that greppable instead of silent.
    if grep -q 'Encrypted: no' "$create_out"; then
      echo "[backup] WARNING UNENCRYPTED tenant=$tenant: dump stored without encryption (no age recipient registered)" >&2
      unencrypted+=("$tenant")
    fi
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

if [[ "${#unencrypted[@]}" -gt 0 ]]; then
  echo "[backup] ${#unencrypted[@]}/$total tenant(s) stored UNENCRYPTED: ${unencrypted[*]}" >&2
fi

if [[ "$failed" -gt 0 ]]; then
  echo "[backup] $failed/$total tenant(s) failed" >&2
  exit 1
fi

echo "[backup] all $total tenant(s) done"
if [[ "${#unencrypted[@]}" -gt 0 ]]; then
  # #3169: every tenant ran, but a plaintext dump is not a clean run.
  exit 3
fi
