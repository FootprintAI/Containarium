#!/usr/bin/env bash
# Real daemon + Incus + PostgreSQL scope contract for #2401.
# Run as root against a disposable daemon with JWT_SECRET and ADMIN_TOKEN.
set -euo pipefail

bin=${CONTAINARIUM_BIN:-/tmp/containarium}
server=${CONTAINARIUM_BACKUP_E2E_SERVER:-http://localhost:8080}
image=${CONTAINARIUM_LANE_IMAGE:-images:ubuntu/24.04}
: "${JWT_SECRET:?required}"
: "${ADMIN_TOKEN:?required}"
tenant="verifylane$$"
source_name="$tenant-container"
scratch_dir=$(mktemp -d)
cleanup() {
  incus delete "$source_name" --force >/dev/null 2>&1 || true
  rm -rf "$scratch_dir"
}
trap cleanup EXIT

# api <expected-status> <out-file> <curl args...> <url>
# Runs one request, keeps the response body in <out-file>, and fails unless
# the HTTP status equals <expected-status>. On a mismatch it prints the
# URL, the status, and the response body, so a failure in CI shows
# its cause (#3028). Authorization headers are never echoed.
api() {
  local want=$1 out=$2 code url
  shift 2
  url=${*: -1}
  if ! code=$(curl -sS -o "$out" -w '%{http_code}' "$@"); then
    echo "request failed before a response: $url" >&2
    return 1
  fi
  if [ "$code" != "$want" ]; then
    echo "Expected HTTP $want from $url, received $code; response body:" >&2
    cat "$out" >&2 || true
    echo >&2
    return 1
  fi
}
printf '%s' "$JWT_SECRET" > "$scratch_dir/jwt.secret"
chmod 600 "$scratch_dir/jwt.secret"

incus launch "$image" "$source_name"
incus exec "$source_name" -- sh -c '
  set -eu
  if command -v cloud-init >/dev/null 2>&1; then cloud-init status --wait; fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq postgresql-16
  pg_ctlcluster 16 main start || pg_isready -q
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "ALTER USER postgres PASSWORD '\''lane-source-password'\''"
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "CREATE TABLE scope_contract(id integer); INSERT INTO scope_contract VALUES (1)"
'

request=$(jq -n --arg tenant "$tenant" '{username:$tenant,destination:"BACKUP_DESTINATION_LOCAL",connection:{database:"postgres",password:"lane-source-password"}}')
api 200 "$scratch_dir/create.json" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d "$request" "$server/v1/backups"
backup_id=$(jq -er '.record.id' "$scratch_dir/create.json")

# The exact documented invocation, including the non-admin role and 720h TTL.
token=$("$bin" token generate --username "$tenant" --roles user \
  --scopes backups:read,backups:verify --expiry 720h \
  --secret-file "$scratch_dir/jwt.secret" --raw)

api 200 "$scratch_dir/list.json" -H "Authorization: Bearer $token" \
  "$server/v1/backups?username=$tenant"
jq -e --arg id "$backup_id" --arg tenant "$tenant" \
  '(.records | length) == 1 and .records[0].id == $id and .records[0].username == $tenant' "$scratch_dir/list.json"

request=$(jq -n --arg tenant "$tenant" '{targetUsername:$tenant}')
api 200 "$scratch_dir/verify.json" --max-time 600 -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' -d "$request" \
  "$server/v1/backups/$backup_id/verify"
if ! jq -e '.verification.result == "VERIFICATION_RESULT_PASSED"' "$scratch_dir/verify.json"; then
  echo "Verification did not pass; response body:" >&2
  cat "$scratch_dir/verify.json" >&2
  exit 1
fi
target=$(jq -er '.verification.targetContainer' "$scratch_dir/verify.json")
test "$target" != "$source_name"
if incus info "$target" >/dev/null 2>&1; then
  echo "Verifier container was not deleted: $target" >&2
  exit 1
fi

for path in '/v1/backups?username=other-tenant' '/v1/containers' "/v1/secrets/$tenant/db"; do
  api 403 "$scratch_dir/denied.json" -H "Authorization: Bearer $token" "$server$path"
done

# The narrow verifier token must be refused on every RPC that creates,
# restores, deletes or prunes (#3186). 403 is the daemon's PermissionDenied.
create_req=$(jq -n --arg tenant "$tenant" '{username:$tenant,destination:"BACKUP_DESTINATION_LOCAL",connection:{database:"postgres",password:"lane-source-password"}}')
api 403 "$scratch_dir/denied.json" -X POST -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' -d "$create_req" "$server/v1/backups"
api 403 "$scratch_dir/denied.json" -X POST -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' -d '{}' "$server/v1/backups/$backup_id/restore"
api 403 "$scratch_dir/denied.json" -X DELETE -H "Authorization: Bearer $token" \
  "$server/v1/backups/$backup_id"
api 403 "$scratch_dir/denied.json" -X POST -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' -d "{\"username\":\"$tenant\",\"keep\":1}" "$server/v1/backups/prune"
# The backup must still exist after the refused delete/prune.
api 200 "$scratch_dir/still.json" -H "Authorization: Bearer $token" "$server/v1/backups/$backup_id"

# deprecation_lines counts the daemon's "[backup] DEPRECATED:" lines for this
# run's tenant. Only callable when CONTAINARIUM_BACKUP_E2E_DAEMON_LOG names the
# daemon's log file.
deprecation_lines() {
  grep -c "\[backup\] DEPRECATED: VerifyBackup authorized by legacy scope backups:write user=\"$tenant\" " \
    "$CONTAINARIUM_BACKUP_E2E_DAEMON_LOG" || true
}
daemon_log=${CONTAINARIUM_BACKUP_E2E_DAEMON_LOG:-}
if [ -n "$daemon_log" ]; then
  # The backups:verify token verified above: that must not log a deprecation.
  test "$(deprecation_lines)" = 0 || {
    echo "backups:verify verify logged a deprecation line" >&2
    exit 1
  }
fi

# A verifier token minted before backups:verify existed (backups:write) keeps
# verifying for one release (#3186, Q8 on #3196) and logs a deprecation line;
# the next release stops accepting backups:write for VerifyBackup.
legacy=$("$bin" token generate --username "$tenant" --roles user \
  --scopes backups:read,backups:write --expiry 5m \
  --secret-file "$scratch_dir/jwt.secret" --raw)
request=$(jq -n --arg tenant "$tenant" '{targetUsername:$tenant}')
api 200 "$scratch_dir/legacy-verify.json" --max-time 600 -H "Authorization: Bearer $legacy" \
  -H 'Content-Type: application/json' -d "$request" "$server/v1/backups/$backup_id/verify"
jq -e '.verification.result == "VERIFICATION_RESULT_PASSED"' "$scratch_dir/legacy-verify.json"
legacy_target=$(jq -er '.verification.targetContainer' "$scratch_dir/legacy-verify.json")
if incus info "$legacy_target" >/dev/null 2>&1; then
  echo "Verifier container was not deleted: $legacy_target" >&2
  exit 1
fi
if [ -n "$daemon_log" ]; then
  test "$(deprecation_lines)" = 1 || {
    echo "legacy backups:write verify did not log exactly one deprecation line in $daemon_log" >&2
    exit 1
  }
else
  echo 'SKIP deprecation-log check: set CONTAINARIUM_BACKUP_E2E_DAEMON_LOG to the daemon log file to run it.'
fi

# Verification must leave the source database intact.
test "$(incus exec "$source_name" -- runuser -u postgres -- psql -Atc 'SELECT count(*) FROM scope_contract')" = 1
echo 'PASS: backups:verify token lists and verifies its own backup, is refused create/restore/delete/prune and other APIs, and cleans up its isolated target.'
