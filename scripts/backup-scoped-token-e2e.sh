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
curl --fail-with-body -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d "$request" "$server/v1/backups" > "$scratch_dir/create.json"
backup_id=$(jq -er '.record.id' "$scratch_dir/create.json")

# The exact documented invocation, including the non-admin role and 720h TTL.
token=$("$bin" token generate --username "$tenant" --roles user \
  --scopes backups:read,backups:write --expiry 720h \
  --secret-file "$scratch_dir/jwt.secret" --raw)

curl --fail-with-body -sS -H "Authorization: Bearer $token" \
  "$server/v1/backups?username=$tenant" > "$scratch_dir/list.json"
jq -e --arg id "$backup_id" --arg tenant "$tenant" \
  '(.records | length) == 1 and .records[0].id == $id and .records[0].username == $tenant' "$scratch_dir/list.json"

request=$(jq -n --arg tenant "$tenant" '{targetUsername:$tenant}')
curl --fail-with-body -sS --max-time 600 -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' -d "$request" \
  "$server/v1/backups/$backup_id/verify" > "$scratch_dir/verify.json" || {
    echo "verify request failed; response body:" >&2
    cat "$scratch_dir/verify.json" >&2
    exit 1
  }
jq -e '.verification.result == "VERIFICATION_RESULT_PASSED"' "$scratch_dir/verify.json"
target=$(jq -er '.verification.targetContainer' "$scratch_dir/verify.json")
test "$target" != "$source_name"
if incus info "$target" >/dev/null 2>&1; then
  echo "Verifier container was not deleted: $target" >&2
  exit 1
fi

for path in '/v1/backups?username=other-tenant' '/v1/containers' "/v1/secrets/$tenant/db"; do
  code=$(curl -sS -o "$scratch_dir/denied.json" -w '%{http_code}' \
    -H "Authorization: Bearer $token" "$server$path")
  if [ "$code" != 403 ]; then
    echo "Expected 403 for $path, received $code" >&2
    cat "$scratch_dir/denied.json" >&2
    exit 1
  fi
done

# Verification must leave the source database intact.
test "$(incus exec "$source_name" -- runuser -u postgres -- psql -Atc 'SELECT count(*) FROM scope_contract')" = 1
echo 'PASS: scoped token lists and verifies its own backup, denies other APIs, and cleans up its isolated target.'
