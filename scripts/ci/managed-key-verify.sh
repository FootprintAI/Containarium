#!/usr/bin/env bash
# #3213 verification harness: `containarium backup status` detects whether a
# daemon has a managed backup key, run against PUBLISHED release binaries only
# (never a CI build) with a real daemon, Incus and PostgreSQL.
#
# Needs: Ubuntu runner with sudo, Incus up with the image alias $LANE_IMAGE
# pulled, PostgreSQL server installed on the host (for the daemon's secrets
# store), cosign, curl, jq, git. Used by .github/workflows/managed-key-verify.yml.
#
# Env: RELEASE_TAG (tag under test), OLDER_TAG (predates #3231), OUTPUT_DIR.
# Cases (b), (c), (d)-older and (d)-failed-lookup are asserted with exact
# output and exit status. Cases (a) and (c)-managed need a real KMS key (Q14)
# and are reported as NOT VERIFIED, never passed or silently skipped.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/ci/managed-key-verify-lib.sh
. "$here/managed-key-verify-lib.sh"

tag=${RELEASE_TAG:?set RELEASE_TAG}
older=${OLDER_TAG:?set OLDER_TAG}
for t in "$tag" "$older"; do
  [[ "$t" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release tag: $t" >&2; exit 1; }
done
out=${OUTPUT_DIR:?Set OUTPUT_DIR to an empty evidence directory}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
lane_image=${LANE_IMAGE:-lane-box}
pg_url=${PG_URL:?set PG_URL (platform Postgres connection string for the daemon)}
repo=FootprintAI/Containarium
server=http://localhost:8080
tenant="verifykey$$"
conf="$work/backup-tenants.conf"
jwt_secret=managed-key-lane-only-secret-not-a-credential
daemon_pid=
cases="$out/results.txt.cases"
: >"$cases"
failed=0

cleanup() {
  [ -z "$daemon_pid" ] || sudo kill "$daemon_pid" 2>/dev/null || true
  sudo incus delete "$tenant-container" --force >/dev/null 2>&1 || true
  sudo rm -rf "$work"
}
trap cleanup EXIT

fetch() { curl -fsSL --retry 3 --connect-timeout 30 --max-time 300 "$1" -o "$2"; }

# record PASS|FAIL <name>
record() { printf '%s (%s)\n' "$1" "$2" | tee -a "$cases"; [ "$1" = PASS ] || failed=1; }
# case_run <name> <check cmd...>: run one checker, record the verdict.
case_run() {
  local name=$1; shift
  if "$@"; then record PASS "$name"; else record FAIL "$name"; fi
}

# fetch_release <tag> <dir>: download the daemon, CLI, checksum list and
# signatures of a published release, then verify them the way
# docs/security/VERIFYING-RELEASES.md describes.
fetch_release() {
  local t=$1 dir=$2 f
  local base="https://github.com/$repo/releases/download/$t"
  local id="https://github.com/$repo/.github/workflows/release.yml@refs/tags/$t"
  mkdir -p "$dir"
  for f in containariumd-linux-amd64 containarium-linux-amd64 SHA256SUMS.txt; do
    fetch "$base/$f" "$dir/$f"
    fetch "$base/$f.sigstore.json" "$dir/$f.sigstore.json"
    cosign verify-blob --bundle "$dir/$f.sigstore.json" \
      --certificate-identity "$id" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$dir/$f"
  done
  (cd "$dir" && sha256sum -c --ignore-missing SHA256SUMS.txt | tee "$out/sha256-check-$t.txt")
  # --ignore-missing passes if nothing matched; require both binaries.
  for f in containariumd-linux-amd64 containarium-linux-amd64; do
    grep -Fxq "$f: OK" "$out/sha256-check-$t.txt" || { echo "$f not covered by SHA256SUMS.txt for $t" >&2; exit 1; }
  done
  chmod +x "$dir/containariumd-linux-amd64" "$dir/containarium-linux-amd64"
}

echo "== Fetching and verifying published releases $tag and $older"
fetch_release "$tag" "$work/new"
fetch_release "$older" "$work/old"
newcli="$work/new/containarium-linux-amd64"
newd="$work/new/containariumd-linux-amd64"
oldd="$work/old/containariumd-linux-amd64"

commit_of() { git ls-remote "https://github.com/$repo" "refs/tags/$1^{}" "refs/tags/$1" | awk 'NR==1{print $1}'; }
{
  printf 'Release under test: %s commit %s\n' "$tag" "$(commit_of "$tag")"
  printf 'Older release: %s commit %s\n' "$older" "$(commit_of "$older")"
  for t in new:$tag old:$older; do
    for f in containariumd-linux-amd64 containarium-linux-amd64; do
      printf '%s %s sha256 %s\n' "${t#*:}" "$f" "$(sha256sum "$work/${t%%:*}/$f" | cut -d ' ' -f1)"
    done
  done
  printf 'CLI version: %s\n' "$("$newcli" version 2>&1 | head -n3 | tr '\n' ' ' || true)"
  printf 'Runner image: %s %s\n' "${ImageOS:-unknown}" "${ImageVersion:-unknown}"
  # shellcheck disable=SC1091
  . /etc/os-release && printf 'OS: %s\n' "$PRETTY_NAME"
  printf 'Harness commit: %s\n' "$(git -C "$here" rev-parse HEAD)"
} | tee "$out/identity.txt"

printf '%s' "$jwt_secret" >"$work/jwt.secret"
chmod 600 "$work/jwt.secret"
mint() { "$newcli" token generate --username "$1" --roles "$2" --expiry 1h --secret-file "$work/jwt.secret" --raw; }
admin_token=$(mint admin admin)
tenant_admin_token=$(mint "$tenant" admin) # acts on its own tenant: lists its secrets and reads system info
tenant_user_token=$(mint "$tenant" user)   # same tenant, no admin role: system info is refused
printf '%s\n' "$tenant" >"$conf"
backup_dir="$work/backups"
mkdir -p "$backup_dir"

start_daemon() { # <daemon binary> <log>
  # The log is written by this (unprivileged) shell on purpose.
  # shellcheck disable=SC2024
  sudo env CONTAINARIUM_BACKUP_DIR="$backup_dir" CONTAINARIUM_BACKUP_VERIFY_IMAGE="$lane_image" \
    "$1" daemon --standalone --rest --app-hosting --jwt-secret "$jwt_secret" --postgres "$pg_url" >"$2" 2>&1 &
  daemon_pid=$!
  local ready=""
  for _ in $(seq 1 60); do
    if curl --fail -sS -H "Authorization: Bearer $admin_token" "http://localhost:8080/v1/backups" >/dev/null 2>&1; then ready=yes; break; fi
    sleep 5
  done
  [ -n "$ready" ] || { echo "daemon never became ready; log:" >&2; tail -60 "$2" >&2; exit 1; }
  # The secrets store is wired by --app-hosting, after the API is up.
  for _ in $(seq 1 30); do
    # 200 once the store is wired; 503 (Unavailable) until then or when it never is.
    if curl --fail -sS -o /dev/null -H "Authorization: Bearer $tenant_admin_token" "http://localhost:8080/v1/secrets/$tenant" 2>/dev/null; then return 0; fi
    sleep 2
  done
  echo "secrets store never became available; log:" >&2; tail -60 "$2" >&2; exit 1
}
stop_daemon() {
  sudo kill "$daemon_pid" 2>/dev/null || true
  for _ in $(seq 1 30); do sudo kill -0 "$daemon_pid" 2>/dev/null || break; sleep 1; done
  daemon_pid=
}

# cli <name> <token> <cli args...>: capture stdout, stderr and status of one
# call into $out/<name>.{out,err,rc}; never aborts the script.
cli() {
  local name=$1 token=$2; shift 2
  set +e
  CONTAINARIUM_HTTP=true CONTAINARIUM_TOKEN="$token" "$newcli" --server "$server" "$@" \
    >"$out/$name.out" 2>"$out/$name.err"
  echo $? >"$out/$name.rc"
  set -e
}
rc_of() { cat "$out/$1.rc"; }

echo "== Daemon $tag (tag under test)"
start_daemon "$newd" "$out/daemon-$tag.log"

# The tenant database the backups dump. Same shape as backup-scoped-token-e2e.sh.
sudo incus launch "$lane_image" "$tenant-container"
sudo incus exec "$tenant-container" -- sh -c '
  set -eu
  if command -v cloud-init >/dev/null 2>&1; then cloud-init status --wait; fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq postgresql-16
  pg_ctlcluster 16 main start || pg_isready -q
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "ALTER USER postgres PASSWORD '\''lane-source-password'\''"
'

echo "== Step 1 (b): no managed key"
curl -sS -H "Authorization: Bearer $admin_token" "http://localhost:8080/v1/system/info" >"$out/sysinfo-$tag.json"
case_run "(b) system info reports no managed key on $tag" mk_sysinfo_no_key "$out/sysinfo-$tag.json"
cli status-b "$tenant_admin_token" backup status --conf "$conf"
case_run "(b) backup status on $tag: UNENCRYPTED line, no warning, exit 1" \
  mk_status_absent "$tenant" "$conf" "$out/status-b.out" "$out/status-b.err" "$(rc_of status-b)"

echo "== Step 2 (c) contrast: create without a recipient"
count_records() { curl -sS -H "Authorization: Bearer $admin_token" "http://localhost:8080/v1/backups?username=$tenant" | jq '.records | length'; }
count_files() { find "$backup_dir" -type f | wc -l; }
cli create-plain "$admin_token" backup create "$tenant" --database postgres --db-password lane-source-password
create_check() { mk_create_unencrypted "$@" >"$out/create-plain.id"; }
case_run "(c) backup create: Encrypted: no, UNENCRYPTED warning, exit 0" \
  create_check "$out/create-plain.out" "$out/create-plain.err" "$(rc_of create-plain)"
records=$(count_records); files=$(count_files)
cli create-refused "$admin_token" backup create "$tenant" --database postgres --db-password lane-source-password --require-encryption
case_run "(c) backup create --require-encryption: refused, names the tenant, non-zero" \
  mk_create_refused "$tenant" "$out/create-refused.out" "$out/create-refused.err" "$(rc_of create-refused)"
case_run "(c) refused create wrote no backup record" mk_record_count "$records" "$(count_records)" 'records after refusal'
case_run "(c) refused create wrote no object" mk_record_count "$files" "$(count_files)" 'files after refusal'

echo "== Step 4 (d) failed lookup: token that cannot read system info"
cli status-d-denied "$tenant_user_token" backup status --conf "$conf"
case_run "(d) failed lookup on $tag: warning on stderr, encryption not confirmed, exit 1" \
  mk_status_unknown "$tenant" "$conf" "$out/status-d-denied.out" "$out/status-d-denied.err" "$(rc_of status-d-denied)"

stop_daemon
echo "== Step 3 (d) older daemon $older (predates #3231), new CLI $tag"
start_daemon "$oldd" "$out/daemon-$older.log"
curl -sS -H "Authorization: Bearer $admin_token" "http://localhost:8080/v1/system/info" >"$out/sysinfo-$older.json"
case_run "(d) older daemon $older reports no managed key" mk_sysinfo_no_key "$out/sysinfo-$older.json"
cli status-d-old "$tenant_admin_token" backup status --conf "$conf"
case_run "(d) $tag CLI against $older daemon: UNENCRYPTED line, no warning, exit 1" \
  mk_status_absent "$tenant" "$conf" "$out/status-d-old.out" "$out/status-d-old.err" "$(rc_of status-d-old)"
stop_daemon

mk_write_summary "$out/results.txt"
echo "== Result"
cat "$out/results.txt"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo "### #3213 managed-key verification: $tag (older: $older)"; echo '```'; cat "$out/results.txt"; echo '```'; } >>"$GITHUB_STEP_SUMMARY"
fi
[ "$failed" -eq 0 ] || { echo "FAIL: at least one case failed" >&2; exit 1; }
echo 'All covered cases passed; (a) and (c)-managed are NOT VERIFIED (no KMS key).'
