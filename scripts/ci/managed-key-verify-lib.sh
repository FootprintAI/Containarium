#!/usr/bin/env bash
# Output checkers for the #3213 managed-backup-key verification harness
# (scripts/ci/managed-key-verify.sh). Sourced, never run. Each check takes the
# captured stdout file, stderr file and exit status of one CLI call, prints
# what is wrong and returns non-zero on any mismatch, so a changed line, a
# changed exit status or a stray/missing `warning:` line cannot pass.
#
# The expected strings are quoted from the shipped code (v0.121.0 and later):
#   internal/cmd/backup_status.go   checkBackupRecipients, runBackupStatus
#   internal/cmd/backup_create.go   printCreatedBackups
#   internal/server/backup_server.go refusePlaintext
# scripts/ci/test-managed-key-verify.sh proves each check can fail.

mk_secret=CONTAINARIUM_BACKUP_AGE_RECIPIENT

mk_fail() { echo "FAIL: $*" >&2; return 1; }

# mk_has_line <file> <exact line>: the whole line must be present.
mk_has_line() {
  grep -Fxq -- "$2" "$1" || mk_fail "expected exact line not found in $1: $2"
}

# mk_has_text <file> <substring>
mk_has_text() {
  grep -Fq -- "$2" "$1" || mk_fail "expected text not found in $1: $2"
}

# mk_count_warning <file>: number of lines that start with "warning:".
mk_count_warning() { grep -c '^warning:' "$1" || true; }

# mk_no_warning <out> <err>: no `warning:` line on either stream.
mk_no_warning() {
  local n
  n=$(( $(mk_count_warning "$1") + $(mk_count_warning "$2") ))
  [ "$n" -eq 0 ] || mk_fail "unexpected 'warning:' line (count $n) in $1 / $2"
}

# mk_rc <want> <got> <what>
mk_rc() {
  [ "$2" -eq "$1" ] || mk_fail "$3: exit status $2, expected $1"
}

# mk_sysinfo_no_key <json-file>: /v1/system/info must not report a managed key.
mk_sysinfo_no_key() {
  jq -e '.info != null and ((.info.managedBackupKeyConfigured // false) == false)' "$1" >/dev/null ||
    mk_fail "system info is missing or reports managedBackupKeyConfigured=true: $(cat "$1")"
}

# mk_status_absent <tenant> <conf> <out> <err> <rc>
# Steps 1 and 3: the daemon answered and reports no managed key. The tenant
# has no recipient, so it is flagged UNENCRYPTED, there is no `warning:`
# line, and the command exits 1.
mk_status_absent() {
  local tenant=$1 conf=$2 out=$3 err=$4 rc=$5 bad=0
  mk_rc 1 "$rc" 'backup status' || bad=1
  mk_has_line "$out" "Backup encryption for tenants in $conf:" || bad=1
  mk_has_line "$out" "  ✗ $tenant — no $mk_secret registered: its dump will be stored UNENCRYPTED (this daemon reports no managed backup key)" || bad=1
  mk_no_warning "$out" "$err" || bad=1
  mk_has_text "$err" '1 of 1 configured tenant(s) have no backup recipient on this daemon or could not be checked' || bad=1
  return "$bad"
}

# mk_status_unknown <tenant> <conf> <out> <err> <rc>
# Step 4: the system-info lookup failed. A warning on stderr, the tenant is
# reported "encryption not confirmed", exit 1.
mk_status_unknown() {
  local tenant=$1 conf=$2 out=$3 err=$4 rc=$5 bad=0
  mk_rc 1 "$rc" 'backup status (failed lookup)' || bad=1
  mk_has_line "$out" "Backup encryption for tenants in $conf:" || bad=1
  mk_has_line "$out" "  ✗ $tenant — no $mk_secret registered and the daemon's managed backup key could not be checked: encryption not confirmed" || bad=1
  [ "$(mk_count_warning "$err")" -eq 1 ] || { mk_fail "expected exactly one 'warning:' line on stderr in $err"; bad=1; }
  mk_has_text "$err" 'warning: could not tell whether the daemon has a managed backup key (failed to get system info: ' || bad=1
  mk_has_text "$err" '); tenants with no recipient will be reported as encryption not confirmed' || bad=1
  [ "$(mk_count_warning "$out")" -eq 0 ] || { mk_fail "'warning:' must be on stderr, not stdout ($out)"; bad=1; }
  return "$bad"
}

# mk_create_unencrypted <out> <err> <rc>: step 2, plain create succeeds but
# says so loudly.
mk_create_unencrypted() {
  local out=$1 rc=$3 bad=0 id
  mk_rc 0 "$rc" 'backup create' || bad=1
  mk_has_line "$out" '      Encrypted: no' || bad=1
  id=$(sed -n 's/^      WARNING: backup \(.*\) was stored UNENCRYPTED (no age recipient registered or given)$/\1/p' "$out" | head -n1)
  [ -n "$id" ] || { mk_fail "UNENCRYPTED warning line not found in $out"; bad=1; }
  grep -Fq 'Encrypted: yes' "$out" && { mk_fail "output claims Encrypted: yes ($out)"; bad=1; }
  printf '%s\n' "$id"
  return "$bad"
}

# mk_create_refused <tenant> <out> <err> <rc>: step 2, --require-encryption.
mk_create_refused() {
  local tenant=$1 out=$2 err=$3 rc=$4 bad=0
  [ "$rc" -ne 0 ] || { mk_fail 'backup create --require-encryption exited 0'; bad=1; }
  mk_has_text "$err" "refusing to store tenant $tenant's backup unencrypted (require_encryption)" || bad=1
  grep -Fq 'Encrypted: no' "$out" && { mk_fail "a record was printed for the refused create ($out)"; bad=1; }
  return "$bad"
}

# mk_record_count <want> <got> <what>: the refused create must write no object.
mk_record_count() {
  [ "$2" -eq "$1" ] || mk_fail "$3: $2 backup record(s), expected $1"
}

# mk_write_summary <out-file> <failures>... : the honest result summary.
# Cases the harness cannot cover are listed as NOT VERIFIED, never as PASS.
mk_write_summary() {
  local file=$1
  {
    cat "$file.cases" 2>/dev/null || true
    echo 'NOT VERIFIED (no KMS key): (a) managed key present - needs CONTAINARIUM_KMS_BACKEND=gcp and a real CryptoKey (Q14)'
    echo 'NOT VERIFIED (no KMS key): (c)-managed managed-key backup is encrypted - same requirement'
  } >"$file"
}
