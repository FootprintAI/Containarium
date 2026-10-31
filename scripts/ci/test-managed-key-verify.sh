#!/usr/bin/env bash
# Self-test for scripts/ci/managed-key-verify-lib.sh (#3306). The checkers are
# the only thing standing between a wrong CLI output and a green run, so each
# one must accept the exact good output and reject every way of being wrong:
# a changed line, a changed exit status, a stray or missing `warning:` line,
# a record written by a refused create, and a summary that hides the cases
# the harness cannot cover.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/ci/managed-key-verify-lib.sh
. "$here/managed-key-verify-lib.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tn=tenanta
conf=/etc/containarium/backup-tenants.conf
secret=CONTAINARIUM_BACKUP_AGE_RECIPIENT

absent_line="  ✗ $tn — no $secret registered: its dump will be stored UNENCRYPTED (this daemon reports no managed backup key)"
unknown_line="  ✗ $tn — no $secret registered and the daemon's managed backup key could not be checked: encryption not confirmed"
header="Backup encryption for tenants in $conf:"
errcount='Error: 1 of 1 configured tenant(s) have no backup recipient on this daemon or could not be checked'
warn='warning: could not tell whether the daemon has a managed backup key (failed to get system info: forbidden); tenants with no recipient will be reported as encryption not confirmed'

# fixture <name> <content>: write a fixture file and print its path.
fixture() { printf '%s\n' "$2" >"$tmp/$1"; echo "$tmp/$1"; }
quiet() { "$@" >/dev/null 2>&1; }
# ok <label> <cmd...>: must pass.   bad <label> <cmd...>: must fail.
ok()  { local l=$1; shift; if quiet "$@"; then echo "ok: $l"; else echo "FAIL: good output rejected: $l"; exit 1; fi; }
bad() { local l=$1; shift; if quiet "$@"; then echo "FAIL: wrong output accepted: $l"; exit 1; else echo "ok: rejected: $l"; fi; }

# --- status, daemon reports no managed key (steps 1 and 3) -----------------
out=$(fixture a.out "$header
$absent_line"); err=$(fixture a.err "$errcount")
ok 'absent: exact output, exit 1' mk_status_absent $tn $conf "$out" "$err" 1
bad 'absent: exit 0' mk_status_absent $tn $conf "$out" "$err" 0
bad 'absent: exit 2' mk_status_absent $tn $conf "$out" "$err" 2
o=$(fixture b.out "$header
${absent_line/UNENCRYPTED/unencrypted}")
bad 'absent: reworded line' mk_status_absent $tn $conf "$o" "$err" 1
o=$(fixture c.out "$header
  ✓ $tn — age recipient registered")
bad 'absent: tenant reported OK' mk_status_absent $tn $conf "$o" "$err" 1
o=$(fixture d.out "$header
${absent_line/ (this daemon reports no managed backup key)/}")
bad 'absent: missing "(this daemon reports no managed backup key)"' mk_status_absent $tn $conf "$o" "$err" 1
e=$(fixture e.err "$warn
$errcount")
bad 'absent: stray warning on stderr' mk_status_absent $tn $conf "$out" "$e" 1
o=$(fixture f.out "$header
$absent_line
warning: something")
bad 'absent: stray warning on stdout' mk_status_absent $tn $conf "$o" "$err" 1
bad 'absent: unknown-state line instead' mk_status_absent $tn $conf "$(fixture g.out "$header
$unknown_line")" "$err" 1
bad 'absent: wrong tenant' mk_status_absent other $conf "$out" "$err" 1
bad 'absent: wrong conf path' mk_status_absent $tn /tmp/x.conf "$out" "$err" 1
bad 'absent: missing failure count' mk_status_absent $tn $conf "$out" "$(fixture h.err 'Error: boom')" 1

# --- status, lookup failed (step 4) ----------------------------------------
out=$(fixture u.out "$header
$unknown_line"); err=$(fixture u.err "$warn
$errcount")
ok 'unknown: exact output, warning, exit 1' mk_status_unknown $tn $conf "$out" "$err" 1
bad 'unknown: exit 0' mk_status_unknown $tn $conf "$out" "$err" 0
bad 'unknown: warning missing' mk_status_unknown $tn $conf "$out" "$(fixture v.err "$errcount")" 1
bad 'unknown: warning reworded' mk_status_unknown $tn $conf "$out" "$(fixture w.err "${warn/could not tell/cannot say}
$errcount")" 1
bad 'unknown: warning lacks "failed to get system info"' mk_status_unknown $tn $conf "$out" "$(fixture x.err "${warn/failed to get system info: /}
$errcount")" 1
bad 'unknown: warning twice' mk_status_unknown $tn $conf "$out" "$(fixture y.err "$warn
$warn
$errcount")" 1
bad 'unknown: warning on stdout only' mk_status_unknown $tn $conf "$(fixture z.out "$header
$unknown_line
$warn")" "$(fixture z.err "$errcount")" 1
bad 'unknown: UNENCRYPTED line instead (lookup treated as Absent)' mk_status_unknown $tn $conf "$(fixture p.out "$header
$absent_line")" "$err" 1

# --- create (step 2) --------------------------------------------------------
cid=db-backup-1
out=$(fixture c1.out "Backing up $tn database \"postgres\" to local...

✓ 1 backup(s) created
  - $cid (db: postgres)
      Size:     1.0 KiB
      SHA-256:  abc
      Location: /var/backups/x
      Encrypted: no
      WARNING: backup $cid was stored UNENCRYPTED (no age recipient registered or given)")
empty=$(fixture empty.err '')
got=$(mk_create_unencrypted "$out" "$empty" 0 2>/dev/null)
[ "$got" = "$cid" ] || { echo "FAIL: backup id not extracted, got '$got'"; exit 1; }
echo 'ok: create: exact output, exit 0, backup id extracted'
bad 'create: exit 1' mk_create_unencrypted "$out" "$empty" 1
bad 'create: "Encrypted: no" missing' mk_create_unencrypted "$(fixture c2.out "${out//Encrypted: no/Encrypted: maybe}")" "$empty" 0
bad 'create: WARNING missing' mk_create_unencrypted "$(fixture c3.out "${out//WARNING/NOTE}")" "$empty" 0
bad 'create: claims Encrypted: yes' mk_create_unencrypted "$(fixture c4.out "$out
      Encrypted: yes (to age1x)")" "$empty" 0

rerr=$(fixture r.err "Error: refusing to store tenant $tn's backup unencrypted (require_encryption): no age recipient was given or registered ($secret) and this daemon has no managed backup key")
ok 'refused: names the tenant, exit 1' mk_create_refused $tn "$tmp/empty.err" "$rerr" 1
bad 'refused: exit 0' mk_create_refused $tn "$tmp/empty.err" "$rerr" 0
bad 'refused: other tenant named' mk_create_refused other "$tmp/empty.err" "$rerr" 1
bad 'refused: different reason' mk_create_refused $tn "$tmp/empty.err" "$(fixture r2.err 'Error: connection refused')" 1
bad 'refused: a record was created' mk_create_refused $tn "$out" "$rerr" 1
ok 'records: unchanged count' mk_record_count 1 1 refused
bad 'records: an object was written' mk_record_count 1 2 refused

# --- system info -------------------------------------------------------------
ok 'sysinfo: field absent (older daemon)' mk_sysinfo_no_key "$(fixture s1.json '{"info":{"hostname":"h"}}')"
ok 'sysinfo: field false' mk_sysinfo_no_key "$(fixture s2.json '{"info":{"managedBackupKeyConfigured":false}}')"
bad 'sysinfo: field true' mk_sysinfo_no_key "$(fixture s3.json '{"info":{"managedBackupKeyConfigured":true}}')"
bad 'sysinfo: no info object' mk_sysinfo_no_key "$(fixture s4.json '{"code":403}')"

# --- summary: never silent, never PASS for the uncovered cases ----------------
printf 'PASS (b) one\n' >"$tmp/sum.cases"
mk_write_summary "$tmp/sum"
ok 'summary: (a) NOT VERIFIED' grep -Fq 'NOT VERIFIED (no KMS key): (a) managed key present' "$tmp/sum"
ok 'summary: (c)-managed NOT VERIFIED' grep -Fq 'NOT VERIFIED (no KMS key): (c)-managed' "$tmp/sum"
bad 'summary: (a) reported as PASS' grep -Eq '^PASS \((a|c)' "$tmp/sum"
echo 'managed-key harness self-test: all checks behave'
