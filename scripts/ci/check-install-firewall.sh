#!/usr/bin/env bash
# Prove the installers open 50051/tcp in ufw only with --mtls (#3063).
#
# Without --mtls the daemon serves no external gRPC listener
# (internal/server/dual_server.go), so a 50051 allow rule exposes nothing but
# widens the firewall. The installers' setup_firewall (and, for hacks/install.sh,
# parse_args) are extracted and run against a stubbed ufw that records its
# arguments, once without and once with --mtls.
#
# Usage:
#   scripts/ci/check-install-firewall.sh              # test both installers
#   scripts/ci/check-install-firewall.sh --self-test  # seeded broken installers
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# extract_fn SCRIPT NAME prints the top-level shell function NAME from SCRIPT.
extract_fn() {
  awk -v n="$2" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$1"
}

# run_case SCRIPT MTLS(0|1) prints the ufw calls setup_firewall makes.
run_case() {
  local script="$1" mtls="$2" dir out
  dir="$(mktemp -d)"
  mkdir -p "$dir/bin"
  cat > "$dir/bin/ufw" <<STUB
#!/usr/bin/env bash
if [ "\$1" = "status" ]; then echo "Status: active"; exit 0; fi
echo "ufw \$*" >> "$dir/calls"
STUB
  chmod +x "$dir/bin/ufw"
  : > "$dir/calls"
  {
    echo 'log_info() { :; }; log_success() { :; }; log_warn() { :; }'
    echo 'SKIP_FIREWALL=0; ENABLE_MTLS=0'
    extract_fn "$script" parse_args
    extract_fn "$script" setup_firewall
    if [ "$mtls" = 1 ]; then
      if grep -q '^parse_args()' "$script"; then
        echo 'parse_args --mtls'
      else
        echo 'ENABLE_MTLS=1'
      fi
    fi
    echo 'setup_firewall'
  } > "$dir/run.sh"
  PATH="$dir/bin:$PATH" bash "$dir/run.sh" > /dev/null
  out="$(cat "$dir/calls")"
  rm -rf "$dir"
  printf '%s\n' "$out"
}

check() {
  local rc=0 script calls
  for script in "$@"; do
    calls="$(run_case "$script" 0)"
    if grep -q '50051' <<< "$calls"; then
      echo "::error file=${script#"$ROOT"/}::50051/tcp opened without --mtls"
      rc=1
    fi
    if ! grep -q '22/tcp' <<< "$calls" || ! grep -q '8080/tcp' <<< "$calls"; then
      echo "::error file=${script#"$ROOT"/}::22/tcp and 8080/tcp must stay open without --mtls"
      rc=1
    fi
    calls="$(run_case "$script" 1)"
    if ! grep -q '50051/tcp' <<< "$calls"; then
      echo "::error file=${script#"$ROOT"/}::50051/tcp not opened with --mtls"
      rc=1
    fi
  done
  return "$rc"
}

self_test() {
  local dir rc=0 good
  dir="$(mktemp -d)"
  trap 'rm -rf "$dir"' RETURN
  good="$ROOT/hacks/install.sh"
  # shellcheck disable=SC2016 # the ${...} is literal text to match, not an expansion
  # Always opens 50051: the pre-fix behavior.
  sed 's/if \[ "\${ENABLE_MTLS:-0}" = "1" \]; then/if true; then/' "$good" > "$dir/always.sh"
  # Never opens 50051: --mtls would silently do nothing.
  # shellcheck disable=SC2016
  sed 's/if \[ "\${ENABLE_MTLS:-0}" = "1" \]; then/if false; then/' "$good" > "$dir/never.sh"
  if cmp -s "$good" "$dir/always.sh" || cmp -s "$good" "$dir/never.sh"; then
    echo "self-test FAIL: mutation did not apply (guard line changed?)"
    return 1
  fi
  local f
  for f in always never; do
    if check "$dir/$f.sh" > /dev/null; then
      echo "self-test FAIL: $f.sh is broken but passed"
      rc=1
    fi
  done
  [ "$rc" -eq 0 ] && echo "self-test ok: always-open and never-open installers caught"
  return "$rc"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
else
  check "$ROOT/hacks/install.sh" "$ROOT/hacks/offline-install/install.sh"
fi
