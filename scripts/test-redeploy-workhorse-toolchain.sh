#!/usr/bin/env bash
# Prove redeploy-workhorse.sh reports the host's managed toolchain release
# (#3360): since v0.123.0 BUILD_TOOLS runs are refused without one, and a
# binary-only upgrade does not install it. `status` and a successful `deploy`
# share toolchain_report; this runs `status` against a temporary toolchain
# root, so it needs no root, no daemon and no network.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/redeploy-workhorse.sh"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
fail=0

run_status() { CTN_TOOLCHAIN_ROOT="$1" CTN_BIN="$work/no-such-binary" bash "$script" status 2>&1; }

expect() { # <name> <output> <grep -E pattern> <want: present|absent>
  if printf '%s\n' "$2" | grep -qE -- "$3"; then found=present; else found=absent; fi
  if [ "$found" = "$4" ]; then echo "PASS: $1"; else echo "FAIL: $1 (pattern '$3' $found, want $4)"; printf '%s\n' "$2" | sed 's/^/    /'; fail=1; fi
}

# 1. No toolchain installed: warn, name the consequence and the doc.
out="$(run_status "$work/missing")"
expect "missing release warns" "$out" 'WARNING: no managed toolchain release' present
expect "missing release names BUILD_TOOLS" "$out" 'BUILD_TOOLS runs are refused' present
expect "missing release points at the doc" "$out" 'docs/MANAGED-TOOLCHAINS.md' present

# 2. A release installed: report it, no warning.
mkdir -p "$work/installed/releases/v0.123.0"
printf '{"schema_version":1,"release":"v0.123.0","arch":"amd64"}\n' > "$work/installed/releases/v0.123.0/manifest.json"
ln -s releases/v0.123.0 "$work/installed/current"
out="$(run_status "$work/installed")"
expect "installed release is reported" "$out" 'toolchain: .*releases/v0.123.0' present
expect "installed release does not warn" "$out" 'no managed toolchain release' absent

exit "$fail"
