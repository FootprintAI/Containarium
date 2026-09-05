#!/usr/bin/env bash
# Regression test for #1732: GNU Make expands $(shell ...) (and re-scans any
# nested $(...) it produces) wherever a recipe body dereferences a variable —
# including one that arrived via a command-line override (`make build
# VERSION=...`). Worse, Make auto-exports every command-line-set variable
# into each recipe's shell environment, which forces that same expansion
# even for a target whose recipe never references the variable at all.
#
# This proves, against the real repo Makefile, that none of the documented
# override points (VERSION, GIT_COMMIT, BUILD_TIME, BUNDLE_VERSION,
# BUNDLE_OS, BUNDLE_ARCH) can execute an attacker-supplied payload, while a
# legitimate override still reaches the build as plain data.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0; fail=0
proof="$(mktemp -u)"

check_inert() { # var payload_kind payload
  local var="$1" kind="$2" payload="$3"
  rm -f "$proof"
  make version "$var=$payload" >/dev/null 2>&1
  if [ -e "$proof" ]; then
    echo "  FAIL  $var=<$kind> executed (proof file created)"
    fail=$((fail+1))
  else
    echo "  PASS  $var=<$kind> did not execute"
    pass=$((pass+1))
  fi
  rm -f "$proof"
}

echo "=== malicious overrides must be inert ==="
for var in VERSION GIT_COMMIT BUILD_TIME BUNDLE_VERSION BUNDLE_OS BUNDLE_ARCH; do
  check_inert "$var" 'make $(shell ...)'   "\$(shell touch $proof)"
  check_inert "$var" 'shell $(...)'        "\$(touch $proof)"
  check_inert "$var" 'shell backtick'      "\`touch $proof\`"
done

echo "=== legitimate overrides must still reach the build as data ==="
out="$(make version VERSION=9.9.9-test-marker 2>/dev/null)"
if [[ "$out" == *"9.9.9-test-marker"* ]]; then
  echo "  PASS  VERSION override reaches \`make version\`"
  pass=$((pass+1))
else
  echo "  FAIL  VERSION override did not reach \`make version\`: $out"
  fail=$((fail+1))
fi

echo "passed=$pass failed=$fail"
[ "$fail" = "0" ]
