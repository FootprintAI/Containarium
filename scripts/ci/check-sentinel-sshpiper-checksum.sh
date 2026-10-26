#!/usr/bin/env bash
# Prove both sentinel startup scripts verify the sshpiperd tarball (#3103).
#
# ssh-ban.yml pins the v1.6.1 release tarball by sha256 (#3087). The two
# sentinel startup scripts fetch the same tarball on a real sentinel boot, so
# each must check the same value between the curl and the tar, under
# `set -e`, so a mismatch fails the boot step. This gate fails when either
# script has no SSHPIPER_SHA256 pin, no `sha256sum -c` between the download
# and the extraction, or a value that differs from the workflow's.
#
# Usage:
#   scripts/ci/check-sentinel-sshpiper-checksum.sh              # check the repo
#   scripts/ci/check-sentinel-sshpiper-checksum.sh --self-test  # seeded broken copies
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW=".github/workflows/ssh-ban.yml"
SCRIPTS=(
  "terraform/modules/containarium/scripts/startup-sentinel.sh"
  "terraform/gce/scripts/startup-sentinel.sh"
)
HEX='[0-9a-f]{64}'

# check ROOT prints one line per problem found under ROOT.
check() {
  local root="$1" want f got
  want="$(grep 'sshpiperd_with_plugins' "$root/$WORKFLOW" | grep -oE "$HEX" | sort -u || true)"
  if [ "$(printf '%s\n' "$want" | grep -c .)" -ne 1 ]; then
    echo "$WORKFLOW: expected exactly one sshpiperd tarball sha256, found: ${want:-none}"
    return
  fi
  for f in "${SCRIPTS[@]}"; do
    got="$(grep -E "^SSHPIPER_SHA256=\"$HEX\"" "$root/$f" | grep -oE "$HEX" || true)"
    if [ "$got" != "$want" ]; then
      echo "$f: SSHPIPER_SHA256 is '${got:-missing}', $WORKFLOW pins $want"
    fi
    # sha256sum -c must sit between the curl and the tar extraction.
    if ! awk '
      /curl .*sshpiper/ {c=1}
      c && /sha256sum -c/ && /SSHPIPER_SHA256/ {v=1}
      c && /tar x/ {if (v) ok=1; exit}
      END {exit !ok}' "$root/$f"; then
      echo "$f: no sha256sum -c of \$SSHPIPER_SHA256 between the curl and the tar"
    fi
  done
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  fresh() {
    rm -rf "$tmp/r"
    mkdir -p "$tmp/r/.github/workflows"
    cp -r "$ROOT/terraform" "$tmp/r/"
    cp "$ROOT/$WORKFLOW" "$tmp/r/$WORKFLOW"
  }
  expect_fail() {
    if [ -z "$(check "$tmp/r")" ]; then
      echo "self-test: '$1' was not caught" >&2
      exit 1
    fi
  }
  fresh
  if [ -n "$(check "$tmp/r")" ]; then
    echo "self-test: clean copy flagged" >&2
    check "$tmp/r" >&2
    exit 1
  fi
  bad="$(printf 'a%.0s' {1..64})"
  fresh
  sed -i -E 's/^SSHPIPER_SHA256="[0-9a-f]{64}"/SSHPIPER_SHA256="'"$bad"'"/' "$tmp/r/${SCRIPTS[0]}"
  expect_fail "wrong value"
  fresh
  sed -i '/sha256sum -c/d' "$tmp/r/${SCRIPTS[1]}"
  expect_fail "verify step removed"
  fresh
  sed -i '/^SSHPIPER_SHA256=/d' "$tmp/r/${SCRIPTS[1]}"
  expect_fail "pin removed"
  echo "self-test ok"
  exit 0
fi

out="$(check "$ROOT")"
if [ -n "$out" ]; then
  echo "$out" >&2
  exit 1
fi
echo "ok: both sentinel startup scripts verify the sshpiperd tarball with the pinned sha256"
