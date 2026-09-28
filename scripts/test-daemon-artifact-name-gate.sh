#!/usr/bin/env bash
# Daemon-artifact-name gate for the CLI client/server split, Rollout
# Phase 2 (#1784, docs/architecture/cli-client-server-split.md).
#
# From Phase 2 on, the containarium-<os>-<arch> release artifacts are the
# CLIENT build. A host-side installer, provisioner, bundle script or
# terraform file that still downloads (or copies out of bin/) a
# containarium-linux-* / containarium-${OS}-* artifact and installs it as
# the daemon would put the client where containariumd belongs — the unit
# then fails at start with the moved-command stub. Every such consumer
# must name containariumd-<os>-<arch> instead.
#
# This is the release-artifact companion of test-old-binary-path-gate.sh
# (#1781), which covers the on-host INSTALL path; this covers the SOURCE
# artifact name. Go code is pinned separately by
# internal/sentinel/artifact_name_test.go (releaseBinaryName).
#
# .github/workflows/ is not scanned: release.yml legitimately lists
# bin/containarium-* as upload files (the client artifacts themselves).
set -uo pipefail
cd "$(dirname "$0")/.."

# containarium-linux-…  or  containarium-${OS}-… / containarium-$OS-…
# (the trailing "-" after containarium excludes containariumd-*).
PATTERN='containarium-(linux-|\$\{?OS\}?-)'

# Files whose remaining hits are NOT release-artifact consumers.
ALLOWLIST=(
  # The client-only installer (laptops, CI runners): containarium-* is
  # exactly the artifact it should fetch.
  "hacks/install-cli.sh"
  # These three use the LOCAL `make build-linux` output, which is still the
  # daemon built under the historical name (not a release artifact; out of
  # #1784's scope — tracked separately).
  "scripts/deploy-binary.sh"
  "scripts/setup-peer.sh"
  "scripts/install-lab-tunnel.sh"
)

is_allowlisted() {
  local f="$1"
  for a in "${ALLOWLIST[@]}"; do
    [ "$f" = "$a" ] && return 0
  done
  return 1
}

SELF="scripts/$(basename "$0")"
fail=0
while IFS= read -r -d '' file; do
  [ "$file" = "$SELF" ] && continue
  case "$file" in .github/workflows/*) continue ;; esac
  hits="$(grep -nE "$PATTERN" "$file" 2>/dev/null || true)"
  [ -z "$hits" ] && continue
  is_allowlisted "$file" && continue
  echo "FAIL  $file consumes a containarium-* artifact (the client build from Phase 2) where the daemon is meant:"
  echo "$hits" | sed 's/^/        /'
  fail=1
done < <(git ls-files -z -- '*.sh' '*.tf' '*.tpl' '*.yaml' '*.yml')

# Dead allow-list entries would silently hide a real regression later.
for a in "${ALLOWLIST[@]}"; do
  if [ ! -f "$a" ] || ! grep -qE "$PATTERN" "$a"; then
    echo "FAIL  allow-list entry '$a' no longer matches — remove it from $SELF"
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "PASS  no host-side file consumes containarium-<os>-<arch> as the daemon"
fi
exit $fail
