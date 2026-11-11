#!/usr/bin/env bash
# Template test for the containarium-k8s daemon JWT secret guard (#3442).
#
# The chart used to ship daemon.jwtSecret="change-me-please-use-a-real-secret"
# and render it into the daemon Secret unchecked, so an install that forgot
# --set daemon.jwtSecret=... ran a control plane whose tokens anyone who has
# read the public chart could forge. This asserts the chart now refuses to
# render with the shipped default, an explicit empty value, or the old
# placeholder, and that a real value renders into the Secret.
#
# Usage: scripts/ci/helm-chart-jwt-secret.sh [chart-dir]
set -euo pipefail

chart="${1:-charts/containarium-k8s}"
placeholder="change-me-please-use-a-real-secret"
# Synthetic test value, not a credential.
real="0123456789abcdef0123456789abcdef0123456789abcdef"
failures=0

render() {
  helm template containarium "$chart" \
    --set gateway.upstreamKeySecret=smoke-test-placeholder \
    --show-only templates/daemon-secret.yaml "$@" 2>&1
}

# expect_refused NAME HELM-ARGS... — the render must fail, and the error must
# name the value to set and how to generate one.
expect_refused() {
  local name="$1"; shift
  local out
  if out="$(render "$@")"; then
    echo "::error::$name: chart rendered; expected it to refuse"
    echo "$out"
    failures=$((failures + 1))
    return
  fi
  if ! grep -q 'daemon.jwtSecret' <<<"$out" || ! grep -q 'openssl rand -hex' <<<"$out"; then
    echo "::error::$name: chart refused, but the error does not name daemon.jwtSecret and how to generate it"
    echo "$out"
    failures=$((failures + 1))
    return
  fi
  echo "ok: $name refused"
}

expect_refused "shipped default (no --set)"
expect_refused "empty value" --set-string daemon.jwtSecret=
expect_refused "shipped placeholder" --set-string "daemon.jwtSecret=$placeholder"

if out="$(render --set-string "daemon.jwtSecret=$real")" &&
  grep -q "jwt-secret: \"$real\"" <<<"$out"; then
  echo "ok: real value renders into the daemon Secret"
else
  echo "::error::real value: chart did not render it into the daemon Secret"
  echo "$out"
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures jwtSecret guard case(s) failed"
  exit 1
fi
echo "all jwtSecret guard cases passed"
