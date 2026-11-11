#!/usr/bin/env bash
# Template test for daemon.insecureIgnoreHostKey (#3628).
#
# The chart used to hardcode CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY=1 in
# the daemon Deployment. It is now off by default and set only by the
# daemon.insecureIgnoreHostKey value.
#
# Usage: scripts/ci/helm-chart-host-key.sh [chart-dir]
set -euo pipefail

chart="${1:-charts/containarium-k8s}"
env_name=CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY
failures=0

render() {
  helm template containarium "$chart" \
    --set gateway.upstreamKeySecret=smoke-test-placeholder \
    --set daemon.jwtSecret=0123456789abcdef0123456789abcdef0123456789abcdef \
    --show-only templates/daemon-deployment.yaml "$@"
}

default="$(render)"
if grep -q "$env_name" <<<"$default"; then
  echo "::error::default render sets $env_name; it must be absent"
  failures=$((failures + 1))
fi

explicit_false="$(render --set daemon.insecureIgnoreHostKey=false)"
if grep -q "$env_name" <<<"$explicit_false"; then
  echo "::error::daemon.insecureIgnoreHostKey=false sets $env_name; it must be absent"
  failures=$((failures + 1))
fi

opt_in="$(render --set daemon.insecureIgnoreHostKey=true)"
if ! grep -A1 "name: $env_name" <<<"$opt_in" | grep -q 'value: "1"'; then
  echo "::error::daemon.insecureIgnoreHostKey=true does not set $env_name to \"1\""
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  exit 1
fi
echo "host-key chart assertions passed"
