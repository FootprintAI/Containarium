#!/usr/bin/env bash
#
# k8s-e2e.sh — spin up a throwaway kind cluster and run the K8s agent-box
# backend's e2e suite (the reconciler driven against a real apiserver).
#
# Local use:    bash scripts/k8s-e2e.sh
# Keep cluster: E2E_KEEP=1 bash scripts/k8s-e2e.sh   (skips teardown for debugging)
# CI:           invoked by .github/workflows/k8s-e2e.yml on an ubuntu runner.
#
# Requirements: kind, go, and a working Docker daemon (preinstalled on the
# GitHub ubuntu-latest runner). kubectl is NOT required — the e2e talks to the
# apiserver via client-go, not the CLI.
#
# Note: kind's default CNI (kindnet) does NOT enforce NetworkPolicy, so this
# suite asserts the reconciler creates the right objects + the pod lifecycle,
# not egress *enforcement*. Testing NetworkPolicy enforcement needs a
# Calico-backed kind config — tracked as a follow-up.
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-containarium-k8s-e2e}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

KUBECONFIG_FILE="$(mktemp)"
export KUBECONFIG="$KUBECONFIG_FILE"

cleanup() {
  if [ "${E2E_KEEP:-}" = "1" ]; then
    echo "==> E2E_KEEP=1 — leaving cluster '$CLUSTER' up (KUBECONFIG=$KUBECONFIG_FILE)"
    return
  fi
  echo "==> tearing down kind cluster '$CLUSTER'"
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  rm -f "$KUBECONFIG_FILE"
}
trap cleanup EXIT

echo "==> creating kind cluster '$CLUSTER'"
kind create cluster --name "$CLUSTER" --wait 120s

echo "==> running K8s agent-box e2e (reconciler vs. the kind apiserver)"
CONTAINARIUM_K8S_E2E=1 go test -tags k8s -run TestE2E -timeout 12m -v ./pkg/core/box/k8s/

echo "==> e2e passed"
