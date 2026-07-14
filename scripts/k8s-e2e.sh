#!/usr/bin/env bash
#
# k8s-e2e.sh — spin up a throwaway kind cluster and run the K8s agent-box
# backend's e2e suite (the reconciler driven against a real apiserver).
#
# Local use:    bash scripts/k8s-e2e.sh
# Keep cluster: E2E_KEEP=1 bash scripts/k8s-e2e.sh   (skips teardown for debugging)
# CI:           invoked by .github/workflows/k8s-e2e.yml on an ubuntu runner.
#
# Requirements: kind, kubectl, go, and a working Docker daemon (all
# preinstalled on the GitHub ubuntu-latest runner). kubectl installs the
# agent-sandbox controller; the e2e itself talks to the apiserver via
# client-go.
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

# The box backend declares agent-sandbox Sandbox CRs; the agent-sandbox
# controller (kubernetes-sigs/agent-sandbox) owns the pod + Service under
# them, so it must run in the cluster for the lifecycle e2e to converge.
# Note: v0.5.1's install asset is manifest.yaml (their README still says
# sandbox-with-extensions.yaml, which 404s).
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.5.1}"
echo "==> installing agent-sandbox controller ${AGENT_SANDBOX_VERSION}"
command -v kubectl >/dev/null || { echo "kubectl is required to install the agent-sandbox controller" >&2; exit 1; }
kubectl apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml"
# The manifest installs Deployment agent-sandbox-controller in namespace
# agent-sandbox-system (it does NOT carry the kubebuilder-conventional
# control-plane=controller-manager label — a label-selector wait matches
# nothing and kubectl exits "no matching resources found").
kubectl -n agent-sandbox-system wait --for=condition=available \
  deployment/agent-sandbox-controller --timeout=180s

echo "==> running K8s agent-box e2e (reconciler vs. the kind apiserver)"
CONTAINARIUM_K8S_E2E=1 go test -tags k8s -run TestE2E -timeout 12m -v ./pkg/core/box/k8s/

echo "==> e2e passed"
