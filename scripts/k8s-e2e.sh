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

# kind's default CNI (kindnet) does NOT enforce NetworkPolicy, so a cluster
# built with it silently passes every isolation assertion — the per-tenant
# default-deny policy is created and then ignored. That is how #1195 (ingress
# restricted to the sshpiper pod, egress to cluster DNS) merged on a green
# e2e that could not have failed. See #1234.
#
# Calico enforces NetworkPolicy, so the isolation cases below are real. Set
# E2E_CNI=kindnet to opt out (faster startup, but NetworkPolicy assertions
# become vacuous — the e2e skips them rather than passing them falsely).
E2E_CNI="${E2E_CNI:-calico}"

echo "==> creating kind cluster '$CLUSTER' (cni=$E2E_CNI)"
if [ "$E2E_CNI" = "calico" ]; then
  KIND_CFG="$(mktemp)"
  cat >"$KIND_CFG" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
EOF
  # --wait is pointless before a CNI exists: nodes stay NotReady until Calico
  # lands, so wait for node readiness after installing it instead.
  kind create cluster --name "$CLUSTER" --config "$KIND_CFG"
  rm -f "$KIND_CFG"

  echo "==> installing Calico (NetworkPolicy enforcement)"
  kubectl apply -f "${CALICO_MANIFEST:-https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml}"
  kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
  kubectl wait --for=condition=ready node --all --timeout=180s
else
  kind create cluster --name "$CLUSTER" --wait 120s
fi

# The box backend declares agent-sandbox Sandbox CRs; the agent-sandbox
# controller (kubernetes-sigs/agent-sandbox) owns the pod + Service under
# them, so it must run in the cluster for the lifecycle e2e to converge.
# Note: the install asset is manifest.yaml (their README says
# sandbox-with-extensions.yaml, which 404s for this release).
#
# Keep this in step with the sigs.k8s.io/agent-sandbox version in go.mod.
# Skew matters: 0.5.4 is the release that makes the Suspended condition
# always present, which stateOf now reads (#1186). Pinned at v0.5.1 the e2e
# exercised only the pre-0.5.4 fallback path, so the new behavior was never
# covered here.
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.5.4}"
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
