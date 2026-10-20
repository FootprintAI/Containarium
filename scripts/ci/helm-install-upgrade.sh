#!/usr/bin/env bash
# Install and upgrade published OCI charts in a disposable kind cluster (#2574).
# Usage: bash scripts/ci/helm-install-upgrade.sh BASE_VERSION VERSION [CANDIDATE_TGZ]
# The optional candidate is stamped with VERSION's appVersion and tested after
# the published upgrade, so PRs also exercise their own chart changes.
set -euo pipefail

base="${1:?usage: helm-install-upgrade.sh BASE_VERSION VERSION [CANDIDATE_TGZ]}"
version="${2:?missing target version}"
candidate="${3:-}"
base="${base#v}"
version="${version#v}"
chart=oci://ghcr.io/footprintai/charts/containarium-k8s
work="$(mktemp -d)"
cluster="helm-release-$(basename "$work" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')"
export KUBECONFIG="$work/kubeconfig"
release=helm-release
namespace=helm-release
gateway=helm-release-gateway
timeout="${HELM_TEST_TIMEOUT:-20m}"

# EXIT handler: preserve the test status, emit diagnostics on failure, then
# remove this invocation's disposable kind cluster and temporary kubeconfig.
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then
    kubectl get pods -A -o wide || true
    for ns in "$namespace" "$gateway"; do
      kubectl -n "$ns" describe pods || true
      kubectl -n "$ns" logs -l "app.kubernetes.io/instance=$release" --all-containers --tail=100 || true
    done
  fi
  kind delete cluster --name "$cluster" || true
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT

# Never use the contributor's current context or a shared dev cluster.
kind create cluster --name "$cluster" --image kindest/node:v1.31.0 --wait 180s

ssh-keygen -q -t ed25519 -N '' -f "$work/server"
ssh-keygen -q -t ed25519 -N '' -f "$work/upstream"
# Create the gateway namespace with Helm ownership and install its host and
# upstream key Secrets. Call before each clean install; failures stop the test.
prepare_gateway() {
  # Secrets must predate installation. The chart manages this Namespace, so
  # give the precreated namespace the same ownership as the Helm release.
  kubectl create namespace "$gateway"
  kubectl label namespace "$gateway" app.kubernetes.io/managed-by=Helm
  kubectl annotate namespace "$gateway" \
    "meta.helm.sh/release-name=$release" "meta.helm.sh/release-namespace=$namespace"
  kubectl -n "$gateway" create secret generic sshpiper-server-key --from-file="server_key=$work/server"
  kubectl -n "$gateway" create secret generic sshpiper-upstream-key --from-file="ssh-privatekey=$work/upstream"
}
prepare_gateway

values=(
  --namespace "$namespace" --create-namespace
  --set fullnameOverride=helm-release
  --set-string "daemon.jwtSecret=$(openssl rand -hex 32)"
  --set-string "gateway.namespace=$gateway"
  --set gateway.upstreamKeySecret=sshpiper-upstream-key
  --set-file "gateway.upstreamPublicKey=$work/upstream.pub"
  --wait --timeout "$timeout"
)

# Require ready daemon and gateway pods with the expected images and pulled
# image IDs. $1 is the daemon version without v; optional $2 overrides only
# the gateway tag for the historical baseline that predates release pinning.
assert_running_release() {
  expected="$1"
  gateway_tag="${2:-v$expected}"
  kubectl -n "$namespace" rollout status deployment/helm-release-daemon --timeout="$timeout"
  kubectl -n "$gateway" rollout status deployment/helm-release-sshpiper --timeout="$timeout"
  kubectl -n "$namespace" get pods -l "app.kubernetes.io/instance=$release" -o json > "$work/pods.json"
  kubectl -n "$gateway" get pods -l "app.kubernetes.io/instance=$release,app.kubernetes.io/name=sshpiper" -o json > "$work/gateway-pods.json"
  python3 - "$work/pods.json" "$work/gateway-pods.json" "$expected" "$gateway_tag" <<'PY'
import json
import sys

images = (
    (sys.argv[1], "daemon", "ghcr.io/footprintai/containarium:v" + sys.argv[3]),
    (sys.argv[2], "sshpiper", "ghcr.io/footprintai/containarium-sshpiper:" + sys.argv[4]),
)
for path, name, expected in images:
    pods = json.load(open(path))["items"]
    running = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
    assert running, f"no current {name} pods"
    for pod in running:
        container = next(c for c in pod["spec"]["containers"] if c["name"] == name)
        assert container["image"] == expected, (container["image"], expected)
        status = next(c for c in pod["status"]["containerStatuses"] if c["name"] == name)
        assert status["ready"] and status.get("imageID"), status
    print("ready, pulled image:", expected)
PY
}

# No image overrides: the image must come from the published chart appVersion.
helm install "$release" "$chart" --version "$base" "${values[@]}"
# This fixed baseline predates gateway pinning (#2703); all target/candidate
# assertions below require the gateway's exact release tag as well.
assert_running_release "$base" latest-stable
helm upgrade "$release" "$chart" --version "$version" "${values[@]}"
assert_running_release "$version"

if [ -n "$candidate" ]; then
  helm upgrade "$release" "$candidate" "${values[@]}"
  assert_running_release "$version"
fi

# A second clean install proves the target also works without an old release.
helm uninstall "$release" --namespace "$namespace" --wait --timeout "$timeout"
prepare_gateway
helm install "$release" "$chart" --version "$version" "${values[@]}"
assert_running_release "$version"
helm history "$release" --namespace "$namespace"
