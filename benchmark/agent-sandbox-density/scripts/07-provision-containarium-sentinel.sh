#!/bin/bash
#
# Provision the "sentinel-statefulset" benchmark scenario: the same shared
# base cluster + gVisor as 03-provision-containarium.sh, but with
# Containarium's daemon fronted by the topology documented in README.md's
# "The experiment group's k8s footprint" — a Service, a Deployment running
# a stand-in "sentinel" that forwards traffic, and a StatefulSet running
# the daemon itself — instead of the chart's own single Deployment.
#
# This is a BENCHMARK-ONLY exploration, not a proposed production chart
# change. See manifests/sentinel-statefulset/README.md for why: the real
# daemon is stateless (no PVCs, all durable state in the k8s API/etcd via
# CRDs), so a StatefulSet buys it nothing architecturally — this exists to
# put a real number on what the topology costs, not to recommend building
# it. `charts/containarium-k8s/` is untouched by this script.
#
# How the daemon's container spec gets here without hand-duplicating Helm's
# logic: this still `helm install`s the real chart (same as 03), but with
# `daemon.replicaCount=0` so its own Deployment never actually runs a pod.
# The resulting (0-replica but fully-specced) Deployment object is read
# back with `kubectl get -o json` and reshaped into a StatefulSet with
# `jq` — the container spec (image, env, probes, ports) is copied exactly
# from what Helm computed, not re-typed by hand, so it can't drift from
# what the chart actually produces.
#
# Usage:
#   scripts/07-provision-containarium-sentinel.sh --name <vm-name>
#
# Assumes the guest is Ubuntu Server 24.04 with passwordless sudo for
# REMOTE_SSH_USER, same as 03-provision-containarium.sh.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh
# shellcheck source=k8s-common.sh
source ./k8s-common.sh

VM_NAME=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	--name)
		VM_NAME="$2"
		shift 2
		;;
	-h | --help)
		grep '^#' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		die "unknown argument: $1"
		;;
	esac
done
[[ -n "$VM_NAME" ]] || die "usage: $0 --name <vm-name>"

load_config
require_vars K8S_MAX_PODS AGENT_SANDBOX_VERSION CONTAINARIUM_VERSION GVISOR_RUNTIME_CLASS REMOTE_SSH_USER BENCH_SSH_KEY_FILE
resolve_remote "$VM_NAME"

log "provisioning Containarium sentinel-statefulset scenario on '${VM_NAME}'"
provision_base_k8s
install_gvisor

log "installing Helm and jq (jq drives the Deployment->StatefulSet reshape below)"
ssh_or_local "curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash"
ssh_or_local "sudo apt-get install -y -qq jq git >/dev/null"

log "resolving Containarium ${CONTAINARIUM_VERSION} and fetching the chart + CLI"
ssh_or_local "sudo bash -s" <<REMOTE
set -euo pipefail
TAG="${CONTAINARIUM_VERSION}"
if [[ "\$TAG" == "latest" ]]; then
	TAG=\$(curl -fsSL https://api.github.com/repos/FootprintAI/Containarium/releases/latest | jq -r .tag_name)
fi
echo "resolved tag: \$TAG"
echo "\$TAG" >/tmp/containarium-resolved-tag

BASE_URL="https://github.com/FootprintAI/Containarium/releases/download/\${TAG}"
curl -fsSL -o /tmp/containarium "\${BASE_URL}/containarium-linux-amd64"
curl -fsSL -o /tmp/SHA256SUMS.txt "\${BASE_URL}/SHA256SUMS.txt"
EXPECTED=\$(grep 'containarium-linux-amd64\$' /tmp/SHA256SUMS.txt | awk '{print \$1}')
ACTUAL=\$(sha256sum /tmp/containarium | awk '{print \$1}')
[[ "\$EXPECTED" == "\$ACTUAL" ]] || { echo "SHA256 mismatch: expected \$EXPECTED, got \$ACTUAL" >&2; exit 1; }
install -m 0755 /tmp/containarium /usr/local/bin/containarium
containarium version

rm -rf /opt/containarium-src
git clone --depth 1 --branch "\$TAG" https://github.com/FootprintAI/Containarium.git /opt/containarium-src
REMOTE

log "helm installing the chart with daemon.replicaCount=0 (same throwaway gateway keypair workaround as 03-provision-containarium.sh — see its header comment)"
ssh_or_local "sudo bash -s" <<REMOTE
set -euo pipefail
ssh-keygen -t ed25519 -N "" -f /tmp/sshpiper_upstream -C sshpiper-upstream <<<y >/dev/null 2>&1 || true
PUBKEY=\$(cat /tmp/sshpiper_upstream.pub)

helm install containarium /opt/containarium-src/charts/containarium-k8s \
	--set daemon.jwtSecret="\$(openssl rand -hex 32)" \
	--set daemon.replicaCount=0 \
	--set runtimeClass=${GVISOR_RUNTIME_CLASS} \
	--set gateway.enabled=false \
	--set gateway.upstreamKeySecret=sshpiper-upstream-key \
	--set gateway.upstreamPublicKey="\$PUBKEY" \
	--wait --timeout 5m

kubectl -n agent-gateway create secret generic sshpiper-upstream-key \
	--from-file=ssh-privatekey=/tmp/sshpiper_upstream \
	--dry-run=client -o yaml | kubectl apply -f -
REMOTE

log "reshaping the chart's (0-replica) daemon Deployment into a StatefulSet with jq (remote: needs a live kubectl against the cluster)"
ssh_or_local "sudo bash -s" <<'REMOTE'
set -euo pipefail
kubectl get deployment containarium-containarium-k8s-daemon -o jsonpath='{.metadata.namespace}' >/tmp/release-ns.txt

kubectl get deployment containarium-containarium-k8s-daemon -o json | jq \
'{
  apiVersion: "apps/v1",
  kind: "StatefulSet",
  metadata: {
    name: "containarium-bench-daemon",
    namespace: .metadata.namespace,
    labels: {
      "app.kubernetes.io/name": "containarium-bench-daemon",
      "app.kubernetes.io/instance": "containarium-bench",
      "benchmark": "agent-sandbox-density"
    }
  },
  spec: {
    serviceName: "containarium-bench-daemon-headless",
    replicas: 1,
    selector: {
      matchLabels: {
        "app.kubernetes.io/name": "containarium-bench-daemon",
        "app.kubernetes.io/instance": "containarium-bench"
      }
    },
    template: {
      metadata: {
        labels: {
          "app.kubernetes.io/name": "containarium-bench-daemon",
          "app.kubernetes.io/instance": "containarium-bench"
        }
      },
      spec: .spec.template.spec
    }
  }
}' >/tmp/daemon-statefulset.json

echo "--- reshaped StatefulSet (verify the container spec below matches what the chart would have run) ---"
jq '.spec.template.spec.containers[0] | {image, args, env: (.env | map(.name))}' /tmp/daemon-statefulset.json

kubectl apply -f /tmp/daemon-statefulset.json
REMOTE

# The remaining manifests (headless Service, sentinel ConfigMap/Deployment/
# Service) are static — no cluster state to read — so they're templated
# LOCALLY (same __NAMESPACE__-substitution pattern 02-run-density-k8s.sh
# uses for sandbox-template.yaml) and piped through ssh, rather than
# expected to exist inside the VM's own tag-pinned git clone (which only
# ever contains a released tag — these benchmark-only files aren't part of
# any release).
RELEASE_NS=$(ssh_or_local "cat /tmp/release-ns.txt")
[[ -n "$RELEASE_NS" ]] || die "couldn't read back the release namespace from the VM"
log "release namespace: ${RELEASE_NS}"

log "waiting for the daemon StatefulSet's pod to be Ready"
ssh_or_local "kubectl wait --for=condition=ready pod/containarium-bench-daemon-0 --timeout=180s"

for manifest in daemon-headless-service sentinel-configmap sentinel-deployment sentinel-service; do
	sed "s/__NAMESPACE__/${RELEASE_NS}/g" "${BENCH_ROOT}/manifests/sentinel-statefulset/${manifest}.yaml" |
		ssh_or_local "kubectl apply -f -"
done

log "waiting for the sentinel Deployment to be available"
ssh_or_local "kubectl wait --for=condition=available deployment/containarium-bench-sentinel --timeout=180s"

log "topology summary:"
ssh_or_local "kubectl get deployment,statefulset,svc -l 'app.kubernetes.io/instance in (containarium,containarium-bench)'"

log "sanity check: a request through the sentinel actually reaches the daemon"
ssh_or_local "kubectl run -it --rm sentinel-smoke-test --image=curlimages/curl:latest --restart=Never --command -- curl -sf http://containarium-bench-sentinel:8080/health" \
	&& log "sentinel -> daemon hop confirmed reachable" \
	|| die "sentinel smoke test failed — the density loop would fail the same way; check nginx.conf / StatefulSet pod logs before proceeding"

log "provisioning complete. Verify: ssh (see config.env) 'kubectl get pods -A; kubectl get statefulset,deployment,svc -A | grep bench'"
