#!/bin/bash
#
# Provision the experiment-group VM: the same shared base cluster as the
# control group, INCLUDING gVisor (k8s-common.sh — gVisor is identical on
# both sides, see README.md "What's actually under test"), plus the
# Containarium daemon (Helm chart) configured to schedule every box pod
# under the same runsc RuntimeClass — pod -> gVisor -> containarium.
#
# Gateway (SSH) routing is deliberately disabled (gateway.namespace="",
# gateway.enabled=false): this benchmark only needs to know whether a box
# reached RUNNING, not to SSH into it, so there's no need to stand up
# sshpiper here. If you DO want to reach the boxes afterward, note that
# `kubectl exec`/`port-forward` straight to a gVisor-scheduled box pod does
# not work (kubernetes-sigs/agent-sandbox#158, this repo's #1489) — see
# docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md "Hard isolation via RuntimeClass"
# and re-enable the gateway per docs/KIND-QUICKSTART.md if needed.
#
# Usage:
#   scripts/03-provision-containarium.sh --name <vm-name>
#
# Assumes the guest is Ubuntu Server 24.04 with passwordless sudo for
# REMOTE_SSH_USER, same as 01-provision-k8s-control.sh.

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

log "provisioning Containarium (pod -> gVisor -> containarium) on '${VM_NAME}'"
provision_base_k8s
install_gvisor

log "installing Helm"
ssh_or_local "curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash"

log "resolving Containarium ${CONTAINARIUM_VERSION} and fetching the chart + CLI"
ssh_or_local "sudo bash -s" <<REMOTE
set -euo pipefail
# jq is needed below to resolve "latest" — install it FIRST. Found live:
# installing it at the end of this same block (after it's already used)
# means "latest" resolution silently fails (jq: command not found breaks
# the curl|jq pipe, which then makes curl itself fail with "Failure
# writing output to destination" — a confusing secondary symptom of the
# real, primary cause).
apt-get install -y -qq jq >/dev/null

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

log "helm installing the Containarium daemon (runtimeClass=${GVISOR_RUNTIME_CLASS}, gateway disabled)"
ssh_or_local "sudo bash -s" <<REMOTE
set -euo pipefail
helm install containarium /opt/containarium-src/charts/containarium-k8s \
	--set daemon.jwtSecret="\$(openssl rand -hex 32)" \
	--set runtimeClass=${GVISOR_RUNTIME_CLASS} \
	--set gateway.enabled=false \
	--set gateway.namespace="" \
	--wait --timeout 5m

kubectl get deployment -l app.kubernetes.io/instance=containarium
REMOTE

log "provisioning complete. Verify: ssh (see config.env) 'kubectl get pods -A; kubectl get runtimeclass'"
