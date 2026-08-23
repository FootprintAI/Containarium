#!/bin/bash
#
# Provision the control-group VM: the shared base cluster (see
# k8s-common.sh — kubeadm, CNI, raised max-pods, gVisor, upstream
# kubernetes-sigs/agent-sandbox controller) with nothing Containarium-
# specific on top. The control group creates `Sandbox` CRs directly via
# kubectl (02); their pods are scheduled under gVisor exactly like the
# experiment group's (manifests/sandbox-template.yaml sets
# runtimeClassName). See README.md "What's actually under test" — gVisor
# is deliberately identical on both sides, so what differs is Containarium
# the orchestrator, not gVisor.
#
# Usage:
#   scripts/01-provision-k8s-control.sh --name <vm-name>
#
# Assumes the guest is Ubuntu Server 24.04 with passwordless sudo for
# REMOTE_SSH_USER.

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
require_vars K8S_MAX_PODS AGENT_SANDBOX_VERSION GVISOR_RUNTIME_CLASS REMOTE_SSH_USER BENCH_SSH_KEY_FILE
resolve_remote "$VM_NAME"

log "provisioning k8s control group on '${VM_NAME}' (max-pods=${K8S_MAX_PODS}, agent-sandbox=${AGENT_SANDBOX_VERSION}, runtime=${GVISOR_RUNTIME_CLASS})"
provision_base_k8s
install_gvisor

log "creating benchmark namespace"
ssh_or_local "kubectl create namespace sandbox-density-bench --dry-run=client -o yaml | kubectl apply -f -"

log "provisioning complete. Verify: kubectl get nodes -o wide; kubectl get runtimeclass; kubectl -n agent-sandbox-system get pods"
