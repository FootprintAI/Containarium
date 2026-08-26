#!/bin/bash
#
# Provision the fourth benchmark scenario (#1565): a k8s cluster hosting
# ONE privileged pod that runs a nested `incusd` plus the existing,
# unmodified `containarium daemon --runtime=lxc` inside it. See
# manifests/nested-incus-pod/README.md for what this is and RESULTS.md's
# 2026-08-26 entry for what actually happened when it was run — the
# mechanism works, but per-container cgroup resource limits don't enforce
# in every cluster (a cgroup-namespace/delegation gap, diagnosed but not
# fixed here).
#
# gVisor is NOT installed on this VM's base cluster — the privileged pod
# must run under plain `runc` (unset RuntimeClassName), since Incus
# itself performs mount/cgroup/namespace-creation syscalls against its
# own child containers, exactly what gVisor intercepts and blocks.
#
# CONTAINARIUM_BINARY_URL (optional, config.env): if the resolved
# CONTAINARIUM_VERSION release predates a flag this scenario's daemon
# invocation needs (--disable-{security,pentest,zap}-scanner — the same
# snag the #1558 and sentinel-statefulset entries in RESULTS.md hit),
# build a `containarium` binary from `main` (CGO_ENABLED=0 GOOS=linux
# GOARCH=amd64 go build -buildvcs=false ./cmd/containarium), serve it and
# a `<url>.sha256` file over plain HTTP from somewhere this VM's pod can
# reach (its own host IP works — pods can reach the node they're
# scheduled on), and set this to that URL. Leave unset to use the
# resolved release tag's binary as normal.
#
# Usage:
#   scripts/09-provision-nested-incus-pod.sh --name <vm-name>
#
# Assumes the guest is Ubuntu Server 24.04 with passwordless sudo for
# REMOTE_SSH_USER, same as the other provisioning scripts.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh
# shellcheck source=k8s-common.sh
source ./k8s-common.sh

VM_NAME=""
POD_CPU="16"
POD_MEM="40Gi"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--name)
		VM_NAME="$2"
		shift 2
		;;
	--pod-cpu)
		POD_CPU="$2"
		shift 2
		;;
	--pod-mem)
		POD_MEM="$2"
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
[[ -n "$VM_NAME" ]] || die "usage: $0 --name <vm-name> [--pod-cpu N] [--pod-mem NGi]"

load_config
require_vars K8S_MAX_PODS CONTAINARIUM_VERSION REMOTE_SSH_USER BENCH_SSH_KEY_FILE
resolve_remote "$VM_NAME"

log "provisioning nested-incus-pod scenario on '${VM_NAME}' (pod budget: ${POD_CPU} CPU / ${POD_MEM})"
provision_base_k8s
# install_gvisor deliberately NOT called — see header comment.

RELEASE_NS="default"
BINARY_URL="${CONTAINARIUM_BINARY_URL:-}"

log "rendering and applying the ConfigMap"
sed "s/__NAMESPACE__/${RELEASE_NS}/g" "${BENCH_ROOT}/manifests/nested-incus-pod/pod-configmap.yaml" |
	ssh_or_local "kubectl apply -f -"

log "rendering and applying the pod"
sed \
	-e "s/__NAMESPACE__/${RELEASE_NS}/g" \
	-e "s/__CONTAINARIUM_VERSION__/${CONTAINARIUM_VERSION}/g" \
	-e "s/__POD_CPU__/${POD_CPU}/g" \
	-e "s/__POD_MEM__/${POD_MEM}/g" \
	-e "s#__CONTAINARIUM_BINARY_URL__#${BINARY_URL}#g" \
	"${BENCH_ROOT}/manifests/nested-incus-pod/pod.yaml" |
	ssh_or_local "kubectl apply -f -"

log "waiting for the pod to be Ready (apt-get + incus-init + image-bake all run at startup — this takes several minutes)"
ssh_or_local "kubectl wait --for=condition=ready pod/nested-incus-pod --timeout=15m" ||
	die "pod never became ready — check: ssh (see config.env) 'kubectl logs nested-incus-pod'"

log "provisioning complete. Verify: ssh (see config.env) 'kubectl exec nested-incus-pod -- incus list'"
