#!/bin/bash
#
# Density loop for the fourth scenario: create Containarium boxes one at a
# time on a nested Incus running INSIDE a k8s pod (issue #1565) until the
# shared stopping rule in lib.sh's run_density_loop triggers. See
# manifests/nested-incus-pod/README.md for what this scenario is and isn't
# testing.
#
# Near-identical to 06-run-density-containarium-lxc.sh — same create/ready/
# cleanup logic, same CPU/memory profile (this is the same LXC backend,
# just nested inside a pod instead of running on a bare VM). The only real
# difference is the transport: every command that would go straight to the
# VM over SSH instead goes one hop further, through `kubectl exec` into
# the pod — see pod_exec() below.
#
# Usage:
#   scripts/10-run-density-nested-incus-pod.sh --name <vm-name> [--pod <pod-name>] [--start-index N]

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh

VM_NAME=""
POD_NAME="nested-incus-pod"
START_INDEX=1
while [[ $# -gt 0 ]]; do
	case "$1" in
	--name)
		VM_NAME="$2"
		shift 2
		;;
	--pod)
		POD_NAME="$2"
		shift 2
		;;
	--start-index)
		START_INDEX="$2"
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
[[ -n "$VM_NAME" ]] || die "usage: $0 --name <vm-name> [--pod <pod-name>] [--start-index N]"

load_config
require_vars SANDBOX_MEM_LIMIT FAILURE_STREAK_TO_STOP CREATE_TIMEOUT_SECONDS BENCH_SSH_KEY_FILE

# Same rationale as 06's LXC_SANDBOX_CPU_LIMIT/LXC_CREATE_TIMEOUT_SECONDS —
# this is the same LXC backend, a real LXC box still has to fully boot an
# OS before it's usable, and create_box below is synchronous just like 06.
LXC_CPU_LIMIT="${LXC_SANDBOX_CPU_LIMIT:-${SANDBOX_CPU_LIMIT:-200m}}"
CREATE_TIMEOUT_SECONDS="${LXC_CREATE_TIMEOUT_SECONDS:-$CREATE_TIMEOUT_SECONDS}"

resolve_remote "$VM_NAME"

# pod_exec runs a command inside the nested-Incus pod itself — one hop
# further than ssh_or_local, which only gets us to the VM. containarium's
# CLI and the daemon it's talking to (127.0.0.1:8080) both live inside the
# pod, not on the VM directly.
pod_exec() {
	ssh_or_local "kubectl exec ${POD_NAME} -- $*"
}

INCUS_MEM_LIMIT="${SANDBOX_MEM_LIMIT/Mi/MiB}"
INCUS_MEM_LIMIT="${INCUS_MEM_LIMIT/Gi/GiB}"
log "sandbox profile on the nested-Incus-pod side: cpu=${LXC_CPU_LIMIT} memory=${INCUS_MEM_LIMIT} (Incus limits.cpu/limits.memory, single ceiling, same as scenario 3)"

RESULTS_DIR="${BENCH_ROOT}/results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/nested-incus-pod-$(date -u +%Y%m%dT%H%M%SZ).md"

CTN_SERVER="http://127.0.0.1:8080"

log "minting an admin token"
CTN_TOKEN=$(pod_exec "containarium token generate --username bench-admin --roles admin --expiry 6h --secret-file /etc/containarium/jwt.secret --raw")
[[ -n "$CTN_TOKEN" ]] || die "failed to mint a token — check the daemon is running inside the pod"

create_box() {
	local name="$1"
	pod_exec "containarium create ${name} --no-ssh-key --podman=false --cpu ${LXC_CPU_LIMIT} --memory ${INCUS_MEM_LIMIT} --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1
}

box_ready() {
	local name="$1"
	local state
	state=$(pod_exec "containarium get ${name} --format json --server ${CTN_SERVER} --http --token ${CTN_TOKEN} 2>/dev/null" |
		jq -r --arg n "$name" '.containers[] | select(.Username==$n) | .State' 2>/dev/null || true)
	[[ "$state" == "CONTAINER_STATE_RUNNING" ]]
}

cleanup_box() {
	local name="$1"
	pod_exec "containarium delete ${name} --force --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1 || true
}

resource_snapshot "before" "$RESULTS_FILE"
{
	echo "profile: cpu ${LXC_CPU_LIMIT}, mem ${INCUS_MEM_LIMIT} (Incus native, single ceiling, same profile as scenario 3)"
	echo "backend: nested Incus inside one k8s pod (issue #1565) — Kubernetes only ever admits the pod's own declared request/limit"
	echo
} >>"$RESULTS_FILE"

run_density_loop "sbdnip" create_box box_ready cleanup_box "$RESULTS_FILE" "$START_INDEX"

resource_snapshot "after (${DENSITY_RESULT_COUNT} ready)" "$RESULTS_FILE"
{
	echo "containarium list totals (inside the pod):"
	echo '```'
	pod_exec "containarium list --server ${CTN_SERVER} --http --token ${CTN_TOKEN} 2>&1 | tail -5" || true
	echo '```'
	echo "pod's own declared request/limit (the one number k8s admitted for everything inside it):"
	echo '```'
	ssh_or_local "kubectl get pod ${POD_NAME} -o jsonpath='{.spec.containers[0].resources}'" || true
	echo '```'
} >>"$RESULTS_FILE"

log "nested-Incus-pod fourth-scenario result: ${DENSITY_RESULT_COUNT} boxes reached RUNNING"
log "full log: ${RESULTS_FILE}"
