#!/bin/bash
#
# Density loop for the experiment group: create Containarium boxes one at a
# time (each scheduled under gVisor via the runtimeClass set in
# 03-provision-containarium.sh) until the shared stopping rule in lib.sh's
# run_density_loop triggers.
#
# The k8s backend parses --cpu/--memory with Kubernetes' native quantity
# parser (resource.ParseQuantity) and sets BOTH request and limit to that
# same value — see pkg/core/box/k8s/objects.go. So this passes
# SANDBOX_CPU_LIMIT/SANDBOX_MEM_LIMIT straight through, no unit conversion
# needed (unlike the old LXC-backend version of this script). Worth noting
# as a fairness asymmetry, not hidden: the control group's Sandbox pods
# request the lower REQUEST value (k8s admission packs on requests, not
# limits), while Containarium's boxes request the full LIMIT value — see
# README.md "Fairness notes".
#
# Usage:
#   scripts/04-run-density-containarium.sh --name <vm-name>

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh

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
require_vars SANDBOX_CPU_LIMIT SANDBOX_MEM_LIMIT FAILURE_STREAK_TO_STOP CREATE_TIMEOUT_SECONDS

log "sandbox profile on the Containarium side: cpu=${SANDBOX_CPU_LIMIT} memory=${SANDBOX_MEM_LIMIT} (k8s-native quantities, request==limit)"

RESULTS_DIR="${BENCH_ROOT}/results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/containarium-$(date -u +%Y%m%dT%H%M%SZ).md"

log "starting kubectl port-forward to the daemon and minting an admin token"
ssh_or_local "pkill -f 'port-forward svc/containarium' 2>/dev/null; setsid nohup kubectl port-forward svc/containarium-containarium-k8s-daemon 8080:8080 >/tmp/port-forward.log 2>&1 < /dev/null &"
sleep 3

JWT_SECRET=$(ssh_or_local "kubectl get secret containarium-containarium-k8s-daemon -o jsonpath='{.data.jwt-secret}' | base64 -d")
[[ -n "$JWT_SECRET" ]] || die "failed to read the daemon's jwt-secret — check helm install succeeded (03-provision-containarium.sh)"
CTN_TOKEN=$(ssh_or_local "containarium token generate --username bench-admin --roles admin --expiry 6h --secret '${JWT_SECRET}' --raw")
[[ -n "$CTN_TOKEN" ]] || die "failed to mint a token"

CTN_SERVER="http://127.0.0.1:8080"

create_box() {
	local name="$1"
	ssh_or_local "containarium create ${name} --no-ssh-key --cpu ${SANDBOX_CPU_LIMIT} --memory ${SANDBOX_MEM_LIMIT} --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1
}

box_ready() {
	local name="$1"
	local state
	state=$(ssh_or_local "containarium list --format json --server ${CTN_SERVER} --http --token ${CTN_TOKEN} 2>/dev/null" |
		jq -r --arg n "$name" '.[] | select(.username==$n) | .state' 2>/dev/null || true)
	[[ "$state" == "RUNNING" ]]
}

cleanup_box() {
	local name="$1"
	ssh_or_local "containarium delete ${name} --force --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1 || true
}

resource_snapshot "before" "$RESULTS_FILE"
{
	echo "profile: cpu ${SANDBOX_CPU_LIMIT}, mem ${SANDBOX_MEM_LIMIT} (k8s-native, request==limit)"
	echo "runtimeClass: see 03-provision-containarium.sh GVISOR_RUNTIME_CLASS"
	echo
} >>"$RESULTS_FILE"

run_density_loop "sbdens" create_box box_ready cleanup_box "$RESULTS_FILE"

resource_snapshot "after (${DENSITY_RESULT_COUNT} ready)" "$RESULTS_FILE"
{
	echo "kubectl top nodes (if metrics-server installed):"
	echo '```'
	ssh_or_local "kubectl top nodes 2>&1" || true
	echo '```'
	echo "pods by RuntimeClass (sanity check that boxes really landed on gVisor):"
	echo '```'
	ssh_or_local "kubectl get pods -A -o custom-columns=NAME:.metadata.name,RUNTIMECLASS:.spec.runtimeClassName 2>&1" || true
	echo '```'
} >>"$RESULTS_FILE"

log "Containarium (gVisor) experiment group result: ${DENSITY_RESULT_COUNT} boxes reached RUNNING"
log "full log: ${RESULTS_FILE}"
