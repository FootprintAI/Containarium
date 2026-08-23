#!/bin/bash
#
# Density loop for the control group: create Sandbox CRs (agents.x-k8s.io/
# v1beta1) one at a time via the upstream agent-sandbox controller until the
# shared stopping rule in lib.sh's run_density_loop triggers.
#
# Usage:
#   scripts/02-run-density-k8s.sh --name <vm-name>
#
# NOTE: the Sandbox CR's Ready-status field is asserted here as
# `.status.conditions[?(@.type=="Ready")].status` — the common controller
# convention, but NOT yet verified against a live agent-sandbox-controller
# run (this benchmark hasn't been executed yet — see README.md "Running
# it"). On the first real run, sanity-check with
# `kubectl get sandbox <name> -n sandbox-density-bench -o yaml` and adjust
# `sandbox_ready` below if the actual schema differs.

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
require_vars SANDBOX_CPU_REQUEST SANDBOX_CPU_LIMIT SANDBOX_MEM_REQUEST SANDBOX_MEM_LIMIT \
	FAILURE_STREAK_TO_STOP CREATE_TIMEOUT_SECONDS

NAMESPACE="sandbox-density-bench"
RESULTS_DIR="${BENCH_ROOT}/results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/k8s-$(date -u +%Y%m%dT%H%M%SZ).md"

create_sandbox() {
	local name="$1"
	sed \
		-e "s/__NAME__/${name}/g" \
		-e "s/__SANDBOX_CPU_REQUEST__/${SANDBOX_CPU_REQUEST}/g" \
		-e "s/__SANDBOX_CPU_LIMIT__/${SANDBOX_CPU_LIMIT}/g" \
		-e "s/__SANDBOX_MEM_REQUEST__/${SANDBOX_MEM_REQUEST}/g" \
		-e "s/__SANDBOX_MEM_LIMIT__/${SANDBOX_MEM_LIMIT}/g" \
		"${BENCH_ROOT}/manifests/sandbox-template.yaml" |
		ssh_or_local "kubectl apply -f -" >/dev/null 2>&1
}

sandbox_ready() {
	local name="$1"
	local status
	status=$(ssh_or_local "kubectl get sandbox ${name} -n ${NAMESPACE} -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null" || true)
	[[ "$status" == "True" ]]
}

cleanup_sandbox() {
	local name="$1"
	ssh_or_local "kubectl delete sandbox ${name} -n ${NAMESPACE} --ignore-not-found --wait=false" >/dev/null 2>&1 || true
}

resource_snapshot "before" "$RESULTS_FILE"
{
	echo "profile: cpu ${SANDBOX_CPU_REQUEST}/${SANDBOX_CPU_LIMIT}, mem ${SANDBOX_MEM_REQUEST}/${SANDBOX_MEM_LIMIT}"
	echo
} >>"$RESULTS_FILE"

run_density_loop "sbdens" create_sandbox sandbox_ready cleanup_sandbox "$RESULTS_FILE"

resource_snapshot "after (${DENSITY_RESULT_COUNT} ready)" "$RESULTS_FILE"
{
	echo "kubectl top nodes (if metrics-server installed):"
	echo '```'
	ssh_or_local "kubectl top nodes 2>&1" || true
	echo '```'
} >>"$RESULTS_FILE"

log "k8s control group result: ${DENSITY_RESULT_COUNT} sandboxes reached Ready"
log "full log: ${RESULTS_FILE}"
