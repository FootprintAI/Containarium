#!/bin/bash
#
# Density loop for the experiment group: create Containarium boxes one at a
# time via `containarium create` until the shared stopping rule in lib.sh's
# run_density_loop triggers.
#
# LXC boxes have one enforced resource ceiling per resource, not a
# request+limit pair — this uses SANDBOX_CPU_LIMIT / SANDBOX_MEM_LIMIT
# (converted from k8s quantities to Containarium's core-count / decimal-MB
# units below) as the single --cpu / --memory value, and a deliberately
# small fixed SANDBOX_DISK_LIMIT so disk is never what stops the run.
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
require_vars SANDBOX_CPU_LIMIT SANDBOX_MEM_LIMIT SANDBOX_DISK_LIMIT \
	FAILURE_STREAK_TO_STOP CREATE_TIMEOUT_SECONDS

# k8s CPU quantity ("100m" = 0.1 core, "1" = 1 core) -> Containarium's
# core-count string.
k8s_cpu_to_cores() {
	local q="$1"
	if [[ "$q" == *m ]]; then
		awk -v m="${q%m}" 'BEGIN { printf "%.3f", m / 1000 }'
	else
		echo "$q"
	fi
}

# k8s memory quantity (Mi/Gi, binary) -> Containarium's MB/GB (decimal)
# string. Approximate is fine for a density benchmark; note the ~5% Mi->MB
# gap if you're eyeballing the two sides' raw numbers against each other.
k8s_mem_to_containarium() {
	local q="$1"
	if [[ "$q" == *Mi ]]; then
		awk -v mi="${q%Mi}" 'BEGIN { printf "%dMB", mi * 1.048576 }'
	elif [[ "$q" == *Gi ]]; then
		awk -v gi="${q%Gi}" 'BEGIN { printf "%dGB", gi * 1.073741824 }'
	else
		echo "$q"
	fi
}

CTN_CPU="$(k8s_cpu_to_cores "$SANDBOX_CPU_LIMIT")"
CTN_MEM="$(k8s_mem_to_containarium "$SANDBOX_MEM_LIMIT")"
CTN_DISK="$SANDBOX_DISK_LIMIT"

log "sandbox profile on the Containarium side: cpu=${CTN_CPU} memory=${CTN_MEM} disk=${CTN_DISK}"

RESULTS_DIR="${BENCH_ROOT}/results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/containarium-$(date -u +%Y%m%dT%H%M%SZ).md"

log "minting an admin token"
CTN_TOKEN=$(ssh_or_local "sudo containarium token generate --username bench-admin --roles admin --expiry 6h --secret-file /etc/containarium/jwt.secret --raw")
[[ -n "$CTN_TOKEN" ]] || die "failed to mint a token — check the daemon is running (systemctl status containarium)"

create_box() {
	local name="$1"
	ssh_or_local "containarium create ${name} --no-ssh-key --cpu ${CTN_CPU} --memory ${CTN_MEM} --disk ${CTN_DISK} --server http://127.0.0.1:8080 --http --token ${CTN_TOKEN}" >/dev/null 2>&1
}

box_ready() {
	local name="$1"
	local state
	state=$(ssh_or_local "containarium list --format json --server http://127.0.0.1:8080 --http --token ${CTN_TOKEN} 2>/dev/null" |
		jq -r --arg n "$name" '.[] | select(.username==$n) | .state' 2>/dev/null || true)
	[[ "$state" == "RUNNING" ]]
}

cleanup_box() {
	local name="$1"
	ssh_or_local "containarium delete ${name} --force --server http://127.0.0.1:8080 --http --token ${CTN_TOKEN}" >/dev/null 2>&1 || true
}

resource_snapshot "before" "$RESULTS_FILE"
{
	echo "profile: cpu ${CTN_CPU} cores, mem ${CTN_MEM}, disk ${CTN_DISK} (converted from cpu ${SANDBOX_CPU_LIMIT}, mem ${SANDBOX_MEM_LIMIT})"
	echo
} >>"$RESULTS_FILE"

run_density_loop "sbdens" create_box box_ready cleanup_box "$RESULTS_FILE"

resource_snapshot "after (${DENSITY_RESULT_COUNT} ready)" "$RESULTS_FILE"
{
	echo "containarium list totals:"
	echo '```'
	ssh_or_local "containarium list --server http://127.0.0.1:8080 --http --token ${CTN_TOKEN} 2>&1" || true
	echo '```'
} >>"$RESULTS_FILE"

log "Containarium workhorse result: ${DENSITY_RESULT_COUNT} boxes reached RUNNING"
log "full log: ${RESULTS_FILE}"
