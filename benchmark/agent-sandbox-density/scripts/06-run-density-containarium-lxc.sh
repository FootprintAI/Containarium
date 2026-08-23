#!/bin/bash
#
# Density loop for the third scenario: create Containarium boxes one at a
# time on the native LXC/Incus backend (no k8s, no gVisor) until the
# shared stopping rule in lib.sh's run_density_loop triggers.
#
# Unlike the k8s backend (04-run-density-containarium.sh), `containarium
# list` works fine here — #1525's "incus backend not available" only
# fires against a --runtime=k8s daemon; this one genuinely is Incus-backed.
#
# CPU/memory format differs from the k8s scripts too: pkg/core/incus's
# parseCPULimit accepts Kubernetes millicpu directly (confirmed in code:
# "250m" -> limits.cpu + limits.cpu.allowance), but memory is passed
# straight through to Incus's own `limits.memory` config key with no
# conversion (pkg/core/container/manager.go) — Incus's native format is
# "256MiB", not Kubernetes' "256Mi" (confirmed against this repo's own
# test fixtures, e.g. pkg/core/nodevm/nodevm_test.go's "1GiB"). Uses
# SANDBOX_CPU_LIMIT/SANDBOX_MEM_LIMIT the same way 04 does (LXC has one
# enforced ceiling, not a request+limit pair), converting Mi->MiB (a
# rename, not a real unit conversion — MiB *is* what k8s' "Mi" means).
#
# Usage:
#   scripts/06-run-density-containarium-lxc.sh --name <vm-name>

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
require_vars SANDBOX_CPU_LIMIT SANDBOX_MEM_LIMIT FAILURE_STREAK_TO_STOP CREATE_TIMEOUT_SECONDS BENCH_SSH_KEY_FILE
resolve_remote "$VM_NAME"

INCUS_MEM_LIMIT="${SANDBOX_MEM_LIMIT/Mi/MiB}"
INCUS_MEM_LIMIT="${INCUS_MEM_LIMIT/Gi/GiB}"
log "sandbox profile on the LXC workhorse side: cpu=${SANDBOX_CPU_LIMIT} memory=${INCUS_MEM_LIMIT} (Incus limits.cpu/limits.memory, single ceiling)"

RESULTS_DIR="${BENCH_ROOT}/results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/containarium-lxc-$(date -u +%Y%m%dT%H%M%SZ).md"

CTN_SERVER="http://127.0.0.1:8080"

log "minting an admin token"
CTN_TOKEN=$(ssh_or_local "sudo containarium token generate --username bench-admin --roles admin --expiry 6h --secret-file /etc/containarium/jwt.secret --raw")
[[ -n "$CTN_TOKEN" ]] || die "failed to mint a token — check the daemon is running (systemctl status containarium)"

create_box() {
	local name="$1"
	ssh_or_local "containarium create ${name} --no-ssh-key --cpu ${SANDBOX_CPU_LIMIT} --memory ${INCUS_MEM_LIMIT} --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1
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
	echo "profile: cpu ${SANDBOX_CPU_LIMIT}, mem ${INCUS_MEM_LIMIT} (Incus native, single ceiling)"
	echo "backend: native LXC/Incus, no k8s, no gVisor"
	echo
} >>"$RESULTS_FILE"

run_density_loop "sbdens" create_box box_ready cleanup_box "$RESULTS_FILE"

resource_snapshot "after (${DENSITY_RESULT_COUNT} ready)" "$RESULTS_FILE"
{
	echo "containarium list totals:"
	echo '```'
	ssh_or_local "containarium list --server ${CTN_SERVER} --http --token ${CTN_TOKEN} 2>&1 | tail -5" || true
	echo '```'
} >>"$RESULTS_FILE"

log "Containarium (native LXC) third-scenario result: ${DENSITY_RESULT_COUNT} boxes reached RUNNING"
log "full log: ${RESULTS_FILE}"
