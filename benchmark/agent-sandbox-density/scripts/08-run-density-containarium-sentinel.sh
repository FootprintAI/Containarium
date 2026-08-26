#!/bin/bash
#
# Density loop for the sentinel-statefulset scenario — identical to
# 04-run-density-containarium.sh (same sandbox profile via #1557's
# --memory-request/--cpu-request, same readiness check, same stopping
# rule), with exactly one difference: CTN_SERVER points at the sentinel
# Service instead of the daemon Service directly, so every `containarium
# create` call actually traverses the Service -> Deployment(sentinel) ->
# StatefulSet(daemon) hop documented in README.md's "The experiment
# group's k8s footprint" / manifests/sentinel-statefulset/README.md.
#
# Compare this run's result directly against the 373 baseline from
# 04-run-density-containarium.sh (same host, same profile, no sentinel
# hop) — see RESULTS.md.
#
# Usage:
#   scripts/08-run-density-containarium-sentinel.sh --name <vm-name>

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
require_vars SANDBOX_CPU_LIMIT SANDBOX_MEM_LIMIT SANDBOX_CPU_REQUEST SANDBOX_MEM_REQUEST FAILURE_STREAK_TO_STOP CREATE_TIMEOUT_SECONDS BENCH_SSH_KEY_FILE
resolve_remote "$VM_NAME"

log "sandbox profile: cpu=${SANDBOX_CPU_REQUEST}/${SANDBOX_CPU_LIMIT} memory=${SANDBOX_MEM_REQUEST}/${SANDBOX_MEM_LIMIT} (request/limit) via the sentinel hop"

RESULTS_DIR="${BENCH_ROOT}/results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/containarium-sentinel-$(date -u +%Y%m%dT%H%M%SZ).md"

RESOLVED_TAG=$(ssh_or_local "cat /tmp/containarium-resolved-tag 2>/dev/null" || true)
[[ -n "$RESOLVED_TAG" ]] || die "couldn't read /tmp/containarium-resolved-tag — did 07-provision-containarium-sentinel.sh run first?"
AGENT_BOX_IMAGE="ghcr.io/footprintai/containarium-agent-box:${RESOLVED_TAG}"
log "using agent-box image ${AGENT_BOX_IMAGE}"

log "resolving the SENTINEL's ClusterIP (not the daemon's — this is the whole point of this scenario) and minting an admin token"
CTN_CLUSTERIP=$(ssh_or_local "kubectl get svc containarium-bench-sentinel -o jsonpath='{.spec.clusterIP}'")
[[ -n "$CTN_CLUSTERIP" ]] || die "couldn't resolve the sentinel's ClusterIP — did 07-provision-containarium-sentinel.sh run first? check 'kubectl get svc' on the guest"
CTN_SERVER="http://${CTN_CLUSTERIP}:8080"

# The JWT secret is unchanged from the plain Deployment scenario — it's the
# same Helm-created Secret (containarium-containarium-k8s-daemon), read
# straight from the StatefulSet pod's env by the daemon regardless of which
# controller (Deployment or StatefulSet) is running it.
JWT_SECRET=$(ssh_or_local "kubectl get secret containarium-containarium-k8s-daemon -o jsonpath='{.data.jwt-secret}' | base64 -d")
[[ -n "$JWT_SECRET" ]] || die "failed to read the daemon's jwt-secret — check 07-provision-containarium-sentinel.sh's helm install succeeded"
CTN_TOKEN=$(ssh_or_local "containarium token generate --username bench-admin --roles admin --expiry 6h --secret '${JWT_SECRET}' --raw")
[[ -n "$CTN_TOKEN" ]] || die "failed to mint a token"

create_box() {
	local name="$1"
	ssh_or_local "containarium create ${name} --no-ssh-key --cpu ${SANDBOX_CPU_LIMIT} --memory ${SANDBOX_MEM_LIMIT} --cpu-request ${SANDBOX_CPU_REQUEST} --memory-request ${SANDBOX_MEM_REQUEST} --image ${AGENT_BOX_IMAGE} --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1
}

box_ready() {
	local name="$1"
	local phase ready
	phase=$(ssh_or_local "kubectl get pod -n tenant-${name} box -o jsonpath='{.status.phase}' 2>/dev/null" || true)
	ready=$(ssh_or_local "kubectl get pod -n tenant-${name} box -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null" || true)
	[[ "$phase" == "Running" && "$ready" == "true" ]]
}

cleanup_box() {
	local name="$1"
	ssh_or_local "containarium delete ${name} --force --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1 || true
}

resource_snapshot "before" "$RESULTS_FILE"
{
	echo "profile: cpu ${SANDBOX_CPU_REQUEST}/${SANDBOX_CPU_LIMIT}, mem ${SANDBOX_MEM_REQUEST}/${SANDBOX_MEM_LIMIT} (request/limit)"
	echo "image: ${AGENT_BOX_IMAGE}"
	echo "topology: containarium create -> Service(containarium-bench-sentinel) -> Deployment(sentinel, nginx) -> StatefulSet(containarium-bench-daemon)"
	echo "compare against: results/containarium-*.md (04-run-density-containarium.sh, no sentinel hop, same profile)"
	echo
} >>"$RESULTS_FILE"

run_density_loop "sbdenssent" create_box box_ready cleanup_box "$RESULTS_FILE"

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
	echo "sentinel + daemon pod status at stop:"
	echo '```'
	ssh_or_local "kubectl get pods -l 'app.kubernetes.io/instance=containarium-bench' -o wide 2>&1" || true
	echo '```'
} >>"$RESULTS_FILE"

log "Containarium (sentinel-statefulset) scenario result: ${DENSITY_RESULT_COUNT} boxes reached RUNNING"
log "full log: ${RESULTS_FILE}"
