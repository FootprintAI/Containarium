#!/bin/bash
#
# Density loop for the experiment group: create Containarium boxes one at a
# time (each scheduled under gVisor via the runtimeClass set in
# 03-provision-containarium.sh) until the shared stopping rule in lib.sh's
# run_density_loop triggers.
#
# The k8s backend parses --cpu/--memory with Kubernetes' native quantity
# parser (resource.ParseQuantity) — see pkg/core/box/k8s/objects.go. So this
# passes SANDBOX_CPU_LIMIT/SANDBOX_MEM_LIMIT straight through, no unit
# conversion needed (unlike the old LXC-backend version of this script).
#
# SANDBOX_CPU_REQUEST/SANDBOX_MEM_REQUEST (#1557) set a *separate* request
# below the limit via `--cpu-request`/`--memory-request`, matching how the
# control group's Sandbox pods are sized (request lower than limit — k8s
# admission packs on requests, not limits). Before #1557 there was no
# request knob on the CLI at all: `create --cpu/--memory` pinned request to
# the same value as the limit, a real fairness asymmetry against
# Containarium that's now fixable — see README.md "Fairness notes" and
# RESULTS.md's #1541/#1557 entries for the density cost that asymmetry
# turned out to have.
#
# Two more things found live, worth knowing before reading this script:
#
# 1. `create`'s default --image ("images:ubuntu/24.04") is an LXC-style
#    reference, not a valid OCI image — it 500s the k8s backend's pod with
#    InvalidImageName. There's no backend-aware default. Explicitly passes
#    Containarium's own agent-box image instead (the same one the Helm
#    chart's agentBox.image value points at), version-tagged to match the
#    daemon build (":latest" 404s on GHCR — only version tags are
#    published) — read from /tmp/containarium-resolved-tag, which
#    03-provision-containarium.sh's tag-resolution step writes.
#
# 2. `containarium list` unconditionally errors on this backend —
#    "incus backend not available on this host" — so it can't be used for
#    readiness or cleanup verification here. Readiness is checked directly
#    via the k8s API instead: every box's pod is named "box" in namespace
#    "tenant-<username>" (confirmed live), so this polls
#    `kubectl get pod -n tenant-<name> box` for phase=Running + container
#    ready. `containarium delete` (unlike `list`) works fine and is still
#    used for cleanup.
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
require_vars SANDBOX_CPU_LIMIT SANDBOX_MEM_LIMIT SANDBOX_CPU_REQUEST SANDBOX_MEM_REQUEST FAILURE_STREAK_TO_STOP CREATE_TIMEOUT_SECONDS BENCH_SSH_KEY_FILE
resolve_remote "$VM_NAME"

log "sandbox profile on the Containarium side: cpu=${SANDBOX_CPU_REQUEST}/${SANDBOX_CPU_LIMIT} memory=${SANDBOX_MEM_REQUEST}/${SANDBOX_MEM_LIMIT} (request/limit, k8s-native quantities)"

RESULTS_DIR="${BENCH_ROOT}/results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/containarium-$(date -u +%Y%m%dT%H%M%SZ).md"

RESOLVED_TAG=$(ssh_or_local "cat /tmp/containarium-resolved-tag 2>/dev/null" || true)
[[ -n "$RESOLVED_TAG" ]] || die "couldn't read /tmp/containarium-resolved-tag — did 03-provision-containarium.sh run first?"
AGENT_BOX_IMAGE="ghcr.io/footprintai/containarium-agent-box:${RESOLVED_TAG}"
log "using agent-box image ${AGENT_BOX_IMAGE}"

log "resolving the daemon's ClusterIP and minting an admin token (containarium list is broken on this backend — see header — so no port-forward/list dependency here)"
CTN_CLUSTERIP=$(ssh_or_local "kubectl get svc containarium-containarium-k8s-daemon -o jsonpath='{.spec.clusterIP}'")
[[ -n "$CTN_CLUSTERIP" ]] || die "couldn't resolve the daemon's ClusterIP — check 'kubectl get svc' on the guest"
CTN_SERVER="http://${CTN_CLUSTERIP}:8080"

JWT_SECRET=$(ssh_or_local "kubectl get secret containarium-containarium-k8s-daemon -o jsonpath='{.data.jwt-secret}' | base64 -d")
[[ -n "$JWT_SECRET" ]] || die "failed to read the daemon's jwt-secret — check helm install succeeded (03-provision-containarium.sh)"
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
	echo "profile: cpu ${SANDBOX_CPU_LIMIT}, mem ${SANDBOX_MEM_LIMIT} (k8s-native, request==limit)"
	echo "image: ${AGENT_BOX_IMAGE}"
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
