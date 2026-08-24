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
# `--podman=false`: found live that `create`'s default (--podman=true)
# installs Podman + pip + podman-compose inside every box
# (pkg/core/container/manager.go's installPackages) — under this
# benchmark's tiny 50m CPU limit, that single install chain took several
# minutes per unit (watched it firsthand: still running `apt-get install
# python3-pip` six minutes in). That's not a density measurement, it's a
# package-manager-under-extreme-CPU-starvation measurement, and neither
# the control group's busybox pods nor the k8s-backend's agent-box image
# do anything comparable at create time. Disabling it drops the per-unit cost to just the base package set
# (openssh-server, sudo, curl, git, vim, htop, net-tools, iputils-ping —
# pkg/core/ospkg/debian.go, still installed via apt at create time either
# way). That's still not perfectly comparable to the other two scenarios
# — neither installs anything at create time at all (bare busybox for
# the control group; a pre-baked agent-box image for the k8s-backend
# Containarium group) — but it's the closest this backend gets without
# baking its own base image, and it's the real difference worth reporting
# rather than a multi-minute artifact worth reporting.
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
require_vars SANDBOX_MEM_LIMIT FAILURE_STREAK_TO_STOP CREATE_TIMEOUT_SECONDS BENCH_SSH_KEY_FILE

# LXC_SANDBOX_CPU_LIMIT overrides SANDBOX_CPU_LIMIT for this scenario —
# see config.env.example's comment on it for why (an LXC box has to fully
# boot an OS before it's usable; a too-tight CPU profile makes DHCP
# acquisition time out before boot finishes, unlike a k8s pod which just
# starts an existing process). Falls back to SANDBOX_CPU_LIMIT if unset.
LXC_CPU_LIMIT="${LXC_SANDBOX_CPU_LIMIT:-${SANDBOX_CPU_LIMIT:-200m}}"

# lib.sh's run_density_loop starts its per-unit clock BEFORE calling
# create_box, and create_box here is synchronous — it blocks until
# `containarium create` itself returns, which on this backend means a
# full OS boot (~44s under a 200m CPU ceiling, confirmed via
# systemd-analyze) plus the base package install (~50s, confirmed via
# /var/log/apt/history.log) have already completed. That alone is close
# to or past the shared CREATE_TIMEOUT_SECONDS default (60s), so the
# ready_fn poll loop below would start with its window already expired
# and misreport every unit as "never became ready" even though it's
# already running. LXC_CREATE_TIMEOUT_SECONDS overrides the shared
# CREATE_TIMEOUT_SECONDS for this scenario only — the k8s-backed
# scenarios (02/04) don't pay this synchronous boot+install cost, so
# their 60s default stays correct as-is.
CREATE_TIMEOUT_SECONDS="${LXC_CREATE_TIMEOUT_SECONDS:-$CREATE_TIMEOUT_SECONDS}"

resolve_remote "$VM_NAME"

INCUS_MEM_LIMIT="${SANDBOX_MEM_LIMIT/Mi/MiB}"
INCUS_MEM_LIMIT="${INCUS_MEM_LIMIT/Gi/GiB}"
log "sandbox profile on the LXC workhorse side: cpu=${LXC_CPU_LIMIT} memory=${INCUS_MEM_LIMIT} (Incus limits.cpu/limits.memory, single ceiling)"

RESULTS_DIR="${BENCH_ROOT}/results"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="${RESULTS_DIR}/containarium-lxc-$(date -u +%Y%m%dT%H%M%SZ).md"

CTN_SERVER="http://127.0.0.1:8080"

log "minting an admin token"
CTN_TOKEN=$(ssh_or_local "sudo containarium token generate --username bench-admin --roles admin --expiry 6h --secret-file /etc/containarium/jwt.secret --raw")
[[ -n "$CTN_TOKEN" ]] || die "failed to mint a token — check the daemon is running (systemctl status containarium)"

create_box() {
	local name="$1"
	ssh_or_local "containarium create ${name} --no-ssh-key --podman=false --cpu ${LXC_CPU_LIMIT} --memory ${INCUS_MEM_LIMIT} --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1
}

box_ready() {
	local name="$1"
	local state
	# NOTE: this backend's `list` JSON shape differs from what it looked
	# like on the k8s backend — confirmed live: {"containers":[...]}, not
	# a bare array, with capitalized Username/State fields and the full
	# enum value CONTAINER_STATE_RUNNING, not a short "RUNNING".
	state=$(ssh_or_local "containarium list --format json --server ${CTN_SERVER} --http --token ${CTN_TOKEN} 2>/dev/null" |
		jq -r --arg n "$name" '.containers[] | select(.Username==$n) | .State' 2>/dev/null || true)
	[[ "$state" == "CONTAINER_STATE_RUNNING" ]]
}

cleanup_box() {
	local name="$1"
	ssh_or_local "containarium delete ${name} --force --server ${CTN_SERVER} --http --token ${CTN_TOKEN}" >/dev/null 2>&1 || true
}

resource_snapshot "before" "$RESULTS_FILE"
{
	echo "profile: cpu ${LXC_CPU_LIMIT}, mem ${INCUS_MEM_LIMIT} (Incus native, single ceiling; cpu overridden from the k8s scenarios' value — see this script's header)"
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
