#!/bin/bash
#
# Shared helpers for the sandbox-density benchmark scripts. Sourced, not
# executed directly.
#
# Keeping the stopping rule and the resource-snapshot format here (instead
# of duplicated in 02-run-density-k8s.sh and 04-run-density-containarium.sh)
# is what makes the two sides comparable — a change to the methodology only
# has to be made once. See README.md "Fairness notes".

set -euo pipefail

BENCH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() {
	echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2
}

die() {
	log "ERROR: $*"
	exit 1
}

# load_config sources config.env (created from config.env.example) and
# fails loudly if it's missing, rather than silently running with unset
# variables.
load_config() {
	local config_file="${BENCH_ROOT}/config.env"
	[[ -f "$config_file" ]] || die "missing $config_file — copy config.env.example to config.env and fill it in first"
	# shellcheck source=/dev/null
	source "$config_file"
}

# require_vars checks that every named variable is non-empty, failing
# loudly and naming which one is missing rather than proceeding with an
# empty value that fails confusingly three steps later.
require_vars() {
	local missing=()
	local var
	for var in "$@"; do
		if [[ -z "${!var:-}" ]]; then
			missing+=("$var")
		fi
	done
	if [[ ${#missing[@]} -gt 0 ]]; then
		die "required config value(s) not set: ${missing[*]} (check config.env)"
	fi
}

# resolve_remote looks up the live IP of an Incus VM by name and points
# REMOTE_HOST/REMOTE_SSH_PORT/REMOTE_SSH_USER at it, overriding whatever
# static values config.env has. Incus VMs get a DHCP-assigned bridge IP,
# not a fixed NAT-forwarded port, so there's nothing meaningful to put in
# config.env ahead of time — the provisioning/density scripts all take
# --name and call this instead. REMOTE_SSH_USER/BENCH_SSH_KEY_FILE still
# come from config.env (the cloud-init user and the matching private key).
resolve_remote() {
	local vm_name="$1"
	local ip
	ip=$(sudo incus list "$vm_name" -c 4 --format csv 2>/dev/null | grep -oE '^[0-9.]+' || true)
	[[ -n "$ip" ]] || die "couldn't resolve an IP for Incus VM '${vm_name}' — is it running? (incus list)"
	REMOTE_HOST="$ip"
	REMOTE_SSH_PORT="22"
	log "resolved ${vm_name} -> ${REMOTE_HOST}"
}

# ssh_or_local runs a command inside the guest under test — over SSH to
# REMOTE_HOST:REMOTE_SSH_PORT, using BENCH_SSH_KEY_FILE (the private half
# of the keypair 00-create-vm.sh injects via cloud-init; see config.env's
# BENCH_SSH_PUBKEY_FILE). REMOTE_HOST/REMOTE_SSH_PORT are set per-VM by
# resolve_remote, not config.env — Incus VMs get a DHCP-assigned IP, not a
# fixed port. Empty REMOTE_HOST runs directly via bash instead (e.g.
# running these scripts from inside the guest itself). Every provisioning/
# density script goes through this so there's exactly one place that knows
# how to reach the guest.
ssh_or_local() {
	if [[ -n "${REMOTE_HOST:-}" ]]; then
		ssh -p "${REMOTE_SSH_PORT:-22}" -o StrictHostKeyChecking=accept-new \
			${BENCH_SSH_KEY_FILE:+-i "$BENCH_SSH_KEY_FILE"} \
			"${REMOTE_SSH_USER:+$REMOTE_SSH_USER@}${REMOTE_HOST}" "$@"
	else
		bash -c "$*"
	fi
}

# resource_snapshot appends a labeled host resource snapshot to the given
# results file — memory, CPU count, and disk, using `free`'s "available"
# column rather than "free" (available accounts for reclaimable page
# cache; free doesn't, and undercounts real headroom — see the density
# README's host-sizing note).
resource_snapshot() {
	local label="$1" results_file="$2"
	{
		echo "### snapshot: ${label} ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
		echo '```'
		ssh_or_local "free -h; echo; nproc; echo; df -h /" 2>&1
		echo '```'
		echo
	} >>"$results_file"
}

# run_density_loop drives the shared "create one more unit, check if it
# became ready, stop after N consecutive resource-reason failures" logic.
# Both density scripts (02, 04) pass in their own create/check/cleanup
# functions by name so the loop itself — and therefore the stopping rule —
# is identical on both sides.
#
# Args:
#   $1 - name prefix for created units (e.g. "sbdens" -> sbdens-0001, ...)
#   $2 - name of a function: create_fn <unit-name>  -> returns 0 on accepted, non-zero on rejected
#   $3 - name of a function: ready_fn <unit-name>   -> returns 0 once ready, non-zero while pending
#   $4 - name of a function: cleanup_fn <unit-name> -> best-effort teardown of a failed/half-created unit
#   $5 - results file to append the run log to
#
# On return, sets DENSITY_RESULT_COUNT to the number of units that reached
# ready state before the stopping rule triggered.
run_density_loop() {
	local prefix="$1" create_fn="$2" ready_fn="$3" cleanup_fn="$4" results_file="$5"
	local i=0 ready_count=0 fail_streak=0
	local unit_name start_ts

	log "starting density loop: prefix=${prefix} stop-after=${FAILURE_STREAK_TO_STOP} consecutive failures, per-unit timeout=${CREATE_TIMEOUT_SECONDS}s"
	echo "## density run: ${prefix} ($(date -u +%Y-%m-%dT%H:%M:%SZ))" >>"$results_file"

	while true; do
		i=$((i + 1))
		unit_name="${prefix}-$(printf '%04d' "$i")"
		start_ts=$(date +%s)

		if ! "$create_fn" "$unit_name"; then
			fail_streak=$((fail_streak + 1))
			log "create rejected for ${unit_name} (failure streak: ${fail_streak}/${FAILURE_STREAK_TO_STOP})"
			"$cleanup_fn" "$unit_name" || true
			if [[ $fail_streak -ge $FAILURE_STREAK_TO_STOP ]]; then
				log "stopping: ${FAILURE_STREAK_TO_STOP} consecutive create failures"
				break
			fi
			continue
		fi

		local became_ready=0
		while [[ $(($(date +%s) - start_ts)) -lt $CREATE_TIMEOUT_SECONDS ]]; do
			if "$ready_fn" "$unit_name"; then
				became_ready=1
				break
			fi
			sleep 2
		done

		if [[ $became_ready -eq 1 ]]; then
			ready_count=$((ready_count + 1))
			fail_streak=0
			log "${unit_name} ready (total ready: ${ready_count})"
		else
			fail_streak=$((fail_streak + 1))
			log "${unit_name} never became ready within ${CREATE_TIMEOUT_SECONDS}s (failure streak: ${fail_streak}/${FAILURE_STREAK_TO_STOP})"
			"$cleanup_fn" "$unit_name" || true
			if [[ $fail_streak -ge $FAILURE_STREAK_TO_STOP ]]; then
				log "stopping: ${FAILURE_STREAK_TO_STOP} consecutive not-ready timeouts"
				break
			fi
		fi
	done

	log "final count: ${ready_count} ready units (${i} attempted)"
	{
		echo "- attempted: ${i}"
		echo "- reached ready: ${ready_count}"
		echo
	} >>"$results_file"

	DENSITY_RESULT_COUNT=$ready_count
}
