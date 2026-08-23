#!/bin/bash
#
# Create an Incus VM with a hard CPU/memory/disk cap for the
# sandbox-density benchmark. Incus VMs are KVM-backed — limits.cpu /
# limits.memory are a true hardware-partitioned ceiling on the guest, the
# same guarantee a VirtualBox VM would give (see README.md "Hard resource
# caps"). Uses Incus rather than VirtualBox deliberately: running a second
# hypervisor's kernel module (vboxdrv) alongside an already-live KVM/Incus
# host is an avoidable stability risk, and Incus already provides the same
# hard-cap guarantee on a stack that's already proven on this class of
# host.
#
# Boots a stock cloud image (images:ubuntu/24.04) with a generated SSH
# keypair injected via cloud-init — no manual OS install step needed.
#
# Runs locally on whatever machine has Incus installed. For a remote host,
# SSH in yourself and run this script there — it deliberately does not
# embed a remote host name (see CLAUDE.md's anonymization convention).
#
# Usage:
#   scripts/00-create-vm.sh --name <vm-name>

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
require_vars VM_CPUS VM_MEM_MB VM_DISK_GB INCUS_IMAGE BENCH_SSH_PUBKEY_FILE

command -v incus >/dev/null 2>&1 || die "incus not found — this must run on the hypervisor host"
[[ -f "$BENCH_SSH_PUBKEY_FILE" ]] || die "BENCH_SSH_PUBKEY_FILE ($BENCH_SSH_PUBKEY_FILE) not found — generate a host->guest keypair first: ssh-keygen -t ed25519 -N '' -f <path>"

if sudo incus list --format csv -c n | grep -qx "$VM_NAME"; then
	die "a VM named '${VM_NAME}' already exists — run 99-teardown-vm.sh first, or pick a different --name"
fi

PUBKEY=$(cat "$BENCH_SSH_PUBKEY_FILE")

log "creating Incus VM '${VM_NAME}' (cpus=${VM_CPUS} mem=${VM_MEM_MB}MiB disk=${VM_DISK_GB}GB, image=${INCUS_IMAGE})"
sudo incus launch "$INCUS_IMAGE" "$VM_NAME" --vm \
	-c limits.cpu="$VM_CPUS" \
	-c limits.memory="${VM_MEM_MB}MiB" \
	-d root,size="${VM_DISK_GB}GB" \
	-c cloud-init.user-data="#cloud-config
ssh_authorized_keys:
  - ${PUBKEY}
package_update: true
"

log "waiting for the VM to get an IP and become SSH-reachable"
IP=""
for _ in $(seq 1 60); do
	IP=$(sudo incus list "$VM_NAME" -c 4 --format csv 2>/dev/null | grep -oE '^[0-9.]+' || true)
	[[ -n "$IP" ]] && break
	sleep 3
done
[[ -n "$IP" ]] || die "VM '${VM_NAME}' never got an IP — check 'incus console ${VM_NAME}'"

for _ in $(seq 1 30); do
	nc -z -w2 "$IP" 22 2>/dev/null && break
	sleep 3
done

log "VM '${VM_NAME}' is up at ${IP}. Point config.env's REMOTE_HOST at it, or pass --name to the other scripts (they auto-resolve it)."
log "Verify: sudo incus config show ${VM_NAME} | grep -E 'limits.cpu|limits.memory'"
