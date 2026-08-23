#!/bin/bash
#
# Create a VirtualBox VM with a hard CPU/memory/disk cap for the
# sandbox-density benchmark. VirtualBox enforces --cpus/--memory as a true
# ceiling on the guest (not a soft/advisory limit), which is the point —
# see README.md "Hard resource caps".
#
# Two supported base-image paths, controlled by VM_BASE_ISO in config.env:
#   - a .vdi/.vmdk disk image  -> cloned per run (fast, repeatable — the
#     recommended path: prepare one base Ubuntu Server 24.04 image once,
#     out of band, then run this script fresh for every benchmark run)
#   - a .iso installer image   -> attached for a manual/interactive install;
#     this script starts the VM and returns, it does not automate the
#     installer
#
# Runs locally on whatever machine has VirtualBox installed. For a remote
# host, SSH in yourself and run this script there — it deliberately does
# not embed a remote host name (see CLAUDE.md's anonymization convention);
# config.env's REMOTE_HOST is used by the *provisioning* scripts (01/03),
# which SSH into the guest, not by this one, which needs to run where
# VBoxManage actually is.
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
require_vars VM_CPUS VM_MEM_MB VM_DISK_GB VM_BASE_ISO

command -v VBoxManage >/dev/null 2>&1 || die "VBoxManage not found — install VirtualBox on this machine first"

if VBoxManage list vms | grep -q "\"${VM_NAME}\""; then
	die "a VM named '${VM_NAME}' already exists — run 99-teardown-vm.sh first, or pick a different --name"
fi

log "creating VM '${VM_NAME}' (cpus=${VM_CPUS} mem=${VM_MEM_MB}MB disk=${VM_DISK_GB}GB)"
VBoxManage createvm --name "$VM_NAME" --ostype Ubuntu_64 --register

VBoxManage modifyvm "$VM_NAME" \
	--cpus "$VM_CPUS" \
	--memory "$VM_MEM_MB" \
	--nic1 nat \
	--natpf1 "ssh,tcp,,2222,,22" \
	--audio none \
	--usb off

VBoxManage storagectl "$VM_NAME" --name SATA --add sata --controller IntelAHCI

DISK_PATH="$HOME/VirtualBox VMs/${VM_NAME}/${VM_NAME}.vdi"

case "$VM_BASE_ISO" in
*.vdi | *.vmdk)
	log "cloning base image ${VM_BASE_ISO} -> ${DISK_PATH}"
	VBoxManage clonemedium disk "$VM_BASE_ISO" "$DISK_PATH" --format VDI
	VBoxManage modifymedium disk "$DISK_PATH" --resize $((VM_DISK_GB * 1024))
	VBoxManage storageattach "$VM_NAME" --storagectl SATA --port 0 --device 0 --type hdd --medium "$DISK_PATH"
	VBoxManage startvm "$VM_NAME" --type headless
	log "VM '${VM_NAME}' started from cloned base image. SSH: ssh -p 2222 <user>@127.0.0.1"
	;;
*.iso)
	log "creating a fresh ${VM_DISK_GB}GB disk and attaching installer ISO ${VM_BASE_ISO}"
	VBoxManage createmedium disk --filename "$DISK_PATH" --size $((VM_DISK_GB * 1024)) --format VDI
	VBoxManage storageattach "$VM_NAME" --storagectl SATA --port 0 --device 0 --type hdd --medium "$DISK_PATH"
	VBoxManage storagectl "$VM_NAME" --name IDE --add ide
	VBoxManage storageattach "$VM_NAME" --storagectl IDE --port 0 --device 0 --type dvddrive --medium "$VM_BASE_ISO"
	VBoxManage startvm "$VM_NAME" --type headless
	log "VM '${VM_NAME}' started with the installer ISO attached — complete the OS install manually" \
		"(VBoxManage startvm ${VM_NAME} --type gui to see the console), then re-run without --type headless" \
		"disabled, or just rerun the density scripts once SSH on port 2222 is reachable."
	;;
*)
	die "VM_BASE_ISO must end in .vdi, .vmdk, or .iso — got '${VM_BASE_ISO}'"
	;;
esac

log "done. Verify with: VBoxManage showvminfo '${VM_NAME}' | grep -E 'Memory size|Number of CPUs'"
