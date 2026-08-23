#!/bin/bash
#
# Stop and delete a benchmark VM (including its disk image), freeing the
# host's resources for the other side's run — see README.md "Why
# sequential, not parallel".
#
# Usage:
#   scripts/99-teardown-vm.sh --name <vm-name>

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

command -v VBoxManage >/dev/null 2>&1 || die "VBoxManage not found"

if ! VBoxManage list vms | grep -q "\"${VM_NAME}\""; then
	log "no VM named '${VM_NAME}' — nothing to do"
	exit 0
fi

log "stopping '${VM_NAME}' (if running)"
VBoxManage controlvm "$VM_NAME" poweroff 2>/dev/null || true
sleep 2

log "deleting '${VM_NAME}' and its disk(s)"
VBoxManage unregistervm "$VM_NAME" --delete

log "done"
