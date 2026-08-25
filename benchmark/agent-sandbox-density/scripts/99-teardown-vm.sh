#!/bin/bash
#
# Stop and delete a benchmark Incus VM (including its disk), freeing the
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

command -v incus >/dev/null 2>&1 || die "incus not found — this must run on the hypervisor host"

if ! sudo incus list --format csv -c n | grep -qx "$VM_NAME"; then
	log "no VM named '${VM_NAME}' — nothing to do"
	exit 0
fi

log "deleting Incus VM '${VM_NAME}' (force stop + delete, including its disk)"
sudo incus delete "$VM_NAME" --force

log "done"
