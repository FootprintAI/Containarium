#!/bin/bash
#
# Provision the third scenario's VM: Containarium's native LXC/Incus
# "workhorse" backend — no Kubernetes, no gVisor, no pooling. See
# README.md "Third scenario: native LXC workhorse" for why this exists
# and what it isn't (it is NOT a test of the #1488 warm-pool feature —
# SpawnSandbox still serves the Phase 1 cold path as of this writing, see
# #1523 — this measures the same create path #1522/#1527 already cover on
# the k8s backend, just on Containarium's original backend instead).
#
# Runs the daemon in its default mode (core services on: Postgres, Caddy,
# the otel collector) — NOT --standalone — so the fixed overhead matches
# what a real deployment carries, same principle as the k8s side's
# kube-system pods being left in place (README.md "Fairness notes").
#
# Usage:
#   scripts/05-provision-containarium-lxc.sh --name <vm-name>
#
# Assumes the guest is Ubuntu Server 24.04 with passwordless sudo for
# REMOTE_SSH_USER, same as the other provisioning scripts.

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
require_vars CONTAINARIUM_VERSION REMOTE_SSH_USER BENCH_SSH_KEY_FILE
resolve_remote "$VM_NAME"

log "provisioning Containarium native LXC workhorse on '${VM_NAME}' (version=${CONTAINARIUM_VERSION})"

log "installing Incus"
ssh_or_local "sudo bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# iptables found missing live too — without it the daemon's
# PassthroughSyncJob logs a retry failure every 5s (same class of gap as
# jq/git elsewhere in this benchmark; the base image is minimal). Whether
# it was also the cause of a slow first-boot core-container init isn't
# fully confirmed — installing it and restarting is what got past the
# stall live, but the timing doesn't rule out it just needing more time
# regardless. Installed upfront either way since the log noise alone is
# worth avoiding.
apt-get install -y -qq curl jq iptables zfsutils-linux
curl -fsSL https://pkgs.zabbly.com/get/incus-stable | sudo sh

# `incus admin init --auto` picks its storage driver from what's on the
# host: with zfsutils-linux installed first (above), it sets up a
# loop-backed zpool instead of falling back to the plain "dir" driver.
# This matters a lot, not just cosmetically — found live that "dir"
# does a full recursive filesystem copy per container create (no
# copy-on-write), and the daemon's own startup log already warns about
# exactly this (see docs referenced in that warning, issue #1206):
# single creates took 80-90s, almost entirely inside that copy, dwarfing
# every other stage in the daemon's own documented latency breakdown
# (docs/architecture/two-digit-ms-sandbox-spawn.md). ZFS gives instant
# COW clones instead.
incus admin init --auto

DRIVER=$(incus storage show default | grep '^driver:' | awk '{print $2}')
echo "storage pool driver: ${DRIVER}"
if [[ "$DRIVER" != "zfs" ]]; then
	echo "WARNING: storage pool ended up as '${DRIVER}', not zfs — container creates will be much slower than expected (see comment above)" >&2
fi
REMOTE

log "downloading containarium ${CONTAINARIUM_VERSION}"
ssh_or_local "sudo bash -s" <<REMOTE
set -euo pipefail
TAG="${CONTAINARIUM_VERSION}"
if [[ "\$TAG" == "latest" ]]; then
	TAG=\$(curl -fsSL https://api.github.com/repos/FootprintAI/Containarium/releases/latest | jq -r .tag_name)
fi
echo "resolved tag: \$TAG"

BASE_URL="https://github.com/FootprintAI/Containarium/releases/download/\${TAG}"
curl -fsSL -o /tmp/containarium "\${BASE_URL}/containarium-linux-amd64"
curl -fsSL -o /tmp/SHA256SUMS.txt "\${BASE_URL}/SHA256SUMS.txt"

EXPECTED=\$(grep 'containarium-linux-amd64\$' /tmp/SHA256SUMS.txt | awk '{print \$1}')
ACTUAL=\$(sha256sum /tmp/containarium | awk '{print \$1}')
[[ "\$EXPECTED" == "\$ACTUAL" ]] || {
	echo "SHA256 mismatch: expected \$EXPECTED, got \$ACTUAL" >&2
	exit 1
}

install -m 0755 /tmp/containarium /usr/local/bin/containarium
containarium version
REMOTE

log "starting the daemon (default mode: core services on, LXC backend)"
# --disable-{security,pentest,zap}-scanner: found live that the daemon's
# default (non-standalone) mode auto-runs a ClamAV malware scan + a
# network pentest scan against every newly created container — real,
# deliberate product behavior, but it added tens of seconds of real
# per-create latency in this benchmark's tiny (200m CPU) boxes, competing
# with the create flow for the host's CPU. Requires a Containarium build
# that has these flags (added specifically for this — check
# CONTAINARIUM_VERSION in config.env resolves to a version that includes
# them, or this ExecStart line will just get three unrecognized-flag
# errors from an older binary).
ssh_or_local "sudo bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p /etc/containarium
[[ -f /etc/containarium/jwt.secret ]] || openssl rand -hex 32 >/etc/containarium/jwt.secret
chmod 0400 /etc/containarium/jwt.secret

cat <<'UNIT' >/etc/systemd/system/containarium.service
[Unit]
Description=Containarium daemon (density benchmark, native LXC workhorse)
After=network-online.target incus.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/containarium daemon --address 0.0.0.0 --rest --http-port 8080 --jwt-secret-file /etc/containarium/jwt.secret --disable-security-scanner --disable-pentest-scanner --disable-zap-scanner
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now containarium
sleep 5
systemctl is-active containarium
REMOTE

log "provisioning complete. Verify: ssh (see config.env) 'containarium list'"
