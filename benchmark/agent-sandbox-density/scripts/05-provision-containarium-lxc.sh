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

# `incus admin init --auto`'s storage-driver auto-detection is NOT
# reliable even with zfsutils-linux installed and the zfs kernel module
# loaded — found live twice now: one run picked zfs, a later run on an
# otherwise-identical host picked "dir" anyway (confirmed post-hoc:
# zfsutils-linux was installed, `lsmod | grep zfs` showed the module
# loaded — auto-detection just didn't pick it). This matters a lot, not
# just cosmetically: "dir" does a full recursive filesystem copy per
# container create (no copy-on-write) — the daemon's own startup log
# warns about exactly this (issue #1206) — and with no COW, real disk
# usage grows roughly linearly with container count until the pool
# fills outright ("Unable to unpack image, run out of disk space" at
# 215 containers on a 181GB disk, live). Stop trusting --auto for this;
# request zfs explicitly.
incus admin init --auto --storage-backend=zfs

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
# --disable-{security,pentest,zap}-scanner: the daemon's default
# (non-standalone) mode auto-runs a ClamAV malware scan + a network pentest
# scan against every newly created container — real, deliberate product
# behavior, but it's background work competing for the host's CPU during
# this benchmark's tiny (200m CPU) boxes. Turned off for a cleaner, more
# isolated measurement. NOTE: found live that this is NOT what was causing
# the ~80-110s-per-create latency this scenario originally showed — that
# was a full OS boot + in-container package install on every create (see
# the image-bake step below, which fixes the actual cause). Requires a
# Containarium build that has these flags (check CONTAINARIUM_VERSION in
# config.env resolves to a version that includes them, or this ExecStart
# line will just get three unrecognized-flag errors from an older binary).
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

log "baking the base image (#1037) so creates clone instead of re-installing packages every time"
# Found live: containarium's stackless create path always re-runs a full
# apt-get update + install of the base package set inside the fresh
# container (openssh-server, sudo, curl, git, vim, htop, net-tools,
# iputils-ping — pkg/core/ospkg/debian.go), on the stock cloud image, on
# EVERY create. Under this scenario's 200m CPU profile that's ~50s of
# package install plus ~44s of throttled first-boot systemd work (vs.
# ~10s unthrottled) — confirmed via systemd-analyze + apt history.log —
# roughly the same shape of gap the k8s scenario already avoids by using a
# pre-baked containarium-agent-box image. Containarium already ships the
# fix for this backend too (#1037, `containarium image-bake`): it launches
# a throwaway container, runs the exact same provisioning once, and
# publishes the result as a local image under a deterministic alias.
# Every subsequent stackless create for the same (image, podman)
# combination clones that image and skips the install entirely — verified
# live: 112s -> 15.7s for an identical create. --podman=false must match
# the density loop's own create flags (06-run-density-containarium-lxc.sh)
# or the bake won't be used (bakedImageMatches checks both axes).
ssh_or_local "sudo containarium image-bake --image images:ubuntu/24.04 --podman=false"

log "provisioning complete. Verify: ssh (see config.env) 'containarium list'"
