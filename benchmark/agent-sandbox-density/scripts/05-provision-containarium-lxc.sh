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
apt-get install -y -qq curl jq
curl -fsSL https://pkgs.zabbly.com/get/incus-stable | sudo sh
incus admin init --auto
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
ExecStart=/usr/local/bin/containarium daemon --address 0.0.0.0 --rest --http-port 8080 --jwt-secret-file /etc/containarium/jwt.secret
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
