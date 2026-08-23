#!/bin/bash
#
# Provision the experiment-group VM: Incus + the Containarium daemon
# running as a plain LXC "workhorse" — the daemon's default mode, no
# --runtime=k8s (that backend targets pods on an *existing* cluster; it
# isn't what "workhorse" means here) and no --standalone (core service
# containers — Postgres, Caddy, the otel collector — stay in, matching a
# real deployment's fixed overhead, same principle as leaving the k8s
# side's kube-system pods in place; see README.md "Fairness notes").
#
# Usage:
#   scripts/03-provision-containarium.sh --name <vm-name>
#
# Assumes the guest is Ubuntu Server 24.04 with passwordless sudo for
# REMOTE_SSH_USER, same as 01-provision-k8s-control.sh.

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
require_vars CONTAINARIUM_VERSION REMOTE_SSH_USER

log "provisioning Containarium workhorse on '${VM_NAME}' (version=${CONTAINARIUM_VERSION})"

log "installing Incus"
ssh_or_local "sudo bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq curl jq
curl -fsSL https://pkgs.zabbly.com/get/incus-stable | sudo sh

usermod -aG incus-admin "$(logname 2>/dev/null || echo root)" || true
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

log "starting the daemon (standard mode: core services on, LXC backend)"
ssh_or_local "sudo bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p /etc/containarium
[[ -f /etc/containarium/jwt.secret ]] || openssl rand -hex 32 >/etc/containarium/jwt.secret
chmod 0400 /etc/containarium/jwt.secret

cat <<'UNIT' >/etc/systemd/system/containarium.service
[Unit]
Description=Containarium daemon (density benchmark workhorse)
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
curl -fsS http://127.0.0.1:8080/healthz || echo "warning: /healthz not yet ready, check systemctl status containarium"
REMOTE

log "provisioning complete. Verify: ssh (see config.env) 'containarium list'"
