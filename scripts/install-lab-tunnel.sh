#!/bin/bash
#
# Phase A of the lab pool bring-up: install the binary and run the tunnel
# client only. The handshake auto-promotes this node into the sentinel's
# primary registry for pool=lab; verifying that confirms slices 1-7 work
# end-to-end against production.
#
# Phase B (Incus + daemon + core containers) follows once Phase A is green.
#
# Usage (on the lab node, with sudo):
#   sudo CONTAINARIUM_TUNNEL_TOKEN=<token> \
#        CONTAINARIUM_SENTINEL_ADDR=<host:port> \
#        CONTAINARIUM_PUBLIC_HOSTNAME=<cluster>.example.com \
#        bash install-lab-tunnel.sh
#
# Idempotent: re-running replaces the unit and restarts the service.

set -euo pipefail

# write_secret_unit PATH: stdin -> PATH with mode 0600. Used for the tunnel
# token file and for the unit, so neither is readable by other users.
# umask 077 keeps a new file private from the first byte; the explicit chmod
# also tightens a file that already existed (> keeps the old mode).
write_secret_unit() {
    local path="$1"
    (umask 077; cat > "$path")
    chmod 0600 "$path"
}

if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root (use sudo)"
    exit 1
fi

BINARY_SRC="${BINARY_SRC:-/tmp/containariumd}"
BINARY_DST="/usr/local/bin/containariumd"

# Lab tunnel token — env-only (no default literal in this OSS-tracked
# file; see CLAUDE.md OSS-disclosure rule). A prior committed literal
# was rotated 2026-05-25.
LAB_TOKEN="${CONTAINARIUM_TUNNEL_TOKEN:-}"
SENTINEL_ADDR="${CONTAINARIUM_SENTINEL_ADDR:-<sentinel-host>:443}"
SPOT_ID="${SPOT_ID:-lab-primary-1}"
POOL="${POOL:-lab}"
# Pool's public hostname — placeholder; the cluster's apex doesn't
# belong in the repo per CLAUDE.md.
PUBLIC_HOSTNAME="${CONTAINARIUM_PUBLIC_HOSTNAME:-<cluster>.example.com}"
PUBLIC_PORT="${PUBLIC_PORT:-443}"

if [[ -z "$LAB_TOKEN" ]]; then
    echo "Error: CONTAINARIUM_TUNNEL_TOKEN env var required"
    exit 1
fi
if [[ "$SENTINEL_ADDR" == *"<sentinel-host>"* ]]; then
    echo "Error: CONTAINARIUM_SENTINEL_ADDR env var required (got placeholder)"
    exit 1
fi
if [[ "$PUBLIC_HOSTNAME" == *"<cluster>.example.com"* ]]; then
    echo "Error: CONTAINARIUM_PUBLIC_HOSTNAME env var required (got placeholder)"
    exit 1
fi

if [[ ! -f "$BINARY_SRC" ]]; then
    echo "Error: $BINARY_SRC not found. SCP the binary there first:"
    echo "  scp bin/containariumd-linux-amd64 ubuntu@<host>:/tmp/containariumd"
    exit 1
fi

echo "==> Installing binary -> $BINARY_DST"
install -m 0755 "$BINARY_SRC" "$BINARY_DST"
echo "    md5: $(md5sum "$BINARY_DST" | cut -d' ' -f1)"
# #1781 rollout compat symlink: keeps the pre-#1780 name working for any
# runbook/cron this inventory missed.
ln -sf "$BINARY_DST" /usr/local/bin/containarium

echo "==> Writing systemd unit"
# The token lives in a root-only file the unit reads with --token-file, so it
# never appears in ExecStart, the unit file, or the process argv (#3672).
TOKEN_FILE=/etc/containarium/tunnel.token
mkdir -p /etc/containarium
printf '%s\n' "${LAB_TOKEN}" | write_secret_unit "${TOKEN_FILE}"

write_secret_unit /etc/systemd/system/containarium-tunnel.service <<TUNNEL
[Unit]
Description=Containarium Tunnel Client (${POOL} pool primary)
Documentation=https://github.com/footprintai/Containarium
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BINARY_DST} tunnel \\
  --sentinel-addr ${SENTINEL_ADDR} \\
  --token-file ${TOKEN_FILE} \\
  --spot-id ${SPOT_ID} \\
  --ports 22,8080,443 \\
  --pool ${POOL} \\
  --public-hostname ${PUBLIC_HOSTNAME} \\
  --public-port ${PUBLIC_PORT}
Restart=always
RestartSec=5s
TimeoutStopSec=10s
User=root
Group=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=containarium-tunnel
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
TUNNEL

systemctl daemon-reload
systemctl enable --now containarium-tunnel
sleep 3

echo "==> Service status"
systemctl status containarium-tunnel --no-pager | head -12 || true
echo
echo "==> Recent journal"
journalctl -u containarium-tunnel --no-pager -n 10 --since='30 seconds ago' || true
