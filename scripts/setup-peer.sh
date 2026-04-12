#!/bin/bash
#
# Containarium Peer Node Setup Script
#
# Sets up a bare-metal server as a Containarium peer node with:
#   1. Containarium daemon (--app-hosting mode)
#   2. Tunnel client connecting to sentinel
#
# Prerequisites:
#   - Incus installed and initialized
#   - /tmp/containarium binary uploaded
#   - Run as root: sudo bash setup-peer.sh --spot-id <ID>
#
# Usage:
#   sudo bash setup-peer.sh --spot-id fts-13700k-gpu [--network-subnet 10.0.3.1/24] [--tunnel-token TOKEN]
#

set -euo pipefail

# Defaults
SPOT_ID=""
NETWORK_SUBNET="10.0.3.1/24"
TUNNEL_TOKEN="82ae3301b4650ab2d0026cf0f6a5b5b78dfcc9e022922ac23858d1609913aa7f"
SENTINEL_ADDR="containarium.kafeido.app:443"
SENTINEL_URL=""  # Internal URL for auto-update (auto-detected from primary)
BINARY_SRC="/tmp/containarium"
BINARY_DST="/usr/local/bin/containarium"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --spot-id) SPOT_ID="$2"; shift 2 ;;
        --network-subnet) NETWORK_SUBNET="$2"; shift 2 ;;
        --tunnel-token) TUNNEL_TOKEN="$2"; shift 2 ;;
        --sentinel-addr) SENTINEL_ADDR="$2"; shift 2 ;;
        --sentinel-url) SENTINEL_URL="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 --spot-id <ID> [--network-subnet CIDR] [--tunnel-token TOKEN]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$SPOT_ID" ]]; then
    echo "Error: --spot-id is required (e.g., fts-13700k-gpu)"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root (use sudo)"
    exit 1
fi

echo "==> Setting up Containarium peer node: $SPOT_ID"

# 1. Install binary
echo "==> Installing containarium binary..."
if [[ ! -f "$BINARY_SRC" ]]; then
    echo "Error: $BINARY_SRC not found. Upload it first:"
    echo "  scp bin/containarium-linux-amd64 <host>:/tmp/containarium"
    exit 1
fi
cp "$BINARY_SRC" "$BINARY_DST"
chmod +x "$BINARY_DST"
echo "  Binary installed: $BINARY_DST"

# 2. Install daemon service
echo "==> Installing daemon service..."
"$BINARY_DST" service install

# 3. Override daemon config for app-hosting mode
echo "==> Configuring daemon for app-hosting mode..."
mkdir -p /etc/systemd/system/containarium.service.d
# Build sentinel URL flag if provided
SENTINEL_URL_FLAG=""
if [[ -n "$SENTINEL_URL" ]]; then
    SENTINEL_URL_FLAG="--sentinel-url ${SENTINEL_URL}"
fi

cat > /etc/systemd/system/containarium.service.d/override.conf <<CONF
[Service]
ExecStart=
ExecStart=/usr/local/bin/containarium daemon \\
  --app-hosting \\
  --rest \\
  --jwt-secret-file /etc/containarium/jwt.secret \\
  --network-subnet ${NETWORK_SUBNET} ${SENTINEL_URL_FLAG}
Restart=on-failure
RestartSec=5s
Environment="CONTAINARIUM_ALLOWED_ORIGINS=https://containarium.kafeido.app,http://localhost:3000,http://localhost:8080"
CONF
echo "  Override written: /etc/systemd/system/containarium.service.d/override.conf"

# 4. Install tunnel service
echo "==> Installing tunnel service..."
cat > /etc/systemd/system/containarium-tunnel.service <<TUNNEL
[Unit]
Description=Containarium Tunnel Client (GPU Spot)
Documentation=https://github.com/footprintai/Containarium
After=network-online.target containarium.service
Wants=network-online.target containarium.service

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium tunnel \\
  --sentinel-addr ${SENTINEL_ADDR} \\
  --token ${TUNNEL_TOKEN} \\
  --spot-id ${SPOT_ID} \\
  --ports 22,8080
Restart=on-failure
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
echo "  Tunnel service written: /etc/systemd/system/containarium-tunnel.service"

# 5. Start everything
echo "==> Starting services..."
systemctl daemon-reload
systemctl restart containarium
systemctl enable --now containarium-tunnel

echo ""
echo "=== Setup complete ==="
echo "  Daemon:  $(systemctl is-active containarium)"
echo "  Tunnel:  $(systemctl is-active containarium-tunnel)"
echo ""
echo "  Logs:    journalctl -u containarium -f"
echo "  Tunnel:  journalctl -u containarium-tunnel -f"
echo "  Spot ID: $SPOT_ID"
