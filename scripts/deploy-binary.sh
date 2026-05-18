#!/bin/bash
#
# Deploy containarium binary to all instances.
#
# Usage: ./scripts/deploy-binary.sh [--build]
#
# This script:
#   1. Optionally builds the linux binary (--build)
#   2. Uploads to the sentinel (which serves it to peers)
#   3. Deploys on the primary GCE VM
#   4. Triggers each peer to self-update from the sentinel
#
# Prerequisites:
#   - gcloud configured with access to footprintai-prod
#   - SSH access to peer nodes (fts-5900x, fts-13700k)
#

set -euo pipefail

BINARY="bin/containarium-linux-amd64"
PROJECT="footprintai-prod"
ZONE="us-west1-a"
PRIMARY_VM="containarium-jump-usw1"
SENTINEL_VM="containarium-jump-usw1-sentinel"
PEERS=("fts-5900x" "fts-13700k")

# Parse flags
BUILD=false
for arg in "$@"; do
    case "$arg" in
        --build) BUILD=true ;;
    esac
done

# 1. Build if requested
if $BUILD; then
    echo "==> Building binary..."
    make build-linux
fi

if [[ ! -f "$BINARY" ]]; then
    echo "Error: $BINARY not found. Run with --build or 'make build-linux' first."
    exit 1
fi

BINARY_SIZE=$(du -h "$BINARY" | cut -f1)
echo "==> Binary: $BINARY ($BINARY_SIZE)"

# 2. Upload to sentinel
echo "==> Uploading to sentinel..."
gcloud compute scp "$BINARY" "$SENTINEL_VM:/tmp/containarium" \
    --zone="$ZONE" --project="$PROJECT" --tunnel-through-iap --scp-flag="-P 2222"
# Sentinel daemon holds /usr/local/bin/containarium open, so a plain `cp`
# fails with "Text file busy". Stop the service before copying, mirroring
# the primary-VM pattern below.
gcloud compute ssh "$SENTINEL_VM" --zone="$ZONE" --project="$PROJECT" \
    --tunnel-through-iap --ssh-flag="-p 2222" \
    --command="sudo systemctl stop containarium-sentinel && sleep 1 && sudo cp /tmp/containarium /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium && sudo systemctl start containarium-sentinel"
echo "  Sentinel updated and restarted"

# 3. Deploy on primary
echo "==> Deploying on primary ($PRIMARY_VM)..."
gcloud compute scp "$BINARY" "$PRIMARY_VM:/tmp/containarium" \
    --zone="$ZONE" --project="$PROJECT" --tunnel-through-iap
gcloud compute ssh "$PRIMARY_VM" --zone="$ZONE" --project="$PROJECT" \
    --tunnel-through-iap \
    --command="sudo systemctl stop containarium && sleep 1 && sudo cp /tmp/containarium /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium && sudo systemctl start containarium"
echo "  Primary updated and restarted"

# 4. Deploy on peers
for peer in "${PEERS[@]}"; do
    echo "==> Deploying on peer ($peer)..."
    scp "$BINARY" "$peer:/tmp/containarium" 2>/dev/null || {
        echo "  Warning: failed to upload to $peer (skipping)"
        continue
    }
    # Peers need interactive sudo — print the command for the user
    echo "  Binary uploaded to $peer:/tmp/containarium"
    echo "  Run on $peer:"
    echo "    sudo systemctl stop containarium-tunnel && sudo systemctl stop containarium && sleep 1 && sudo cp /tmp/containarium /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium && sudo systemctl start containarium && sudo systemctl start containarium-tunnel"
done

echo ""
echo "=== Deploy complete ==="
echo "  Sentinel: updated and restarted"
echo "  Primary:  updated and restarted"
echo "  Peers:    binary uploaded for immediate use"
echo ""
echo "  NOTE: If peers have --sentinel-url configured, they will auto-update"
echo "        from the sentinel within 5 minutes. Otherwise, run the printed"
echo "        commands with sudo on each peer."
