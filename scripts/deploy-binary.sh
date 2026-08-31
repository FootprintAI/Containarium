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
#   - gcloud configured with access to your GCP project
#   - SSH access to your peer node hostnames
#
# Edit the constants below (PROJECT / ZONE / PRIMARY_VM / SENTINEL_VM /
# PEERS) for your deployment OR override at invocation time via env
# vars (`PROJECT=my-prod ZONE=us-east1-a ... bash deploy-binary.sh`).
#
# The systemd unit names are also overridable: most hosts run the daemon
# as `containarium` / the sentinel as `containarium-sentinel`, but some run
# the daemon under a different unit (e.g. `containarium-daemon`). Pass
# PRIMARY_SERVICE / SENTINEL_SERVICE to match — if the unit name is wrong
# the `stop` is a no-op, the running daemon keeps the binary open, and the
# `cp` fails with "Text file busy".
#

set -euo pipefail

BINARY="bin/containarium-linux-amd64"
PROJECT="${PROJECT:-<your-gcp-project>}"
ZONE="${ZONE:-<your-zone>}"
PRIMARY_VM="${PRIMARY_VM:-<your-primary-vm>}"
SENTINEL_VM="${SENTINEL_VM:-<your-sentinel-vm>}"
# systemd unit names (override per host if the daemon runs under a
# different unit, e.g. PRIMARY_SERVICE=containarium-daemon).
PRIMARY_SERVICE="${PRIMARY_SERVICE:-containarium}"
SENTINEL_SERVICE="${SENTINEL_SERVICE:-containarium-sentinel}"
# Space-separated peer hostnames; defaults are placeholders.
PEERS=(${PEERS:-<peer-a> <peer-b>})

# Expected checksum of the binary we are shipping. Every transfer below is
# verified against this BEFORE the receiving host's service is stopped.
#
# This is not belt-and-braces: scp has been observed exiting 0 having written
# a truncated file — twice to the same peer, delivering 31MB then 65MB of a
# 143MB binary, with no error and plenty of free disk. Installing that and
# restarting leaves a host with a corrupt binary and a stopped daemon, which
# on a peer carrying tenant containers is an outage rather than a retry.
#
# Verifying before the stop means a bad transfer costs a retry instead.
verify_remote() {
    # verify_remote <label> <sha-command-runner...>
    # The runner is invoked with the remote shell command as its last argument.
    local label="$1"; shift
    local got
    got="$("$@" "sha256sum /tmp/containarium 2>/dev/null | cut -d' ' -f1" 2>/dev/null || true)"
    got="$(printf '%s' "$got" | tr -d '[:space:]')"
    if [ -z "$got" ]; then
        echo "  ERROR: could not read the uploaded binary's checksum on $label" >&2
        return 1
    fi
    if [ "$got" != "$EXPECTED_SHA" ]; then
        echo "  ERROR: checksum mismatch on $label — refusing to install." >&2
        echo "         expected $EXPECTED_SHA" >&2
        echo "         got      $got" >&2
        echo "         The transfer was corrupted or truncated. Nothing was stopped;" >&2
        echo "         re-run to retry. If scp keeps truncating on this link, try:" >&2
        echo "           cat '$BINARY' | ssh <host> 'cat > /tmp/containarium'" >&2
        return 1
    fi
    echo "  checksum OK on $label"
}

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

# 1b. Preflight: the sentinel↔daemon HMAC secret must already be provisioned.
#
# v0.19.0+ gates the sentinel-facing endpoints (/authorized-keys, /certs,
# /authorized-keys/sentinel) behind an HMAC over CONTAINARIUM_SENTINEL_AUTH_SECRET
# (>=32 bytes), loaded from /etc/containarium/env.secrets via a systemd
# EnvironmentFile drop-in. Swapping a v0.19.0+ binary onto a host that lacks the
# secret silently 401s every sentinel keysync/certsync cycle — sshpiper config
# freezes, upstream pointers go stale, and tenants get locked out for hours
# before anyone finds the 401 (issue #341). Refuse to swap the binary until the
# secret is in place rather than recreate that outage.
#
# Set ALLOW_MISSING_SENTINEL_SECRET=1 to bypass (deliberate pre-HMAC rollback,
# or an unsecured single-node dev box). See docs/SENTINEL-AUTH-SECRET.md for how
# to generate and distribute the secret.
SECRET_FILE="/etc/containarium/env.secrets"
SECRET_MIN_LEN=32
RUNBOOK="docs/SENTINEL-AUTH-SECRET.md"
# grep emits SECRET_OK iff env.secrets holds a CONTAINARIUM_SENTINEL_AUTH_SECRET
# value of at least SECRET_MIN_LEN chars; SECRET_MISSING otherwise (incl. no file).
SECRET_CHECK_CMD="sudo grep -Eq '^CONTAINARIUM_SENTINEL_AUTH_SECRET=.{${SECRET_MIN_LEN},}' '$SECRET_FILE' 2>/dev/null && echo SECRET_OK || echo SECRET_MISSING"

if [[ "${ALLOW_MISSING_SENTINEL_SECRET:-0}" == "1" ]]; then
    echo "==> ALLOW_MISSING_SENTINEL_SECRET=1 — skipping HMAC secret preflight (#341)"
else
    echo "==> Preflight: checking CONTAINARIUM_SENTINEL_AUTH_SECRET on sentinel + primary (#341)..."
    missing=()

    sentinel_secret=$(gcloud compute ssh "$SENTINEL_VM" --zone="$ZONE" --project="$PROJECT" \
        --tunnel-through-iap --ssh-flag="-p 2222" --command="$SECRET_CHECK_CMD" 2>/dev/null || echo SECRET_MISSING)
    [[ "$sentinel_secret" == *SECRET_OK* ]] || missing+=("sentinel ($SENTINEL_VM)")

    primary_secret=$(gcloud compute ssh "$PRIMARY_VM" --zone="$ZONE" --project="$PROJECT" \
        --tunnel-through-iap --command="$SECRET_CHECK_CMD" 2>/dev/null || echo SECRET_MISSING)
    [[ "$primary_secret" == *SECRET_OK* ]] || missing+=("primary ($PRIMARY_VM)")

    if (( ${#missing[@]} > 0 )); then
        echo ""
        echo "ERROR: CONTAINARIUM_SENTINEL_AUTH_SECRET (>=${SECRET_MIN_LEN} bytes) is not provisioned on:"
        for h in "${missing[@]}"; do echo "         - $h"; done
        echo ""
        echo "  Deploying a v0.19.0+ binary here would silently 401 every sentinel"
        echo "  keysync/certsync cycle and can SSH-lock tenants for hours (#341)."
        echo ""
        echo "  Provision the secret first (one per cluster, same value on every host):"
        echo "    see $RUNBOOK"
        echo ""
        echo "  To bypass intentionally (pre-HMAC rollback / unsecured dev box):"
        echo "    ALLOW_MISSING_SENTINEL_SECRET=1 $0 $*"
        exit 1
    fi
    echo "  OK: secret present on sentinel and primary"
fi

# Compute the expected checksum once, after any --build has produced the binary.
if [ ! -f "$BINARY" ]; then
    echo "ERROR: $BINARY not found (use --build, or build it first)" >&2
    exit 1
fi
EXPECTED_SHA="$(sha256sum "$BINARY" 2>/dev/null | cut -d' ' -f1)"
if [ -z "$EXPECTED_SHA" ]; then
    EXPECTED_SHA="$(shasum -a 256 "$BINARY" | cut -d' ' -f1)"   # macOS
fi
echo "==> Shipping $BINARY (sha256 $EXPECTED_SHA)"

# 2. Upload to sentinel
echo "==> Uploading to sentinel..."
gcloud compute scp "$BINARY" "$SENTINEL_VM:/tmp/containarium" \
    --zone="$ZONE" --project="$PROJECT" --tunnel-through-iap --scp-flag="-P 2222"
# Sentinel daemon holds /usr/local/bin/containarium open, so a plain `cp`
# fails with "Text file busy". Stop the service before copying, mirroring
# the primary-VM pattern below.
verify_remote "sentinel ($SENTINEL_VM)" \
    gcloud compute ssh "$SENTINEL_VM" --zone="$ZONE" --project="$PROJECT" \
    --tunnel-through-iap --ssh-flag="-p 2222" --command
gcloud compute ssh "$SENTINEL_VM" --zone="$ZONE" --project="$PROJECT" \
    --tunnel-through-iap --ssh-flag="-p 2222" \
    --command="sudo systemctl stop $SENTINEL_SERVICE && sleep 1 && sudo cp /tmp/containarium /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium && sudo systemctl start $SENTINEL_SERVICE"
echo "  Sentinel updated and restarted ($SENTINEL_SERVICE)"

# 3. Deploy on primary
echo "==> Deploying on primary ($PRIMARY_VM)..."
gcloud compute scp "$BINARY" "$PRIMARY_VM:/tmp/containarium" \
    --zone="$ZONE" --project="$PROJECT" --tunnel-through-iap
verify_remote "primary ($PRIMARY_VM)" \
    gcloud compute ssh "$PRIMARY_VM" --zone="$ZONE" --project="$PROJECT" \
    --tunnel-through-iap --command
gcloud compute ssh "$PRIMARY_VM" --zone="$ZONE" --project="$PROJECT" \
    --tunnel-through-iap \
    --command="sudo systemctl stop $PRIMARY_SERVICE && sleep 1 && sudo cp /tmp/containarium /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium && sudo systemctl start $PRIMARY_SERVICE"
echo "  Primary updated and restarted ($PRIMARY_SERVICE)"

# 4. Deploy on peers.
# Guard the expansion: with PEERS=" " (the "primary+sentinel only" idiom) the
# array is empty, and `"${PEERS[@]}"` under `set -u` on bash 3.2 (macOS) errors
# "PEERS[@]: unbound variable". Skip the loop entirely when there are none.
if (( ${#PEERS[@]} > 0 )); then
  for peer in "${PEERS[@]}"; do
    echo "==> Deploying on peer ($peer)..."
    scp "$BINARY" "$peer:/tmp/containarium" 2>/dev/null || {
        echo "  Warning: failed to upload to $peer (skipping)"
        continue
    }
    # Verify before telling the operator to install it. Printing the install
    # command for a truncated upload is how a corrupt binary gets run by hand.
    if ! verify_remote "peer ($peer)" ssh "$peer"; then
        echo "  Warning: skipping $peer — re-run to retry the upload"
        continue
    fi
    # Peers need interactive sudo — print the command for the user
    echo "  Binary uploaded to $peer:/tmp/containarium"
    echo "  Run on $peer:"
    echo "    sudo systemctl stop containarium-tunnel && sudo systemctl stop $PRIMARY_SERVICE && sleep 1 && sudo cp /tmp/containarium /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium && sudo systemctl start $PRIMARY_SERVICE && sudo systemctl start containarium-tunnel"
  done
fi

echo ""
echo "=== Deploy complete ==="
echo "  Sentinel: updated and restarted"
echo "  Primary:  updated and restarted"
echo "  Peers:    binary uploaded for immediate use"
echo ""
echo "  NOTE: If peers have --sentinel-url configured, they will auto-update"
echo "        from the sentinel within 5 minutes. Otherwise, run the printed"
echo "        commands with sudo on each peer."
echo ""
echo "  NOTE: Peer daemons also need CONTAINARIUM_SENTINEL_AUTH_SECRET set to the"
echo "        same cluster secret (the preflight above only gates sentinel +"
echo "        primary). Verify each peer has it before they take sentinel"
echo "        keysync/certsync traffic — see $RUNBOOK."
