#!/bin/bash
# Install the Containarium CLI binary only — no daemon, no Incus,
# no system service. Intended for:
#
#   - CI runners (GitHub Actions, etc.) that talk to a remote
#     Containarium server via `--server` / `CONTAINARIUM_SERVER`
#   - Developer laptops that need the CLI for client work
#   - Lightweight admin shells that don't host any containers
#
# For the full server install (CLI + daemon + Incus + dependencies),
# use install.sh instead.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/footprintai/containarium/main/hacks/install-cli.sh | sudo bash
#
#   # Specific version:
#   curl -fsSL https://raw.githubusercontent.com/footprintai/containarium/main/hacks/install-cli.sh \
#     | sudo CONTAINARIUM_VERSION=v0.18.0 bash
#
#   # Custom install dir (no sudo needed if writable):
#   curl -fsSL https://raw.githubusercontent.com/footprintai/containarium/main/hacks/install-cli.sh \
#     | INSTALL_DIR=$HOME/.local/bin bash

set -euo pipefail

VERSION="${CONTAINARIUM_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture (release artifacts use amd64 / arm64)
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;;
esac

# Note: as of v0.18.0 the release publishes linux-amd64, darwin-amd64,
# darwin-arm64. linux-arm64 is not built — surface that early instead
# of 404ing the download.
if [ "$OS" = "linux" ] && [ "$ARCH" = "arm64" ]; then
  echo "Error: linux-arm64 binaries are not currently published." >&2
  echo "Build from source via 'make build' or open an issue to request." >&2
  exit 1
fi

BINARY="containarium-${OS}-${ARCH}"
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/footprintai/containarium/releases/latest/download/${BINARY}"
else
  URL="https://github.com/footprintai/containarium/releases/download/${VERSION}/${BINARY}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading ${BINARY} from ${URL}"
curl -fsSL -o "$TMP/containarium" "$URL"
chmod +x "$TMP/containarium"

# If INSTALL_DIR isn't writable, suggest sudo
if [ ! -w "$INSTALL_DIR" ]; then
  echo "Error: ${INSTALL_DIR} is not writable. Re-run with sudo, or set INSTALL_DIR=\$HOME/.local/bin" >&2
  exit 1
fi

mv "$TMP/containarium" "${INSTALL_DIR}/containarium"
# Print the installed version. The CLI exposes its version via the
# `version` subcommand, NOT a top-level `--version` flag (the daemon
# accepts both, the CLI doesn't). The previous wording here
# (`--version`) produced "Installed: Error: unknown flag: --version"
# which read like a fatal install error in CI logs — see
# containarium-run#8 / #9 / #10 for the cloud CI debug chain that
# this misleading message helped delay.
echo "Installed: $(${INSTALL_DIR}/containarium version 2>&1 | head -1)"
echo
echo "Talk to a remote Containarium server with:"
echo "  export CONTAINARIUM_HTTP=true"
echo "  export CONTAINARIUM_SERVER=https://your-host:8080"
echo "  export CONTAINARIUM_TOKEN=<jwt>"
echo "  containarium list"
