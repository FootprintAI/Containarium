#!/usr/bin/env bash
# Install a pinned, checksum-verified xcaddy (replaces `go install ...@latest`).
# Usage: scripts/install-xcaddy.sh <destination> [OS] [ARCH]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/xcaddy-version.env"
destination="${1:?Usage: scripts/install-xcaddy.sh <destination> [OS] [ARCH]}"
platform="${2:-$(uname -s)}-${3:-$(uname -m)}"
case "$platform" in
  Linux-x86_64)  asset=linux_amd64; checksum="$XCADDY_SHA256_LINUX_X86_64" ;;
  Linux-aarch64) asset=linux_arm64; checksum="$XCADDY_SHA256_LINUX_AARCH64" ;;
  Darwin-x86_64) asset=mac_amd64;   checksum="$XCADDY_SHA256_DARWIN_X86_64" ;;
  Darwin-arm64)  asset=mac_arm64;   checksum="$XCADDY_SHA256_DARWIN_ARM64" ;;
  *) echo "Unsupported xcaddy platform: $platform" >&2; exit 1 ;;
esac
digest() {
  local output
  if command -v sha256sum >/dev/null; then output="$(sha256sum "$1")"; else output="$(shasum -a 256 "$1")"; fi
  echo "${output%% *}"
}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --fail --location --silent --show-error --retry 3 \
  "https://github.com/caddyserver/xcaddy/releases/download/v${XCADDY_VERSION}/xcaddy_${XCADDY_VERSION}_${asset}.tar.gz" \
  --output "$work/xcaddy.tar.gz"
if [[ "$(digest "$work/xcaddy.tar.gz")" != "$checksum" ]]; then
  echo "xcaddy $XCADDY_VERSION checksum mismatch for $platform" >&2
  exit 1
fi
tar -xzf "$work/xcaddy.tar.gz" -C "$work" xcaddy
mkdir -p "$(dirname "$destination")"
install -m 0755 "$work/xcaddy" "$destination"
echo "Installed xcaddy $XCADDY_VERSION ($platform) at $destination"
