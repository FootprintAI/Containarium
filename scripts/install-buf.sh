#!/usr/bin/env bash
# Install a checksum-verified binary; explicit platform args support bundles.
set -euo pipefail
source "$(dirname "$0")/buf-version.env"
destination="${1:?Usage: scripts/install-buf.sh <destination> [OS] [ARCH]}"
platform="${2:-$(uname -s)}-${3:-$(uname -m)}"
case "$platform" in
  Linux-x86_64) checksum="$BUF_SHA256_LINUX_X86_64" ;;
  Linux-aarch64) checksum="$BUF_SHA256_LINUX_AARCH64" ;;
  Darwin-x86_64) checksum="$BUF_SHA256_DARWIN_X86_64" ;;
  Darwin-arm64) checksum="$BUF_SHA256_DARWIN_ARM64" ;;
  *) echo "Unsupported buf platform: $platform" >&2; exit 1 ;;
esac
digest() {
  local output
  if command -v sha256sum >/dev/null; then
    output="$(sha256sum "$1")"
  else
    output="$(shasum -a 256 "$1")"
  fi
  echo "${output%% *}"
}
if [[ -f "$destination" ]] && [[ "$(digest "$destination")" == "$checksum" ]]; then
  chmod +x "$destination"
  echo "Using verified buf $BUF_VERSION at $destination"
  exit 0
fi
mkdir -p "$(dirname "$destination")"
download="$(mktemp "${destination}.XXXXXX")"
trap 'rm -f "$download"' EXIT
curl --fail --location --silent --show-error --retry 3 \
  "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-${platform}" \
  --output "$download"
if [[ "$(digest "$download")" != "$checksum" ]]; then
  echo "buf $BUF_VERSION checksum mismatch for $platform" >&2
  exit 1
fi
chmod +x "$download"
mv "$download" "$destination"
echo "Installed buf $BUF_VERSION ($platform) at $destination"
