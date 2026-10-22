#!/usr/bin/env bash
# Build the containarium CLIENT for macOS 11 (Big Sur).
#
# Stock Go >= 1.25 cannot target macOS 11, for two reasons, and this script
# works around both with a PRIVATE, patched copy of the Go toolchain (the
# system toolchain is never modified):
#
#   1. crypto/x509 calls SecTrustCopyCertificateChain, a macOS 12+ API, so
#      the binary dies at launch on macOS 11 with "symbol not found". We
#      replace crypto/x509/root_darwin.go + crypto/x509/internal/macos with
#      Go 1.24's, which verify via SecTrustGetCertificateAtIndex (macOS 10.x+).
#   2. The linker stamps LC_BUILD_VERSION minos=12.0. We patch that constant
#      to 11.0 and rebuild cmd/link, so no vtool/codesign is needed (the
#      linker ad-hoc signs arm64 itself) and this runs on a Linux runner.
#
# Dropping macOS 11 is a one-line change: delete the build-macos11 step.
# Re-check this script on every Go bump — it fails loudly (never silently)
# if the files it patches change shape.
#
# Usage: scripts/build-macos11.sh <out-dir> [version]
#   Writes <out-dir>/containarium-darwin-{amd64,arm64}-macos11.
set -euo pipefail

OUT="${1:?usage: $0 <out-dir> [version]}"
VERSION="${2:-dev}"
OLD_GO="${MACOS11_X509_GO:-go1.24.13}"   # source of the macOS-11-safe x509 code

repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# The toolchain to patch is the one the repo itself builds with (go.mod may
# switch to a newer one than the system go). $OLD_GO is resolved from a
# scratch dir instead: inside the repo, go.mod's `go 1.26.x` would force a
# toolchain switch away from it.
new_root="$(cd "$repo" && go env GOROOT)"
old_root="$(cd "$work" && GOTOOLCHAIN="$OLD_GO" go env GOROOT)"
[ -d "$old_root/src/crypto/x509/internal/macos" ] || { echo "no $OLD_GO sources at $old_root" >&2; exit 1; }

patched="$work/goroot"
cp -R "$new_root" "$patched"
chmod -R u+w "$patched"

# 1. Go 1.24 certificate verification.
rm -rf "$patched/src/crypto/x509/internal/macos"
cp -R "$old_root/src/crypto/x509/internal/macos" "$patched/src/crypto/x509/internal/macos"
cp "$old_root/src/crypto/x509/root_darwin.go" "$patched/src/crypto/x509/root_darwin.go"

# 2. Linker minos 12.0 -> 11.0.
macho="$patched/src/cmd/link/internal/ld/macho.go"
grep -q 'version = 12<<16 | 0<<8 | 0<<0 // 12.0.0' "$macho" \
  || { echo "linker minos constant not found in $macho; update this script" >&2; exit 1; }
sed -i.bak 's|version = 12<<16 \| 0<<8 \| 0<<0 // 12.0.0|version = 11<<16 \| 0<<8 \| 0<<0 // 11.0.0|' "$macho"
rm -f "$macho.bak"
grep -q '11<<16' "$macho" || { echo "linker patch did not apply" >&2; exit 1; }

export GOROOT="$patched" GOTOOLCHAIN=local PATH="$patched/bin:$PATH"
( cd "$work" && go install cmd/link )   # rebuild the linker with the patch

commit="$(git -C "$repo" rev-parse --short HEAD)"
pkg=github.com/footprintai/containarium/pkg/version
cd "$repo"
for arch in amd64 arm64; do
  f="$OUT/containarium-darwin-$arch-macos11"
  CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build -tags containarium_client \
    -ldflags "-X $pkg.Version=$VERSION -X $pkg.GitCommit=$commit -X $pkg.BuildTime=$(date -u +%FT%TZ)" \
    -o "$f" cmd/containarium/main.go
  # Gate: the macOS-12-only symbol must be gone from the binary.
  if grep -aq SecTrustCopyCertificateChain "$f"; then
    echo "FAIL: $f still references SecTrustCopyCertificateChain" >&2; exit 1
  fi
  echo "built $f"
done
