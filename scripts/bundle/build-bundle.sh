#!/bin/bash
# build-bundle.sh — assembles the air-gapped install bundle tarball.
#
# Per prd/cloud/air-gapped-install-bundle.md (E3a), produces
# `dist/containarium-bundle-<version>-<os>-<arch>.tar.gz`.
#
# Inputs:
#
#   VERSION   release tag (e.g. v0.19.0) — also stamped into VERSION file
#   OS        target OS (linux only today)
#   ARCH      amd64 | arm64
#   REPO_ROOT defaults to the repo root inferred from this script's path
#
# Pre-requisites (the Makefile target handles these):
#
#   1. `make build-release` has produced bin/*-${OS}-${ARCH} binaries.
#   2. `scripts/bundle/download-deps.sh` has populated dist/bundle-cache/.
#
# The tarball layout matches the PRD §"What's in the bundle":
#
#   containarium-bundle-<version>-<os>-<arch>/
#   ├── README.md
#   ├── VERSION
#   ├── CHECKSUMS.sha256
#   ├── offline-install.sh
#   ├── bin/{containarium,mcp-server,agent-box,actions-runner-*.tar.gz}
#   ├── sidecars/*.tar
#   ├── toolchains/{go*,node*,pnpm*,buf*,golangci-lint*}
#   ├── apt/*.deb
#   ├── images/                       # populated separately (build-base-image)
#   └── docs/{INSTALL.md,VERIFY.md,GHES.md}

set -euo pipefail

# ---- inputs ----
VERSION="${VERSION:-dev}"
OS="${OS:-linux}"
ARCH="${ARCH:-amd64}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

DIST_DIR="$REPO_ROOT/dist"
CACHE_DIR="${CACHE_DIR:-$DIST_DIR/bundle-cache}"

# Strip leading 'v' for the VERSION file content; keep it in tarball name
# for consistency with GH-release tags (which are vN.M.P).
VERSION_NO_V="${VERSION#v}"
BUNDLE_NAME="containarium-bundle-${VERSION}-${OS}-${ARCH}"
STAGING="$DIST_DIR/$BUNDLE_NAME"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[bundle]${NC} $1"; }
log_success() { echo -e "${GREEN}[bundle]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[bundle]${NC} $1"; }
log_error()   { echo -e "${RED}[bundle]${NC} $1" >&2; }

require_file() {
  if [ ! -f "$1" ]; then
    log_error "Required input missing: $1"
    log_error "Hint: $2"
    exit 1
  fi
}

# ---- 1. Validate prerequisites ----
log_info "Bundle: $BUNDLE_NAME"
log_info "Repo:   $REPO_ROOT"
log_info "Cache:  $CACHE_DIR"

require_file "$REPO_ROOT/bin/containarium-${OS}-${ARCH}" \
  "run 'make build-release' first"
require_file "$REPO_ROOT/bin/mcp-server-${OS}-${ARCH}" \
  "run 'make build-release' first"
require_file "$REPO_ROOT/bin/agent-box-${OS}-${ARCH}" \
  "run 'make build-release' first"

# Toolchain cache. Soft-warn rather than fail — the bundle is still
# useful with the binaries alone for testing the offline installer.
if [ ! -d "$CACHE_DIR/toolchains" ] || [ -z "$(ls -A "$CACHE_DIR/toolchains" 2>/dev/null)" ]; then
  log_warn "toolchain cache empty at $CACHE_DIR/toolchains"
  log_warn "run scripts/bundle/download-deps.sh OS=$OS ARCH=$ARCH first"
  log_warn "continuing anyway — bundle will be missing the runner-kit toolchains"
fi

# ---- 2. Clean + create staging tree ----
log_info "Preparing staging tree at $STAGING"
rm -rf "$STAGING"
mkdir -p \
  "$STAGING/bin" \
  "$STAGING/sidecars" \
  "$STAGING/toolchains" \
  "$STAGING/apt" \
  "$STAGING/images" \
  "$STAGING/docs"

# ---- 3. Core binaries ----
log_info "Copying core binaries (containarium, mcp-server, agent-box)"
# Strip the -${OS}-${ARCH} suffix inside the bundle — once extracted on
# the target host the user expects `bin/containarium`, not
# `bin/containarium-linux-amd64`.
install -m 0755 "$REPO_ROOT/bin/containarium-${OS}-${ARCH}" "$STAGING/bin/containarium"
install -m 0755 "$REPO_ROOT/bin/mcp-server-${OS}-${ARCH}"   "$STAGING/bin/mcp-server"
install -m 0755 "$REPO_ROOT/bin/agent-box-${OS}-${ARCH}"    "$STAGING/bin/agent-box"

# ---- 4. Actions-runner tarball (from cache) ----
if [ -d "$CACHE_DIR/bin" ]; then
  for f in "$CACHE_DIR/bin"/actions-runner-*.tar.gz; do
    if [ -f "$f" ]; then
      cp "$f" "$STAGING/bin/"
      log_info "  + $(basename "$f")"
    fi
  done
fi

# ---- 5. Toolchains ----
if [ -d "$CACHE_DIR/toolchains" ]; then
  log_info "Copying toolchains"
  cp -r "$CACHE_DIR/toolchains/." "$STAGING/toolchains/" 2>/dev/null || true
fi

# ---- 6. APT packages ----
if [ -d "$CACHE_DIR/apt" ]; then
  log_info "Copying apt packages"
  cp -r "$CACHE_DIR/apt/." "$STAGING/apt/" 2>/dev/null || true
fi

# ---- 7. Sidecar images ----
# Per PRD, each sidecar ships as a `docker save` tarball so the offline
# installer can `docker load` (or `incus image import`) it. We only have
# one sidecar today (otel-sidecar); generalize the loop for future ones.
log_info "Exporting sidecar images"
SIDECAR_DIR="$REPO_ROOT/sidecars"
if [ -d "$SIDECAR_DIR" ]; then
  for sc in "$SIDECAR_DIR"/*/; do
    sc_name="$(basename "$sc")"
    # Sidecar images are tagged ${name}:v${VERSION_NO_V} by
    # `make sidecar-build-*`. If the image isn't present locally we
    # skip with a warning — bundle is still functional, just no OTel.
    tag="containarium-${sc_name}:v${VERSION_NO_V}"
    out="$STAGING/sidecars/${sc_name}.tar"
    if command -v docker >/dev/null 2>&1 && docker image inspect "$tag" >/dev/null 2>&1; then
      log_info "  docker save $tag → $out"
      docker save "$tag" -o "$out"
    else
      log_warn "  skip $sc_name: image $tag not found locally"
      log_warn "  (run 'make sidecar-build-${sc_name#*-}' to build, then re-run bundle)"
    fi
  done
fi

# ---- 8. Offline installer + docs ----
log_info "Copying offline-install.sh and docs"
install -m 0755 "$REPO_ROOT/hacks/offline-install/install.sh" "$STAGING/offline-install.sh"
cp "$REPO_ROOT/hacks/offline-install/README.md" "$STAGING/README.md"

# Per-doc files inside docs/ subdirectory (matches PRD layout). Generate
# placeholders if the maintainers haven't authored them yet — the bundle
# is shippable without them but they're customer-facing.
for doc in INSTALL.md VERIFY.md GHES.md; do
  src="$REPO_ROOT/hacks/offline-install/docs/$doc"
  if [ -f "$src" ]; then
    cp "$src" "$STAGING/docs/$doc"
  else
    log_warn "  missing $src — writing placeholder"
    printf '# %s\n\nTODO: document this section.\n' "$doc" > "$STAGING/docs/$doc"
  fi
done

# ---- 9. VERSION file ----
echo "$VERSION_NO_V" > "$STAGING/VERSION"

# ---- 10. CHECKSUMS ----
log_info "Computing SHA256 checksums"
(
  cd "$STAGING"
  # Reproducible order: sort by path. Skip CHECKSUMS itself.
  find . -type f ! -name 'CHECKSUMS.sha256*' -print0 \
    | sort -z \
    | xargs -0 sha256sum > CHECKSUMS.sha256
)

# ---- 11. Tar + gzip ----
mkdir -p "$DIST_DIR"
TARBALL="$DIST_DIR/$BUNDLE_NAME.tar.gz"
log_info "Creating tarball: $TARBALL"
# --owner=0 --group=0 for reproducibility (cross-host bit-identical
# output if mtime is also fixed; we don't go that far in v0).
tar -C "$DIST_DIR" \
    --owner=0 --group=0 \
    -czf "$TARBALL" \
    "$BUNDLE_NAME"

SIZE="$(du -h "$TARBALL" | cut -f1)"
log_success "Bundle ready: $TARBALL ($SIZE)"

# ---- 12. Bundle-level checksum (for the GH release page) ----
(
  cd "$DIST_DIR"
  sha256sum "$BUNDLE_NAME.tar.gz" > "$BUNDLE_NAME.tar.gz.sha256"
)
log_success "Outer checksum: $DIST_DIR/$BUNDLE_NAME.tar.gz.sha256"
