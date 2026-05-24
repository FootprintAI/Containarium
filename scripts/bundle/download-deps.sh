#!/bin/bash
# download-deps.sh — pulls toolchain tarballs + .deb packages into the
# bundle staging directory, for the air-gapped install bundle.
#
# Per prd/cloud/air-gapped-install-bundle.md (E3a), the bundle ships:
#
#   - Go toolchain (runner kit uses it for buf install + Go CI jobs)
#   - Node + pnpm (runner kit uses it for frontend builds)
#   - buf (proto codegen)
#   - golangci-lint (Go linting)
#   - actions-runner (GitHub Actions self-hosted runner binary)
#   - Incus debs + ZFS utils + base apt deps (no internet during install)
#
# Required env (or default):
#
#   STAGING_DIR    where to write tarballs (default: dist/bundle-cache)
#   OS             linux (only OS supported today)
#   ARCH           amd64 | arm64
#   GO_VERSION     pinned in the script (override if bumping)
#   NODE_VERSION
#   PNPM_VERSION
#   BUF_VERSION
#   GOLANGCI_LINT_VERSION
#   RUNNER_VERSION
#
# Outputs (under $STAGING_DIR):
#
#   toolchains/go${GO_VERSION}.${OS}-${ARCH}.tar.gz
#   toolchains/node-v${NODE_VERSION}-${OS}-${node_arch}.tar.xz
#   toolchains/pnpm-${PNPM_VERSION}-${OS}-${node_arch}
#   toolchains/buf-${OS}-${buf_arch}
#   toolchains/golangci-lint-${GOLANGCI_LINT_VERSION}-${OS}-${ARCH}.tar.gz
#   bin/actions-runner-${OS}-${runner_arch}-${RUNNER_VERSION}.tar.gz
#   apt/*.deb
#
# Idempotent — re-runs skip already-downloaded files (checks file
# existence; does NOT re-validate checksums beyond what curl returns).
#
# NOTE on apt downloads: requires `apt-get download` + `apt-rdepends`,
# which only work on a Debian/Ubuntu host. On non-Debian hosts the
# function emits a placeholder + warning, and the operator is expected
# to drop pre-downloaded .debs into $STAGING_DIR/apt/ manually (see
# scripts/bundle/README.md).

set -euo pipefail

# ---- defaults ----
STAGING_DIR="${STAGING_DIR:-dist/bundle-cache}"
OS="${OS:-linux}"
ARCH="${ARCH:-amd64}"

# Toolchain versions — pin precisely per PRD reproducibility requirement.
GO_VERSION="${GO_VERSION:-1.25.10}"
NODE_VERSION="${NODE_VERSION:-22.11.0}"
PNPM_VERSION="${PNPM_VERSION:-9.12.3}"
BUF_VERSION="${BUF_VERSION:-1.38.0}"
GOLANGCI_LINT_VERSION="${GOLANGCI_LINT_VERSION:-2.1.6}"
RUNNER_VERSION="${RUNNER_VERSION:-2.319.1}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[deps]${NC} $1"; }
log_success() { echo -e "${GREEN}[deps]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[deps]${NC} $1"; }
log_error()   { echo -e "${RED}[deps]${NC} $1" >&2; }

# Map ARCH → vendor-specific naming conventions.
# Go uses linux-amd64 / linux-arm64.
# Node uses linux-x64 / linux-arm64.
# buf uses Linux-x86_64 / Linux-aarch64.
# golangci-lint uses linux-amd64 / linux-arm64.
# actions-runner uses linux-x64 / linux-arm64.
case "$ARCH" in
  amd64)
    NODE_ARCH="x64"
    BUF_ARCH="x86_64"
    RUNNER_ARCH="x64"
    ;;
  arm64)
    NODE_ARCH="arm64"
    BUF_ARCH="aarch64"
    RUNNER_ARCH="arm64"
    ;;
  *)
    log_error "Unsupported ARCH: $ARCH (expected amd64 or arm64)"
    exit 1
    ;;
esac

# Capitalised OS for buf (Linux vs linux).
case "$OS" in
  linux)
    BUF_OS="Linux"
    ;;
  *)
    log_error "Unsupported OS: $OS (expected linux)"
    exit 1
    ;;
esac

mkdir -p "$STAGING_DIR/toolchains" "$STAGING_DIR/bin" "$STAGING_DIR/apt"

# fetch <url> <output-path>
# Skip if the output already exists and is non-empty (idempotent re-runs).
fetch() {
  local url="$1" out="$2"
  if [ -s "$out" ]; then
    log_info "skip (cached): $(basename "$out")"
    return 0
  fi
  log_info "fetch: $url"
  # -L follow redirects; -f fail on HTTP error; --retry 3 buffers flaky
  # network without masking persistent failure.
  if ! curl -fL --retry 3 --retry-delay 2 -o "$out.partial" "$url"; then
    log_error "fetch failed: $url"
    rm -f "$out.partial"
    return 1
  fi
  mv "$out.partial" "$out"
  log_success "fetched: $(basename "$out")"
}

# ---- Go ----
download_go() {
  local file="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
  fetch "https://go.dev/dl/${file}" "$STAGING_DIR/toolchains/${file}"
}

# ---- Node ----
download_node() {
  # Node tarballs for linux use .tar.xz; for darwin .tar.gz. We only
  # ship linux today so xz is fine.
  local file="node-v${NODE_VERSION}-${OS}-${NODE_ARCH}.tar.xz"
  fetch "https://nodejs.org/dist/v${NODE_VERSION}/${file}" \
        "$STAGING_DIR/toolchains/${file}"
}

# ---- pnpm ----
download_pnpm() {
  # pnpm publishes raw binaries (no tarball wrapper) named like
  # pnpm-linux-x64 / pnpm-linux-arm64 via GitHub releases.
  local file="pnpm-${OS}-${NODE_ARCH}"
  fetch "https://github.com/pnpm/pnpm/releases/download/v${PNPM_VERSION}/${file}" \
        "$STAGING_DIR/toolchains/pnpm-${PNPM_VERSION}-${OS}-${NODE_ARCH}"
}

# ---- buf ----
download_buf() {
  # buf ships per-platform binaries via GitHub releases.
  local file="buf-${BUF_OS}-${BUF_ARCH}"
  fetch "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/${file}" \
        "$STAGING_DIR/toolchains/buf-${BUF_VERSION}-${OS}-${ARCH}"
}

# ---- golangci-lint ----
download_golangci_lint() {
  local file="golangci-lint-${GOLANGCI_LINT_VERSION}-${OS}-${ARCH}.tar.gz"
  fetch "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/${file}" \
        "$STAGING_DIR/toolchains/${file}"
}

# ---- actions-runner ----
download_actions_runner() {
  local file="actions-runner-${OS}-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
  fetch "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${file}" \
        "$STAGING_DIR/bin/${file}"
}

# ---- apt packages ----
# Downloads the .debs install.sh would pull on a connected host:
#   - incus, incus-client, incus-extra (from Zabbly)
#   - zfsutils-linux (from Ubuntu main)
#   - curl, wget, gnupg, ca-certificates, software-properties-common,
#     jq, build-essential, libicu-dev (runner-kit deps)
# `apt-rdepends` resolves transitive deps; `apt-get download` pulls them.
download_apt_packages() {
  if [ "$OS" != "linux" ]; then
    log_warn "Skipping apt downloads on non-linux OS"
    return 0
  fi

  if ! command -v apt-get >/dev/null 2>&1; then
    log_warn "apt-get not present — cannot download .debs on this host."
    log_warn "Drop pre-downloaded .deb files into: $STAGING_DIR/apt/"
    log_warn "See scripts/bundle/README.md for the apt-prep workflow."
    # Write a sentinel so the bundle build doesn't silently produce an
    # empty apt/ directory.
    touch "$STAGING_DIR/apt/.MANUAL_APT_DOWNLOAD_REQUIRED"
    return 0
  fi

  if ! command -v apt-rdepends >/dev/null 2>&1; then
    log_warn "apt-rdepends not installed; install with: apt-get install apt-rdepends"
    log_warn "Falling back to direct apt-get download (no transitive deps)."
  fi

  log_info "Downloading apt packages into $STAGING_DIR/apt/"
  # Use a subshell so the cd doesn't leak.
  (
    cd "$STAGING_DIR/apt"

    local pkgs=(
      curl wget gnupg ca-certificates software-properties-common
      jq zfsutils-linux build-essential libicu-dev git
      incus incus-client incus-extra
    )

    if command -v apt-rdepends >/dev/null 2>&1; then
      local all_deps=""
      for pkg in "${pkgs[@]}"; do
        all_deps+="$(apt-rdepends "$pkg" 2>/dev/null | grep -v '^ ' | sort -u) "
      done
      # shellcheck disable=SC2086
      apt-get download $all_deps 2>&1 | grep -v '^E:' || true
    else
      apt-get download "${pkgs[@]}" 2>&1 | grep -v '^E:' || true
    fi
  )
  log_success "apt packages downloaded"
}

main() {
  log_info "Staging dir: $STAGING_DIR"
  log_info "Target:      $OS/$ARCH"
  log_info "Versions:    Go $GO_VERSION  Node $NODE_VERSION  pnpm $PNPM_VERSION"
  log_info "             buf $BUF_VERSION  golangci-lint $GOLANGCI_LINT_VERSION"
  log_info "             actions-runner $RUNNER_VERSION"
  echo

  download_go
  download_node
  download_pnpm
  download_buf
  download_golangci_lint
  download_actions_runner
  download_apt_packages

  echo
  log_success "All downloads complete. Staging tree:"
  if command -v find >/dev/null 2>&1; then
    find "$STAGING_DIR" -maxdepth 3 -type f | sort
  fi
}

main "$@"
