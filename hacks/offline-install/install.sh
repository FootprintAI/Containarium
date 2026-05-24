#!/bin/bash
# Containarium Air-Gapped Installation Script
#
# This script installs Containarium and all dependencies on a fresh
# Ubuntu 24.04 system WITHOUT making any network calls. Every dependency
# is read from the surrounding bundle directory tree.
#
# Per prd/cloud/air-gapped-install-bundle.md (E3a/E3b), this is the
# drop-in replacement for `hacks/install.sh` for Tier 3 customers with
# no internet egress.
#
# Run from the extracted bundle directory:
#
#   tar xzf containarium-bundle-vX.Y.Z-linux-amd64.tar.gz
#   cd containarium-bundle-vX.Y.Z-linux-amd64/
#   sudo ./offline-install.sh
#
# Flags (match hacks/install.sh where applicable):
#
#   --skip-checksum-verify    skip re-checking CHECKSUMS.sha256 (NOT
#                             recommended; we re-verify by default
#                             because in-transit corruption is the
#                             primary integrity threat for air-gapped
#                             distribution).
#   --skip-sidecars           don't import sidecar images (do it later)
#   --skip-base-image         don't import the containarium-base Incus
#                             image (do it later)
#   --skip-firewall           don't touch ufw rules

set -e

# Colors for output — match hacks/install.sh
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration (match hacks/install.sh)
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/containarium"
DATA_DIR="/var/lib/containarium"

# Bundle layout — every path is RESOLVED FROM the bundle directory
# (this script's parent), never from the network.
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$BUNDLE_DIR/bin"
APT_DIR="$BUNDLE_DIR/apt"
SIDECAR_DIR="$BUNDLE_DIR/sidecars"
IMAGE_DIR="$BUNDLE_DIR/images"
CHECKSUM_FILE="$BUNDLE_DIR/CHECKSUMS.sha256"
VERSION_FILE="$BUNDLE_DIR/VERSION"

# Flag defaults
SKIP_CHECKSUM_VERIFY=0
SKIP_SIDECARS=0
SKIP_BASE_IMAGE=0
SKIP_FIREWALL=0

# ---- argparse ----
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-checksum-verify) SKIP_CHECKSUM_VERIFY=1 ;;
    --skip-sidecars)        SKIP_SIDECARS=1 ;;
    --skip-base-image)      SKIP_BASE_IMAGE=1 ;;
    --skip-firewall)        SKIP_FIREWALL=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -50
      exit 0
      ;;
    *)
      echo "Unknown flag: $1 (use --help)" >&2
      exit 1
      ;;
  esac
  shift
done

# Helper functions (match hacks/install.sh)
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        log_info "Please run: sudo $0"
        exit 1
    fi
}

check_os() {
    log_info "Checking operating system..."

    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    . /etc/os-release

    if [ "$ID" != "ubuntu" ]; then
        log_warn "This script is designed for Ubuntu. Detected: $ID"
        log_warn "Continuing anyway, but issues may occur..."
    fi

    if [ "$VERSION_ID" != "24.04" ] && [ "$VERSION_ID" != "22.04" ]; then
        log_warn "Recommended version: Ubuntu 24.04. Detected: $VERSION_ID"
        log_warn "Continuing anyway..."
    fi

    log_success "OS check passed: $PRETTY_NAME"
}

check_bundle() {
    log_info "Verifying bundle layout at $BUNDLE_DIR"

    local errors=0
    for required in "$BIN_DIR/containarium" "$BIN_DIR/mcp-server" "$BIN_DIR/agent-box" "$VERSION_FILE"; do
        if [ ! -f "$required" ]; then
            log_error "Missing bundle file: $required"
            errors=$((errors + 1))
        fi
    done

    if [ $errors -gt 0 ]; then
        log_error "Bundle is incomplete. Did you extract the full tarball?"
        exit 1
    fi

    log_success "Bundle layout OK (version $(cat "$VERSION_FILE"))"
}

verify_checksums() {
    if [ "$SKIP_CHECKSUM_VERIFY" = "1" ]; then
        log_warn "Skipping checksum verification (--skip-checksum-verify)"
        return 0
    fi

    if [ ! -f "$CHECKSUM_FILE" ]; then
        log_warn "CHECKSUMS.sha256 not found — skipping verification."
        log_warn "Recommend re-downloading the bundle if this is unexpected."
        return 0
    fi

    log_info "Verifying bundle SHA256 checksums (catches in-transit corruption)..."
    if (cd "$BUNDLE_DIR" && sha256sum -c CHECKSUMS.sha256 --quiet); then
        log_success "All bundle files match recorded checksums"
    else
        log_error "Checksum mismatch — bundle is corrupted or tampered with"
        log_error "Re-transfer the bundle from the source"
        exit 1
    fi
}

install_apt_dependencies() {
    log_info "Installing system dependencies from $APT_DIR (no network)"

    if [ ! -d "$APT_DIR" ] || [ -z "$(ls -A "$APT_DIR" 2>/dev/null | grep -v '\.MANUAL' || true)" ]; then
        log_warn "No .deb packages in bundle apt/ directory"
        log_warn "Skipping apt step — assuming required packages are pre-installed"
        log_warn "(curl, wget, gnupg, jq, ca-certificates, zfsutils-linux, incus,"
        log_warn " incus-client, incus-extra, build-essential, libicu-dev)"
        return 0
    fi

    # `apt-get install ./path/*.deb` installs from local files and resolves
    # local-only deps without contacting the network. --no-download
    # makes any unmet dep fail loudly instead of trying to fetch it.
    log_info "Running: apt-get install --no-download --yes ./apt/*.deb"
    apt-get install --no-download --yes "$APT_DIR"/*.deb || \
        log_warn "apt-get install exited non-zero; checking critical commands below"

    # Verify the critical pieces landed.
    local missing=()
    for cmd in incus zfs jq curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Required commands missing after apt step: ${missing[*]}"
        log_error "Check /var/log/dpkg.log; bundle may be missing transitive deps"
        exit 1
    fi

    log_success "System dependencies installed from bundle"
}

initialize_incus() {
    log_info "Checking Incus initialization..."

    if ! incus info &> /dev/null; then
        log_info "Initializing Incus with default settings..."
        incus admin init --auto
        log_success "Incus initialized"
    else
        log_info "Incus already initialized"
    fi
}

configure_zfs() {
    log_info "Configuring ZFS..."

    if ! lsmod | grep -q zfs; then
        log_info "Loading ZFS kernel module..."
        modprobe zfs || log_warn "modprobe zfs failed; kernel may not have ZFS support"
    fi

    if ! grep -q "^zfs$" /etc/modules-load.d/zfs.conf 2>/dev/null; then
        echo "zfs" > /etc/modules-load.d/zfs.conf
        log_success "ZFS module configured to load on boot"
    fi

    log_success "ZFS configured"
}

configure_kernel_modules() {
    log_info "Configuring kernel modules for Docker support..."

    MODULES=("overlay" "br_netfilter" "nf_nat")

    for module in "${MODULES[@]}"; do
        if ! lsmod | grep -q "^$module"; then
            log_info "Loading kernel module: $module"
            modprobe "$module" || log_warn "modprobe $module failed"
        fi

        if ! grep -q "^$module$" /etc/modules-load.d/containarium.conf 2>/dev/null; then
            echo "$module" >> /etc/modules-load.d/containarium.conf
        fi
    done

    log_success "Kernel modules configured"
}

install_binaries() {
    log_info "Installing Containarium binaries from $BIN_DIR (no network)"

    install -m 0755 "$BIN_DIR/containarium" "$INSTALL_DIR/containarium"
    install -m 0755 "$BIN_DIR/mcp-server"   "$INSTALL_DIR/mcp-server"
    install -m 0755 "$BIN_DIR/agent-box"    "$INSTALL_DIR/agent-box"

    local v
    v="$("$INSTALL_DIR/containarium" version 2>/dev/null || echo "unknown")"
    log_success "Containarium installed: $v"
    log_success "mcp-server installed:   $INSTALL_DIR/mcp-server"
    log_success "agent-box installed:    $INSTALL_DIR/agent-box"
}

generate_tls_certificates() {
    log_info "Generating TLS certificates for mTLS..."

    if [ -f "$CONFIG_DIR/certs/server.crt" ]; then
        log_info "TLS certificates already exist"
        return 0
    fi

    "$INSTALL_DIR/containarium" cert generate --output "$CONFIG_DIR/certs"

    log_success "TLS certificates generated: $CONFIG_DIR/certs"
}

setup_jwt_secret() {
    log_info "Setting up JWT secret for REST API..."

    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    if [ ! -f "$CONFIG_DIR/jwt.secret" ]; then
        # `openssl rand` is local CSPRNG (no network). If openssl is
        # missing in the air-gapped image, fall back to /dev/urandom.
        if command -v openssl >/dev/null 2>&1; then
            openssl rand -base64 32 > "$CONFIG_DIR/jwt.secret"
        else
            head -c 32 /dev/urandom | base64 > "$CONFIG_DIR/jwt.secret"
        fi
        chmod 600 "$CONFIG_DIR/jwt.secret"
        log_success "JWT secret generated: $CONFIG_DIR/jwt.secret"
    else
        log_info "JWT secret already exists: $CONFIG_DIR/jwt.secret"
    fi
}

create_systemd_service() {
    log_info "Creating systemd service via 'containarium service install'..."

    /usr/local/bin/containarium service install

    log_success "Systemd service created"
}

setup_firewall() {
    if [ "$SKIP_FIREWALL" = "1" ]; then
        log_info "Skipping firewall setup (--skip-firewall)"
        return 0
    fi

    log_info "Configuring firewall..."

    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp comment 'SSH' || true
        ufw allow 50051/tcp comment 'Containarium gRPC' || true
        ufw allow 8080/tcp comment 'Containarium REST API' || true

        if ! ufw status | grep -q "Status: active"; then
            log_warn "UFW is installed but not active. Enable with: sudo ufw enable"
        else
            log_success "Firewall rules configured"
        fi
    else
        log_warn "UFW not installed. Consider installing for security: apt install ufw"
    fi
}

generate_initial_token() {
    log_info "Generating initial admin token..."

    if [ -f "$CONFIG_DIR/jwt.secret" ]; then
        TOKEN=$("$INSTALL_DIR/containarium" token generate \
            --username admin \
            --roles admin \
            --expiry 720h \
            --secret-file "$CONFIG_DIR/jwt.secret" 2>/dev/null | grep "^eyJ" || echo "")

        if [ -n "$TOKEN" ]; then
            echo "$TOKEN" > "$CONFIG_DIR/admin.token"
            chmod 600 "$CONFIG_DIR/admin.token"
            log_success "Admin token saved to: $CONFIG_DIR/admin.token"
        fi
    fi
}

import_base_image() {
    if [ "$SKIP_BASE_IMAGE" = "1" ]; then
        log_info "Skipping base-image import (--skip-base-image)"
        return 0
    fi

    if [ ! -d "$IMAGE_DIR" ]; then
        log_info "No images/ directory in bundle — skipping base-image import"
        return 0
    fi

    shopt -s nullglob
    local found=0
    for img in "$IMAGE_DIR"/containarium-base-*.tar.gz "$IMAGE_DIR"/containarium-base-*.tar; do
        if [ -f "$img" ]; then
            found=1
            local alias_name
            # Derive alias from filename:
            #   containarium-base-v0.19.0.tar.gz → containarium-base:v0.19.0
            alias_name="$(basename "$img" \
                | sed -E 's/^(containarium-base)-(v[0-9.]+)\.tar(\.gz)?$/\1:\2/')"
            log_info "incus image import $img --alias $alias_name"
            incus image import "$img" --alias "$alias_name" 2>&1 \
                | grep -v 'already exists' || true
            log_success "Imported base image: $alias_name"
        fi
    done
    shopt -u nullglob

    if [ "$found" = "0" ]; then
        log_info "No containarium-base image tarball in bundle — skipping"
        log_info "(Tier 3 customers without a base image can use stock Ubuntu)"
    fi
}

import_sidecars() {
    if [ "$SKIP_SIDECARS" = "1" ]; then
        log_info "Skipping sidecar imports (--skip-sidecars)"
        return 0
    fi

    if [ ! -d "$SIDECAR_DIR" ]; then
        log_info "No sidecars/ directory in bundle — skipping"
        return 0
    fi

    shopt -s nullglob
    local imports=0
    for tar in "$SIDECAR_DIR"/*.tar; do
        local name
        name="$(basename "$tar" .tar)"
        if command -v docker >/dev/null 2>&1; then
            log_info "docker load < $tar"
            if docker load -i "$tar"; then
                imports=$((imports + 1))
            else
                log_warn "docker load failed for $name (skipping)"
            fi
        else
            log_warn "docker not available; cannot import sidecar $name"
            log_warn "If using Incus to run sidecars, import manually:"
            log_warn "  incus image import $tar --alias $name"
        fi
    done
    shopt -u nullglob

    if [ "$imports" -gt 0 ]; then
        log_success "Loaded $imports sidecar image(s)"
    fi
}

print_completion_message() {
    local bundle_version
    bundle_version="$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")"

    echo ""
    echo "==============================================================="
    echo -e "${GREEN}  Containarium Air-Gapped Installation Complete${NC}"
    echo -e "${GREEN}  No outbound network calls made during install${NC}"
    echo "==============================================================="
    echo ""
    echo "Installed Components:"
    echo "   - Containarium $(containarium version 2>/dev/null || echo "$bundle_version")"
    echo "   - Incus $(incus --version 2>/dev/null || echo "(installed)")"
    echo "   - ZFS kernel module"
    echo "   - mcp-server, agent-box"
    echo ""
    echo "Configuration:"
    echo "   - Config directory: $CONFIG_DIR"
    echo "   - JWT secret: $CONFIG_DIR/jwt.secret"
    if [ -f "$CONFIG_DIR/admin.token" ]; then
        echo "   - Admin token: $CONFIG_DIR/admin.token"
    fi
    echo "   - Systemd service: /etc/systemd/system/containarium.service"
    echo ""
    echo "Next Steps:"
    echo ""
    echo "   1. Start the daemon:"
    echo "      sudo systemctl start containarium"
    echo ""
    echo "   2. Check status:"
    echo "      sudo systemctl status containarium"
    echo ""
    echo "   3. Create your first container (uses the bundled base image,"
    echo "      no network calls):"
    echo ""
    echo "      sudo containarium create test-1 \\"
    echo "        --image containarium-base:v${bundle_version} \\"
    echo "        --ssh-key ~/.ssh/id_ed25519.pub"
    echo ""
    echo "   4. (Optional) Provision a self-hosted GHA runner. For GitHub"
    echo "      Enterprise Server set GH_BASE_URL to your server URL:"
    echo ""
    echo "      ssh test-1 'sudo GH_REPO=org/repo GH_PAT=xxx \\"
    echo "        GH_BASE_URL=https://github.your-company.internal \\"
    echo "        ./hacks/runner/install.sh'"
    echo ""
    echo "Documentation (offline, inside the bundle):"
    echo "   - $BUNDLE_DIR/docs/INSTALL.md"
    echo "   - $BUNDLE_DIR/docs/VERIFY.md"
    echo "   - $BUNDLE_DIR/docs/GHES.md"
    echo ""
    echo "==============================================================="
    echo ""
}

# Main installation flow
main() {
    echo ""
    echo "==============================================================="
    echo "  Containarium Air-Gapped Installation"
    echo "==============================================================="
    echo ""

    check_root
    check_os
    check_bundle
    verify_checksums
    install_apt_dependencies
    initialize_incus
    configure_zfs
    configure_kernel_modules
    install_binaries
    generate_tls_certificates
    setup_jwt_secret
    create_systemd_service
    setup_firewall
    generate_initial_token
    import_base_image
    import_sidecars
    print_completion_message
}

# Run main function
main "$@"
