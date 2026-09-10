#!/bin/bash
# Containarium Uninstallation Script
#
# This script removes Containarium and optionally its dependencies.
#
# Usage:
#   sudo ./hacks/uninstall.sh              # Remove Containarium only
#   sudo ./hacks/uninstall.sh --purge-incus  # Remove Containarium and Incus
#   sudo ./hacks/uninstall.sh --purge-all    # Remove everything including containers

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PURGE_INCUS=false
PURGE_ALL=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --purge-incus)
            PURGE_INCUS=true
            ;;
        --purge-all)
            PURGE_ALL=true
            PURGE_INCUS=true
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  (none)         Remove Containarium only (keep Incus and containers)"
            echo "  --purge-incus  Remove Containarium AND Incus"
            echo "  --purge-all    Remove EVERYTHING (Containarium, Incus, and all containers)"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

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
        exit 1
    fi
}

confirm_action() {
    local message=$1
    echo ""
    echo -e "${YELLOW}⚠️  WARNING: $message${NC}"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
}

stop_containarium_service() {
    log_info "Stopping Containarium service..."

    if systemctl is-active --quiet containarium; then
        systemctl stop containarium
        log_success "Containarium service stopped"
    else
        log_info "Containarium service is not running"
    fi
}

remove_systemd_service() {
    log_info "Removing systemd service..."

    if [ -f /etc/systemd/system/containarium.service ]; then
        systemctl disable containarium 2>/dev/null || true
        rm -f /etc/systemd/system/containarium.service
        systemctl daemon-reload
        log_success "Systemd service removed"
    else
        log_info "Systemd service not found"
    fi
}

remove_containarium_binary() {
    log_info "Removing Containarium binary..."

    removed=false
    if [ -f /usr/local/bin/containariumd ]; then
        rm -f /usr/local/bin/containariumd
        removed=true
    fi
    # #1781 rollout compat symlink: only remove /usr/local/bin/containarium
    # here if it's a symlink (our own, or anyone else's) — never a real file,
    # which some other mechanism placed there and this uninstaller doesn't own.
    if [ -L /usr/local/bin/containarium ]; then
        rm -f /usr/local/bin/containarium
        removed=true
    fi

    if [ "$removed" = "true" ]; then
        log_success "Containarium binary removed"
    else
        log_info "Containarium binary not found"
    fi
}

remove_config_files() {
    log_info "Removing configuration files..."

    if [ -d /etc/containarium ]; then
        rm -rf /etc/containarium
        log_success "Configuration files removed"
    else
        log_info "Configuration directory not found"
    fi

    if [ -f /etc/modules-load.d/containarium.conf ]; then
        rm -f /etc/modules-load.d/containarium.conf
        log_success "Kernel module configuration removed"
    fi
}

remove_data_directory() {
    log_info "Removing data directory..."

    if [ -d /var/lib/containarium ]; then
        rm -rf /var/lib/containarium
        log_success "Data directory removed"
    else
        log_info "Data directory not found"
    fi
}

remove_firewall_rules() {
    log_info "Removing firewall rules..."

    if command -v ufw &> /dev/null; then
        # Remove Containarium-specific rules
        ufw delete allow 50051/tcp 2>/dev/null || true
        ufw delete allow 8080/tcp 2>/dev/null || true
        log_success "Firewall rules removed"
    else
        log_info "UFW not installed, skipping firewall cleanup"
    fi
}

list_containers() {
    if command -v incus &> /dev/null; then
        CONTAINER_COUNT=$(incus list -f json | jq '. | length' 2>/dev/null || echo "0")
        if [ "$CONTAINER_COUNT" -gt 0 ]; then
            log_warn "Found $CONTAINER_COUNT existing container(s)"
            return 0
        fi
    fi
    return 1
}

delete_all_containers() {
    log_info "Deleting all containers..."

    if ! command -v incus &> /dev/null; then
        log_info "Incus not found, skipping container cleanup"
        return
    fi

    # Get list of containers
    CONTAINERS=$(incus list -f json | jq -r '.[].name' 2>/dev/null || echo "")

    if [ -z "$CONTAINERS" ]; then
        log_info "No containers found"
        return
    fi

    for container in $CONTAINERS; do
        log_info "Deleting container: $container"
        incus delete "$container" --force 2>/dev/null || true
    done

    log_success "All containers deleted"
}

remove_incus() {
    log_info "Removing Incus..."

    # Stop Incus service
    if systemctl is-active --quiet incus; then
        systemctl stop incus
    fi

    # Remove Incus packages
    apt-get remove -y incus incus-tools incus-client 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true

    # Remove Zabbly repository
    rm -f /etc/apt/sources.list.d/zabbly-incus-stable.list
    rm -f /usr/share/keyrings/zabbly-incus.gpg

    # Remove Incus data (if purging all)
    if [ "$PURGE_ALL" = true ]; then
        rm -rf /var/lib/incus
        rm -rf /var/log/incus
    fi

    log_success "Incus removed"
}

main() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Containarium Uninstallation Script"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    check_root

    # Show what will be removed
    echo "The following will be removed:"
    echo "  • Containarium binary"
    echo "  • Containarium systemd service"
    echo "  • Containarium configuration files"
    echo "  • Containarium data directory"
    echo "  • Firewall rules (gRPC, REST API)"

    if [ "$PURGE_ALL" = true ]; then
        echo "  • All LXC containers (⚠️  DATA LOSS)"
        echo "  • Incus installation"
        echo "  • Incus data directory (⚠️  DATA LOSS)"
    elif [ "$PURGE_INCUS" = true ]; then
        echo "  • Incus installation (containers preserved)"
    fi

    echo ""

    # Confirm action based on mode
    if [ "$PURGE_ALL" = true ]; then
        if list_containers; then
            confirm_action "This will DELETE ALL CONTAINERS and all their data! This action CANNOT be undone!"
        else
            confirm_action "This will remove Containarium and Incus"
        fi
    elif [ "$PURGE_INCUS" = true ]; then
        confirm_action "This will remove Containarium and Incus (but preserve existing containers)"
    else
        if list_containers; then
            log_info "Existing containers will be preserved"
        fi
        confirm_action "This will remove Containarium (but keep Incus and containers)"
    fi

    # Remove Containarium
    stop_containarium_service
    remove_systemd_service
    remove_containarium_binary
    remove_config_files
    remove_data_directory
    remove_firewall_rules

    # Remove containers if requested
    if [ "$PURGE_ALL" = true ]; then
        delete_all_containers
    fi

    # Remove Incus if requested
    if [ "$PURGE_INCUS" = true ]; then
        remove_incus
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${GREEN}  ✅ Uninstallation Complete${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    if [ "$PURGE_INCUS" = false ]; then
        echo "ℹ️  Incus is still installed. To remove it, run:"
        echo "   sudo ./hacks/uninstall.sh --purge-incus"
        echo ""
    fi

    if [ "$PURGE_ALL" = false ] && list_containers; then
        echo "ℹ️  Existing containers are preserved but no longer managed."
        echo "   You can view them with: incus list"
        echo ""
    fi

    echo "To reinstall Containarium, run:"
    echo "   sudo ./hacks/install.sh"
    echo ""
}

main "$@"
