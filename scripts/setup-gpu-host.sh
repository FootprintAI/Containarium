#!/bin/bash
#
# Containarium GPU Host Setup Script
#
# Sets up a bare-metal or non-GCE Linux server with:
#   1. NVIDIA driver (pinned version)
#   2. NVIDIA Container Toolkit (for Incus GPU passthrough)
#   3. Incus (from Zabbly, pinned version)
#   4. ZFS storage backend
#   5. Kernel modules and sysctl for containers
#
# Usage:
#   sudo ./setup-gpu-host.sh [--skip-reboot]
#
# After running, reboot the machine if the NVIDIA driver was freshly installed.
# Then run: nvidia-smi  to verify GPU access.
#
# Tested on: Ubuntu 24.04 LTS (Noble)
#

set -euo pipefail

# ============================================================
# Pinned versions — update these when upgrading
# ============================================================
NVIDIA_DRIVER_VERSION="570"          # apt: nvidia-driver-570
INCUS_VERSION=""                      # leave empty for latest stable (6.x)
NVIDIA_CTK_VERSION=""                 # leave empty for latest stable

# ============================================================
# Options
# ============================================================
SKIP_REBOOT=false
for arg in "$@"; do
    case "$arg" in
        --skip-reboot) SKIP_REBOOT=true ;;
        --help|-h)
            echo "Usage: sudo $0 [--skip-reboot]"
            exit 0
            ;;
    esac
done

# ============================================================
# Pre-flight checks
# ============================================================
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

if ! grep -q 'Ubuntu' /etc/os-release 2>/dev/null; then
    echo "WARNING: This script is tested on Ubuntu 24.04. Proceed at your own risk."
fi

echo "================================================"
echo "Containarium GPU Host Setup"
echo "================================================"
echo "  NVIDIA driver:   $NVIDIA_DRIVER_VERSION"
echo "  Incus:           ${INCUS_VERSION:-latest stable}"
echo "  NVIDIA CTK:      ${NVIDIA_CTK_VERSION:-latest stable}"
echo ""

# ============================================================
# 1. System update & essentials
# ============================================================
echo "==> [1/7] Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget git vim htop jq net-tools bridge-utils \
    ca-certificates gnupg lsb-release software-properties-common

# ============================================================
# 2. NVIDIA Driver
# ============================================================
echo "==> [2/7] Installing NVIDIA driver ${NVIDIA_DRIVER_VERSION}..."

NEED_REBOOT=false

if nvidia-smi &>/dev/null; then
    CURRENT_DRIVER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -1)
    echo "  NVIDIA driver already installed: $CURRENT_DRIVER"
else
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nvidia-driver-${NVIDIA_DRIVER_VERSION}

    echo "  NVIDIA driver ${NVIDIA_DRIVER_VERSION} installed (reboot required)"
    NEED_REBOOT=true
fi

# ============================================================
# 3. NVIDIA Container Toolkit
# ============================================================
echo "==> [3/7] Installing NVIDIA Container Toolkit..."

if ! command -v nvidia-ctk &>/dev/null; then
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

    curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        | tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

    apt-get update

    if [ -n "$NVIDIA_CTK_VERSION" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y nvidia-container-toolkit="$NVIDIA_CTK_VERSION"
    else
        DEBIAN_FRONTEND=noninteractive apt-get install -y nvidia-container-toolkit
    fi
    echo "  NVIDIA Container Toolkit installed"
else
    echo "  NVIDIA Container Toolkit already installed: $(nvidia-ctk --version 2>/dev/null || echo 'unknown')"
fi

# ============================================================
# 4. Incus (from Zabbly)
# ============================================================
echo "==> [4/7] Installing Incus from Zabbly repository..."

# Remove Ubuntu's default Incus packages (6.0.0) if present — they conflict with Zabbly
if dpkg -l incus-tools 2>/dev/null | grep -q '^ii.*6\.0'; then
    echo "  Removing Ubuntu default incus packages (6.0.x) to avoid conflicts..."
    DEBIAN_FRONTEND=noninteractive apt-get remove -y incus incus-tools incus-client incus-base 2>/dev/null || true
fi

if [ ! -f /etc/apt/sources.list.d/zabbly-incus-stable.list ]; then
    curl -fsSL https://pkgs.zabbly.com/key.asc \
        | gpg --dearmor -o /usr/share/keyrings/zabbly-incus.gpg

    CODENAME=$(lsb_release -cs)
    echo "deb [signed-by=/usr/share/keyrings/zabbly-incus.gpg] https://pkgs.zabbly.com/incus/stable ${CODENAME} main" \
        | tee /etc/apt/sources.list.d/zabbly-incus-stable.list

    # Pin Zabbly repo higher than Ubuntu's default to avoid version conflicts
    cat > /etc/apt/preferences.d/zabbly-incus <<PINEOF
Package: incus* lxc* lxd*
Pin: origin pkgs.zabbly.com
Pin-Priority: 1001
PINEOF

    apt-get update
fi

if ! incus --version 2>/dev/null | grep -qE '^6\.(19|[2-9][0-9])'; then
    # Zabbly's incus package includes tools/client — do NOT install
    # Ubuntu's separate incus-tools/incus-client packages (they conflict)
    if [ -n "$INCUS_VERSION" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y "incus=$INCUS_VERSION"
    else
        DEBIAN_FRONTEND=noninteractive apt-get install -y incus
    fi
    echo "  Incus $(incus --version) installed"
else
    echo "  Incus already installed: $(incus --version)"
fi

# ============================================================
# 5. ZFS + Incus initialization
# ============================================================
echo "==> [5/7] Setting up ZFS and initializing Incus..."

if ! command -v zpool &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y zfsutils-linux
    modprobe zfs
    echo "  ZFS installed"
fi

if [ ! -f /var/lib/incus/.initialized ]; then
    if ! zpool list incus-local &>/dev/null; then
        mkdir -p /var/lib/incus/disks
        truncate -s 50G /var/lib/incus/disks/incus.img
        zpool create \
            -o ashift=12 \
            -O compression=lz4 \
            -O atime=off \
            -O xattr=sa \
            -m /var/lib/incus/storage \
            incus-local /var/lib/incus/disks/incus.img

        zfs create incus-local/containers
        echo "  ZFS pool created (file-backed, 50GB)"
    fi

    cat <<EOF | incus admin init --preseed
config: {}
networks:
- name: incusbr0
  type: bridge
  config:
    ipv4.address: 10.0.3.1/24
    ipv4.nat: "true"
    ipv6.address: none
storage_pools:
- name: default
  driver: zfs
  config:
    source: incus-local/containers
profiles:
- name: default
  devices:
    eth0:
      name: eth0
      network: incusbr0
      type: nic
    root:
      path: /
      pool: default
      type: disk
      size: 20GB
cluster: null
EOF
    touch /var/lib/incus/.initialized
    echo "  Incus initialized with ZFS"
else
    echo "  Incus already initialized"
fi

# ============================================================
# 6. Kernel modules & sysctl
# ============================================================
echo "==> [6/7] Loading kernel modules and configuring sysctl..."

MODULES=(overlay br_netfilter nf_nat xt_conntrack ip_tables iptable_nat)
for mod in "${MODULES[@]}"; do
    if ! lsmod | grep -q "^$mod "; then
        modprobe "$mod"
        echo "$mod" >> /etc/modules-load.d/containarium.conf
    fi
done

cat > /etc/sysctl.d/99-containarium.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 524288
EOF

sysctl --system >/dev/null 2>&1
echo "  Kernel modules and sysctl configured"

# ============================================================
# 7. Verify GPU + Incus integration
# ============================================================
echo "==> [7/7] Verifying setup..."

echo ""
echo "  Incus:        $(incus --version)"
echo "  ZFS pool:     $(zpool list -H -o name,size 2>/dev/null | head -1)"

if nvidia-smi &>/dev/null; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)
    GPU_DRIVER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -1)
    echo "  GPU:          $GPU_NAME"
    echo "  Driver:       $GPU_DRIVER"
    echo "  nvidia-ctk:   $(nvidia-ctk --version 2>/dev/null | tail -1 || echo 'installed')"
    echo ""
    echo "  GPU passthrough ready! To add GPU to a container:"
    echo "    incus config device add <container> gpu gpu"
else
    echo "  GPU:          driver not loaded (reboot required)"
fi

# ============================================================
# Done
# ============================================================
echo ""
echo "================================================"
echo "Setup complete!"
echo "================================================"

if [ "$NEED_REBOOT" = true ]; then
    echo ""
    echo "  ** REBOOT REQUIRED for NVIDIA driver to load **"
    if [ "$SKIP_REBOOT" = false ]; then
        echo "  Rebooting in 5 seconds... (Ctrl+C to cancel)"
        sleep 5
        reboot
    else
        echo "  Run: sudo reboot"
    fi
fi
