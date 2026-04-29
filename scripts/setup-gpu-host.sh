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
#   sudo ./setup-gpu-host.sh [--skip-reboot] [--yes] [--data-disk DISK] [--backup-disks DISK1,DISK2]
#
# Disk layout (auto-detected if not specified):
#   --data-disk     Fastest unused disk for container storage (e.g., nvme0n1)
#   --backup-disks  Rotational disks for ZFS mirror backup pool (e.g., sda,sdb)
#   --yes           Skip confirmation prompt (for automation)
#   If no unused disks are found, falls back to file-backed 50GB pool.
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
AUTO_YES=false
DATA_DISK=""
BACKUP_DISKS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-reboot) SKIP_REBOOT=true; shift ;;
        --yes|-y) AUTO_YES=true; shift ;;
        --data-disk) DATA_DISK="$2"; shift 2 ;;
        --backup-disks) BACKUP_DISKS="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [--skip-reboot] [--yes] [--data-disk DISK] [--backup-disks DISK1,DISK2]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ============================================================
# Disk auto-detection
# ============================================================
# Returns unused whole disks (no partitions, not mounted, not in a zpool)
detect_unused_disks() {
    local nvme_disks=()
    local rotational_disks=()
    local ssd_disks=()

    while IFS= read -r disk; do
        [ -z "$disk" ] && continue
        local devname="/dev/$disk"

        # Skip if disk has partitions
        if lsblk -n -o TYPE "$devname" 2>/dev/null | grep -q part; then
            continue
        fi

        # Skip if any part of it is mounted
        if lsblk -n -o MOUNTPOINTS "$devname" 2>/dev/null | grep -q '/'; then
            continue
        fi

        # Skip if already in a zpool
        if zpool status 2>/dev/null | grep -q "$disk"; then
            continue
        fi

        # Classify by type
        if [[ "$disk" == nvme* ]]; then
            nvme_disks+=("$disk")
        elif [ -f "/sys/block/$disk/queue/rotational" ] && [ "$(cat "/sys/block/$disk/queue/rotational")" = "1" ]; then
            rotational_disks+=("$disk")
        else
            ssd_disks+=("$disk")
        fi
    done < <(lsblk -d -n -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}')

    # Export results via global arrays
    DETECTED_NVME_COUNT=${#nvme_disks[@]}
    DETECTED_ROTATIONAL_COUNT=${#rotational_disks[@]}
    DETECTED_SSD_COUNT=${#ssd_disks[@]}
    DETECTED_NVME_LIST="${nvme_disks[*]:-}"
    DETECTED_ROTATIONAL_LIST="${rotational_disks[*]:-}"
    DETECTED_SSD_LIST="${ssd_disks[*]:-}"
    # First items for auto-selection
    DETECTED_NVME_FIRST="${nvme_disks[0]:-}"
    DETECTED_SSD_FIRST="${ssd_disks[0]:-}"
    DETECTED_ROT_FIRST="${rotational_disks[0]:-}"
    DETECTED_ROT_SECOND="${rotational_disks[1]:-}"
}

if [ -z "$DATA_DISK" ] || [ -z "$BACKUP_DISKS" ]; then
    detect_unused_disks

    # Auto-select data disk: prefer NVMe, then SSD
    if [ -z "$DATA_DISK" ]; then
        if [ -n "$DETECTED_NVME_FIRST" ]; then
            DATA_DISK="$DETECTED_NVME_FIRST"
        elif [ -n "$DETECTED_SSD_FIRST" ]; then
            DATA_DISK="$DETECTED_SSD_FIRST"
        fi
    fi

    # Auto-select backup disks: need at least 2 rotational disks for mirror
    if [ -z "$BACKUP_DISKS" ]; then
        if [ -n "$DETECTED_ROT_FIRST" ] && [ -n "$DETECTED_ROT_SECOND" ]; then
            BACKUP_DISKS="${DETECTED_ROT_FIRST},${DETECTED_ROT_SECOND}"
        fi
    fi

    # Show detection results and confirm
    echo "================================================"
    echo "Disk Auto-Detection Results"
    echo "================================================"
    if [ "$DETECTED_NVME_COUNT" -gt 0 ]; then
        echo "  NVMe (unused):       $DETECTED_NVME_LIST"
    fi
    if [ "$DETECTED_SSD_COUNT" -gt 0 ]; then
        echo "  SSD (unused):        $DETECTED_SSD_LIST"
    fi
    if [ "$DETECTED_ROTATIONAL_COUNT" -gt 0 ]; then
        echo "  HDD (unused):        $DETECTED_ROTATIONAL_LIST"
    fi
    echo ""
    echo "  Planned layout:"
    if [ -n "$DATA_DISK" ]; then
        _size=$(lsblk -d -n -o SIZE "/dev/$DATA_DISK" 2>/dev/null | tr -d ' ')
        echo "    Data pool:    /dev/$DATA_DISK ($_size) — ZFS for containers"
    else
        echo "    Data pool:    file-backed (50GB fallback)"
    fi
    if [ -n "$BACKUP_DISKS" ]; then
        IFS=',' read -ra _BD <<< "$BACKUP_DISKS"
        _size1=$(lsblk -d -n -o SIZE "/dev/${_BD[0]}" 2>/dev/null | tr -d ' ')
        echo "    Backup pool:  /dev/${_BD[0]} + /dev/${_BD[1]} ($_size1 each) — ZFS mirror"
    else
        echo "    Backup pool:  (none — no matching HDD pair found)"
    fi
    echo ""

    if [ "$AUTO_YES" = false ]; then
        read -rp "  Proceed with this layout? [y/N] " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "Aborted. Use --data-disk and --backup-disks to specify manually."
            exit 0
        fi
    fi
fi

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
echo "  Data disk:       ${DATA_DISK:-(file-backed 50GB)}"
echo "  Backup disks:    ${BACKUP_DISKS:-(none)}"
echo ""

# ============================================================
# 1. System update & essentials
# ============================================================
echo "==> [1/8] Updating system packages..."

# Disable apt auto-upgrade timers — manual patching only.
# GPU peers run long-lived ML workloads; surprise package upgrades that
# restart docker / nvidia services would kill running training jobs.
# Re-enable with: systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget git vim htop jq net-tools bridge-utils \
    ca-certificates gnupg lsb-release software-properties-common

# ============================================================
# 2. NVIDIA Driver
# ============================================================
echo "==> [2/8] Installing NVIDIA driver ${NVIDIA_DRIVER_VERSION}..."

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
echo "==> [3/8] Installing NVIDIA Container Toolkit..."

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
echo "==> [4/8] Installing Incus from Zabbly repository..."

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
echo "==> [5/8] Setting up ZFS and initializing Incus..."

if ! command -v zpool &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y zfsutils-linux
    modprobe zfs
    echo "  ZFS installed"
fi

if [ ! -f /var/lib/incus/.initialized ]; then
    # --- Main storage pool (incus-local) ---
    if ! zpool list incus-local &>/dev/null; then
        if [ -n "$DATA_DISK" ]; then
            # Use dedicated NVMe disk for container storage
            DISK_PATH="/dev/${DATA_DISK}"
            if [ ! -b "$DISK_PATH" ]; then
                echo "ERROR: Data disk $DISK_PATH not found"
                exit 1
            fi
            # Safety check: refuse if disk has partitions (likely in use)
            if lsblk -n -o TYPE "$DISK_PATH" | grep -q part; then
                echo "ERROR: $DISK_PATH has existing partitions. Wipe it first if you're sure."
                exit 1
            fi
            zpool create \
                -o ashift=12 \
                -O compression=lz4 \
                -O atime=off \
                -O xattr=sa \
                -O recordsize=128k \
                -m /var/lib/incus/storage \
                incus-local "$DISK_PATH"
            echo "  ZFS pool created on $DISK_PATH ($(lsblk -n -o SIZE "$DISK_PATH" | head -1))"
        else
            # Fallback: file-backed pool
            mkdir -p /var/lib/incus/disks
            truncate -s 50G /var/lib/incus/disks/incus.img
            zpool create \
                -o ashift=12 \
                -O compression=lz4 \
                -O atime=off \
                -O xattr=sa \
                -m /var/lib/incus/storage \
                incus-local /var/lib/incus/disks/incus.img
            echo "  ZFS pool created (file-backed, 50GB)"
        fi
        zfs create incus-local/containers
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

# --- Backup pool (incus-backup) — ZFS mirror on HDDs ---
if [ -n "$BACKUP_DISKS" ]; then
    if ! zpool list incus-backup &>/dev/null; then
        echo "  Setting up backup pool (ZFS mirror)..."
        IFS=',' read -ra BDISKS <<< "$BACKUP_DISKS"
        if [ ${#BDISKS[@]} -ne 2 ]; then
            echo "ERROR: --backup-disks requires exactly 2 disks (e.g., sda,sdb)"
            exit 1
        fi
        DISK1="/dev/${BDISKS[0]}"
        DISK2="/dev/${BDISKS[1]}"
        for d in "$DISK1" "$DISK2"; do
            if [ ! -b "$d" ]; then
                echo "ERROR: Backup disk $d not found"
                exit 1
            fi
            if lsblk -n -o TYPE "$d" | grep -q part; then
                echo "ERROR: $d has existing partitions. Wipe it first if you're sure."
                exit 1
            fi
        done
        zpool create \
            -o ashift=12 \
            -O compression=lz4 \
            -O atime=off \
            incus-backup mirror "$DISK1" "$DISK2"
        zfs create incus-backup/snapshots
        echo "  Backup pool created: mirror of $DISK1 + $DISK2"
    else
        echo "  Backup pool already exists"
    fi
fi

# ============================================================
# 6. Kernel modules & sysctl
# ============================================================
echo "==> [6/8] Loading kernel modules and configuring sysctl..."

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
# 7. ZFS backup script
# ============================================================
echo "==> [7/8] Installing ZFS backup script..."

BACKUP_SCRIPT="/usr/local/bin/containarium-zfs-backup"
cat > "$BACKUP_SCRIPT" <<'BACKUPEOF'
#!/bin/bash
#
# Containarium ZFS Backup — snapshots incus-local and replicates to incus-backup
#
# Usage:
#   containarium-zfs-backup              # run backup
#   containarium-zfs-backup --list       # list snapshots
#   containarium-zfs-backup --prune 7    # keep only last N snapshots per dataset
#
# Note: pipefail is intentionally NOT set. We want replication failures to be
# non-fatal so that snapshot creation and pruning still happen.
set -uo pipefail

MAIN_POOL="incus-local"
BACKUP_POOL="incus-backup/snapshots"
SNAP_PREFIX="backup"
KEEP_COUNT="${CONTAINARIUM_BACKUP_KEEP:-7}"

# prune_snapshots keeps the N most recent backup snapshots PER dataset.
# Listing all snapshots in the pool sorted globally would prune wrong:
# 7 containers × 25 daily snapshots → "keep newest 7 globally" wipes
# everything except today's backups across all containers.
prune_snapshots() {
    local pool="$1"
    local keep="$2"

    # Get unique datasets that have backup snapshots
    local datasets
    datasets=$(zfs list -t snapshot -r "$pool" -o name -H 2>/dev/null \
        | grep "@${SNAP_PREFIX}-" \
        | sed 's/@.*//' \
        | sort -u)

    while IFS= read -r ds; do
        [ -z "$ds" ] && continue
        # List this dataset's backup snapshots, newest first
        local snaps
        snaps=$(zfs list -t snapshot -o name -H -S creation "$ds" 2>/dev/null \
            | grep "@${SNAP_PREFIX}-" || true)
        local count=0
        while IFS= read -r snap; do
            [ -z "$snap" ] && continue
            count=$((count + 1))
            if [ "$count" -gt "$keep" ]; then
                if zfs destroy "$snap" 2>/dev/null; then
                    echo "  Destroyed $snap"
                else
                    echo "  Failed to destroy $snap (held or has clones, skipping)"
                fi
            fi
        done <<< "$snaps"
    done <<< "$datasets"
}

case "${1:-}" in
    --list)
        echo "=== Main pool snapshots ==="
        zfs list -t snapshot -r "$MAIN_POOL" -o name,creation,used 2>/dev/null || echo "  (none)"
        echo ""
        echo "=== Backup pool snapshots ==="
        zfs list -t snapshot -r "$BACKUP_POOL" -o name,creation,used 2>/dev/null || echo "  (none)"
        exit 0
        ;;
    --prune)
        KEEP_COUNT="${2:-$KEEP_COUNT}"
        echo "Pruning snapshots, keeping last $KEEP_COUNT per dataset..."
        prune_snapshots "$MAIN_POOL" "$KEEP_COUNT"
        if zpool list incus-backup &>/dev/null; then
            prune_snapshots "$BACKUP_POOL" "$KEEP_COUNT"
        fi
        echo "Done."
        exit 0
        ;;
esac

# Check pools exist
if ! zpool list "$MAIN_POOL" &>/dev/null; then
    echo "ERROR: Main pool $MAIN_POOL not found"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SNAP_NAME="${SNAP_PREFIX}-${TIMESTAMP}"

# Always prune at end, even if replication fails
trap 'echo "==> Pruning old snapshots (keeping last $KEEP_COUNT per dataset)..."; prune_snapshots "$MAIN_POOL" "$KEEP_COUNT"; if zpool list incus-backup &>/dev/null; then prune_snapshots "$BACKUP_POOL" "$KEEP_COUNT"; fi; echo "==> Backup complete."' EXIT

echo "==> Creating snapshot ${MAIN_POOL}@${SNAP_NAME}..."
if ! zfs snapshot -r "${MAIN_POOL}@${SNAP_NAME}"; then
    echo "ERROR: Snapshot creation failed"
    exit 1
fi

if zpool list incus-backup &>/dev/null; then
    echo "==> Replicating to backup pool..."

    # Find the previous snapshot for incremental send
    PREV_SNAP=$(zfs list -t snapshot -r "$MAIN_POOL" -o name -H -S creation 2>/dev/null \
        | grep "@${SNAP_PREFIX}-" \
        | grep -v "@${SNAP_NAME}" \
        | head -1 || true)

    REPLICATION_OK=false

    if [ -n "$PREV_SNAP" ]; then
        PREV_TAG="${PREV_SNAP#*@}"
        if zfs list "${BACKUP_POOL}/${MAIN_POOL}@${PREV_TAG}" &>/dev/null 2>&1; then
            # Incremental send — try first
            echo "  Incremental send from @${PREV_TAG} to @${SNAP_NAME}"
            if zfs send -R -i "${MAIN_POOL}@${PREV_TAG}" "${MAIN_POOL}@${SNAP_NAME}" \
                | zfs receive -F "${BACKUP_POOL}/${MAIN_POOL}" 2>&1; then
                REPLICATION_OK=true
            else
                # Common failure: backup pool's per-dataset snapshot lineage
                # diverged from main pool (e.g. a previous receive failed
                # partway, leaving some datasets out of sync). Recover by
                # rolling back the backup pool to the last shared snapshot.
                echo "  Incremental failed — attempting to repair divergent backup lineage"
                # Find datasets where backup lacks the previous snapshot and
                # roll back to the latest shared one. Easier: destroy backup
                # and do full re-send. This is heavy but reliable.
                echo "  Falling back to full re-send (this will overwrite backup)"
                if zfs send -R "${MAIN_POOL}@${SNAP_NAME}" \
                    | zfs receive -F "${BACKUP_POOL}/${MAIN_POOL}" 2>&1; then
                    REPLICATION_OK=true
                fi
            fi
        else
            # Previous snapshot not on backup — full send
            echo "  Full send (previous snapshot not found on backup)"
            if zfs send -R "${MAIN_POOL}@${SNAP_NAME}" \
                | zfs receive -F "${BACKUP_POOL}/${MAIN_POOL}" 2>&1; then
                REPLICATION_OK=true
            fi
        fi
    else
        # First backup — full send
        echo "  Full send (first backup)"
        if zfs send -R "${MAIN_POOL}@${SNAP_NAME}" \
            | zfs receive -F "${BACKUP_POOL}/${MAIN_POOL}" 2>&1; then
            REPLICATION_OK=true
        fi
    fi

    if $REPLICATION_OK; then
        echo "  Backup replicated to ${BACKUP_POOL}/${MAIN_POOL}@${SNAP_NAME}"
    else
        echo "  WARNING: Replication failed — local snapshot kept, but backup pool is out of date"
    fi
else
    echo "  Backup pool not available — snapshot only (no replication)"
fi

# Note: prune runs via the EXIT trap above, so it executes even if we exit early
BACKUPEOF
chmod +x "$BACKUP_SCRIPT"
echo "  Installed $BACKUP_SCRIPT"

# Install daily cron job if backup pool exists
if zpool list incus-backup &>/dev/null 2>&1; then
    cat > /etc/cron.d/containarium-zfs-backup <<CRONEOF
# Daily ZFS backup at 3am
0 3 * * * root /usr/local/bin/containarium-zfs-backup >> /var/log/containarium-zfs-backup.log 2>&1
CRONEOF
    echo "  Daily backup cron installed (3am)"
fi

# ============================================================
# 8. Verify GPU + Incus integration
# ============================================================
echo "==> [8/8] Verifying setup..."

echo ""
echo "  Incus:        $(incus --version)"
echo "  ZFS pools:"
zpool list -H -o name,size 2>/dev/null | while read -r name size; do
    echo "    $name: $size"
done

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
