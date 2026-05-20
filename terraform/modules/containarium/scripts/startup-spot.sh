#!/bin/bash
#
# Containarium GCE Startup Script — Spot VM
# Runs on every boot (GCE metadata startup-script behavior).
#
# On RESTART (boot disk preserved): fast-path — just ensure services are running.
# On FIRST BOOT (fresh install): full setup — install packages, configure everything.
#

set -euo pipefail

# Logging
exec 1> >(logger -s -t containarium-startup) 2>&1

echo "================================================"
echo "Containarium Setup Starting"
echo "================================================"

# Variables from Terraform template
INCUS_VERSION="${incus_version}"
ADMIN_USERS="${join(",", admin_users)}"
ENABLE_MONITORING="${enable_monitoring}"
USE_PERSISTENT_DISK="${use_persistent_disk}"
FAIL2BAN_WHITELIST="${fail2ban_whitelist_cidr}"
JWT_SECRET="${jwt_secret}"
# When non-empty, the data-disk ZFS pool is created with native
# encryption=on, keyformat=raw, keylocation=file://$ZFS_ENCRYPTION_KEYFILE.
# The keyfile is generated on first boot if missing (32 random bytes,
# chmod 0400). Lost keyfile = lost pool — operators MUST back this up
# off-host. See docs/SECURITY-ENCRYPTION-AT-REST.md for the full
# custody story.
ZFS_ENCRYPTION_KEYFILE="${zfs_encryption_keyfile}"

# ==========================================================================
# FAST PATH: If this is a restart (not first boot), skip software install.
# The sentinel restarts the stopped VM — boot disk is preserved, everything
# is already installed. Just ensure services are running and exit.
# ==========================================================================
if [ -f /opt/containarium/.setup_complete ]; then
    echo "==> RESTART detected (setup_complete marker exists), using fast path"
    date > /opt/containarium/.last_restart_timestamp

    # Ensure critical services are running
    systemctl start incus 2>/dev/null || true
    systemctl start containarium 2>/dev/null || true
    systemctl start fail2ban 2>/dev/null || true

    # Wait for Incus to be ready, then start any stopped containers
    sleep 3
    for container in $(incus list --format csv -c n 2>/dev/null); do
        if [ "$(incus list "$container" --format csv -c s 2>/dev/null)" = "STOPPED" ]; then
            incus start "$container" 2>/dev/null && echo "  Started $container" || true
        fi
    done

    # Sync jump server accounts (containers may have been running before preemption)
    if [ -f /usr/local/bin/containarium ] && incus list --format=csv --columns=n 2>/dev/null | grep -q .; then
        systemctl stop google-guest-agent 2>/dev/null || true
        /usr/local/bin/containarium sync-accounts --verbose 2>/dev/null || true
        systemctl start google-guest-agent 2>/dev/null || true
    fi

    echo "==> Fast path complete — services running"
    exit 0
fi

# ==========================================================================
# FULL INSTALL: First boot — install everything from scratch.
# ==========================================================================
echo "==> First boot detected, running full setup"

# System info
echo "System: $(uname -a)"
echo "Ubuntu: $(lsb_release -d | cut -f2)"

# Disable apt auto-upgrade timers — manual patching only.
# Auto-upgrades can interrupt long-running container workloads at unpredictable
# times and stack memory pressure on top of normal usage.
# Re-enable with: systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

# Update system
echo "==> Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install essential packages
echo "==> Installing essential packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    jq \
    net-tools \
    bridge-utils \
    ca-certificates \
    gnupg \
    lsb-release

# Install and configure fail2ban for SSH protection
echo "==> Installing fail2ban for intrusion prevention..."
DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban

# Configure fail2ban for SSH
echo "==> Configuring fail2ban..."
cat > /etc/fail2ban/jail.d/sshd.conf <<'EOF'
# Containarium SSH Protection
# Automatically blocks IPs after failed login attempts
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = 3600
banaction = iptables-multiport
EOF

# Whitelist internal IPs (parameterized for different network environments)
# 10.128.0.0/9 covers GCE default network; 10.0.0.0/8 covers VPC
if [ -n "$FAIL2BAN_WHITELIST" ]; then
    cat > /etc/fail2ban/jail.d/containarium-whitelist.conf <<WEOF
# Whitelist internal networks — sentinel sshpiper pre-authenticates SSH
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 $FAIL2BAN_WHITELIST
WEOF
fi

# Start and enable fail2ban
systemctl enable fail2ban
systemctl start fail2ban

echo "✓ fail2ban configured and started"
echo "  - Max retries: 3 failed attempts"
echo "  - Find time: 10 minutes"
echo "  - Ban time: 1 hour"
echo "  - Whitelisted: internal networks ($FAIL2BAN_WHITELIST)"

# Setup persistent disk if enabled
if [ "$USE_PERSISTENT_DISK" = "true" ]; then
    echo "==> Setting up persistent disk for container data..."

    # Wait for disk to be available
    DISK_DEVICE="/dev/disk/by-id/google-incus-data"
    MOUNT_POINT="/mnt/incus-data"

    # Wait up to 30 seconds for disk to appear
    for i in {1..30}; do
        if [ -e "$DISK_DEVICE" ]; then
            echo "✓ Persistent disk found: $DISK_DEVICE"
            break
        fi
        echo "Waiting for persistent disk... ($i/30)"
        sleep 1
    done

    if [ ! -e "$DISK_DEVICE" ]; then
        echo "⚠ WARNING: Persistent disk not found, using local storage"
        USE_PERSISTENT_DISK="false"
    else
        # NOTE: We will use ZFS directly on this disk (not ext4)
        # The disk will be formatted as ZFS later in the setup process
        # Just create the mount point for now
        mkdir -p "$MOUNT_POINT"
        echo "✓ Persistent disk ready for ZFS setup"
    fi
fi

# Remove pre-installed Incus (if any) to avoid conflicts with Zabbly repo.
# Ubuntu 24.04 ships incus-tools 6.0.0 in the default repos which conflicts
# with Zabbly's incus-base 6.19+. The previous detection regex
# (`^ii.*incus `) only matched the exact `incus` binary, missing
# default-installed packages like incus-tools / incus-client. Widened
# to `^ii  incus` so any incus-* package triggers the cleanup.
echo "==> Checking for pre-installed Incus..."
if dpkg -l | grep -qE "^ii  incus" && ! grep -q zabbly /etc/apt/sources.list.d/*.list 2>/dev/null; then
    echo "Removing pre-installed Incus packages (will reinstall from Zabbly)..."
    DEBIAN_FRONTEND=noninteractive apt-get remove -y incus incus-base incus-client incus-tools 2>/dev/null || true
    echo "✓ Pre-installed Incus removed"
fi

# Install Incus 6.19+ (required for Docker build support)
echo "==> Installing Incus 6.19+ from Zabbly repository..."
# Ubuntu 24.04 default repos only have Incus 6.0.0, which has AppArmor bug (CVE-2025-52881)
# that breaks Docker builds in unprivileged containers. We need 6.19+ from Zabbly.

# Add Zabbly Incus stable repository
if [ ! -f /etc/apt/sources.list.d/zabbly-incus-stable.list ]; then
    echo "Adding Zabbly Incus repository..."
    curl -fsSL https://pkgs.zabbly.com/key.asc | gpg --dearmor -o /usr/share/keyrings/zabbly-incus.gpg
    echo 'deb [signed-by=/usr/share/keyrings/zabbly-incus.gpg] https://pkgs.zabbly.com/incus/stable noble main' | tee /etc/apt/sources.list.d/zabbly-incus-stable.list
    apt-get update
    echo "✓ Zabbly repository added"
fi

# Install or upgrade Incus.
#
# Only request `incus` itself. Older versions of this script also asked
# for `incus-tools` and `incus-client`, but those were the Ubuntu-style
# names — the Zabbly 6.19+ repo subsumes them into `incus-base` and
# the meta-package `incus`. Asking for `incus-tools` by name forces
# apt to pull Ubuntu's 6.0.0-1ubuntu0.3 from the default repo, which
# Breaks Zabbly's incus-base 6.19+ and produces:
#   incus-base : Breaks: incus-tools but 6.0.0-1ubuntu0.3 is to be installed
#   E: Unable to correct problems, you have held broken packages.
# Just ask for `incus`; apt resolves the deps through Zabbly cleanly.
if [ -n "$INCUS_VERSION" ]; then
    echo "Installing Incus version: $INCUS_VERSION"
    DEBIAN_FRONTEND=noninteractive apt-get install -y incus="$INCUS_VERSION"
else
    echo "Installing latest stable Incus (6.19+)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y incus
fi

# Verify Incus installation and version
INSTALLED_VERSION=$(incus --version)
echo "✓ Incus $INSTALLED_VERSION installed successfully"

# Verify minimum version requirement (6.19+)
MAJOR=$(echo "$INSTALLED_VERSION" | cut -d. -f1)
MINOR=$(echo "$INSTALLED_VERSION" | cut -d. -f2)
if [ "$MAJOR" -lt 6 ] || ([ "$MAJOR" -eq 6 ] && [ "$MINOR" -lt 19 ]); then
    echo "⚠ WARNING: Incus $INSTALLED_VERSION is below 6.19"
    echo "  Docker builds may fail due to AppArmor bug (CVE-2025-52881)"
    echo "  Please upgrade to Incus 6.19 or later"
fi

# Setup ZFS for quota enforcement (if using persistent disk)
if [ "$USE_PERSISTENT_DISK" = "true" ] && [ -d "/mnt/incus-data" ]; then
    echo "==> Setting up ZFS for disk quota enforcement..."

    # Install ZFS
    if ! command -v zpool &> /dev/null; then
        echo "Installing ZFS utilities..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y zfsutils-linux
        # Load ZFS kernel module
        modprobe zfs
        echo "✓ ZFS installed"
    else
        echo "✓ ZFS already installed"
    fi

    # Create or import ZFS pool
    DISK_DEVICE="/dev/disk/by-id/google-incus-data"
    ZFS_POOL="incus-pool"

    # ZFS native encryption is opt-in via ZFS_ENCRYPTION_KEYFILE.
    # The keyfile lives on the boot disk (so an attacker who exfils
    # only the data disk can't decrypt); GCP CMEK on the boot disk
    # still applies independently. Defense in depth, not a silver
    # bullet — see docs/SECURITY-ENCRYPTION-AT-REST.md.
    ENCRYPT_OPTS=""
    if [ -n "$ZFS_ENCRYPTION_KEYFILE" ]; then
        mkdir -p "$(dirname "$ZFS_ENCRYPTION_KEYFILE")"
        if [ ! -f "$ZFS_ENCRYPTION_KEYFILE" ]; then
            echo "==> Generating ZFS encryption keyfile at $ZFS_ENCRYPTION_KEYFILE"
            dd if=/dev/urandom of="$ZFS_ENCRYPTION_KEYFILE" bs=32 count=1 status=none
            chmod 0400 "$ZFS_ENCRYPTION_KEYFILE"
            echo "==> WARNING: back up $ZFS_ENCRYPTION_KEYFILE off-host. Loss = unrecoverable pool."
        else
            echo "==> Reusing existing ZFS encryption keyfile at $ZFS_ENCRYPTION_KEYFILE"
        fi
        ENCRYPT_OPTS="-O encryption=on -O keyformat=raw -O keylocation=file://$ZFS_ENCRYPTION_KEYFILE"
    fi

    if ! zpool list "$ZFS_POOL" &>/dev/null; then
        echo "Creating ZFS pool on persistent disk..."

        # Check if disk already has a ZFS pool
        if zpool import | grep -q "$ZFS_POOL"; then
            echo "Importing existing ZFS pool..."
            # Use -f to force import (handles cases where pool was last used by different system)
            zpool import -f "$ZFS_POOL"
            # If encryption was enabled at create time, the
            # keyfile-backed key auto-loads via keylocation=file://;
            # explicit load is a no-op but defensive against pools
            # imported from a different ZFS_ENCRYPTION_KEYFILE path.
            if [ -n "$ZFS_ENCRYPTION_KEYFILE" ] && zfs get -H -o value encryption "$ZFS_POOL" 2>/dev/null | grep -qv '^off$'; then
                zfs load-key -L "file://$ZFS_ENCRYPTION_KEYFILE" "$ZFS_POOL" 2>/dev/null || true
            fi
            echo "✓ ZFS pool imported"
        else
            # Create new ZFS pool
            zpool create -f \
                -o ashift=12 \
                -O compression=lz4 \
                -O atime=off \
                -O xattr=sa \
                -O dnodesize=auto \
                $ENCRYPT_OPTS \
                -m /mnt/incus-data/zfs \
                "$ZFS_POOL" "$DISK_DEVICE"

            if [ -n "$ENCRYPT_OPTS" ]; then
                echo "✓ ZFS pool created with compression + native encryption"
            else
                echo "✓ ZFS pool created with compression enabled"
            fi
        fi

        # Create dataset for Incus containers
        if ! zfs list "$ZFS_POOL/containers" &>/dev/null; then
            zfs create "$ZFS_POOL/containers"
            echo "✓ ZFS dataset created for containers"
        fi

        # Set ZFS properties for optimal container performance
        zfs set recordsize=128k "$ZFS_POOL/containers"  # Better for mixed workloads
        zfs set redundant_metadata=most "$ZFS_POOL/containers"

        echo "✓ ZFS optimized for container workloads"
    else
        echo "✓ ZFS pool already exists"
    fi

    # Show ZFS pool status
    zpool status "$ZFS_POOL" | head -10
fi

# Initialize Incus
echo "==> Initializing Incus..."

# Check if ZFS pool already has Incus data (from previous instance)
# This handles spot instance recovery where boot disk is fresh but ZFS has existing data
ZFS_HAS_DATA=false
if [ "$USE_PERSISTENT_DISK" = "true" ] && zfs list incus-pool/containers/containers &>/dev/null; then
    CONTAINER_COUNT=$(zfs list -r -H -o name incus-pool/containers/containers 2>/dev/null | wc -l)
    if [ "$CONTAINER_COUNT" -gt 1 ]; then
        ZFS_HAS_DATA=true
        echo "✓ Found existing Incus data on ZFS pool ($((CONTAINER_COUNT - 1)) containers)"
    fi
fi

if [ "$ZFS_HAS_DATA" = "true" ]; then
    # ==========================================================================
    # RECOVERY MODE: Existing data found on ZFS pool
    # ==========================================================================
    echo "==> Recovering Incus from existing ZFS data..."

    # Ensure Incus service is started
    systemctl start incus || true
    sleep 3

    # CRITICAL: Create network FIRST before running incus admin recover
    # The recover command requires the network to exist for container recovery
    if ! incus network show incusbr0 &>/dev/null; then
        echo "Creating network incusbr0 (required for recovery)..."
        incus network create incusbr0 \
            ipv4.address=10.0.3.1/24 \
            ipv4.nat=true \
            ipv6.address=none
        echo "✓ Network incusbr0 created"
    fi

    # Now recover storage pool and containers
    if ! incus storage show default &>/dev/null; then
        echo "Recovering ZFS storage pool using incus admin recover..."
        printf "yes\ndefault\nzfs\nincus-pool/containers\n\nno\nyes\nyes\n" | incus admin recover || {
            echo "⚠ Recovery command had issues, checking if storage pool exists..."
        }
        sleep 2
    fi

    # Verify storage pool exists now
    if incus storage show default &>/dev/null; then
        echo "✓ Storage pool 'default' recovered"
    else
        echo "⚠ Storage pool recovery may have failed, please check manually"
    fi

    # Add eth0 device to default profile if missing
    if ! incus profile device show default 2>/dev/null | grep -q "eth0:"; then
        echo "Adding eth0 device to default profile..."
        incus profile device add default eth0 nic network=incusbr0 name=eth0 || true
    fi

    # Start all recovered containers
    echo "Starting recovered containers..."
    for container in $(incus list --format csv -c n 2>/dev/null); do
        if [ "$(incus list "$container" --format csv -c s 2>/dev/null)" = "STOPPED" ]; then
            incus start "$container" 2>/dev/null && echo "  Started $container" || echo "  Failed to start $container"
        fi
    done

    echo "✓ Incus recovered from existing ZFS data"
    touch /var/lib/incus/.initialized

elif [ ! -f /var/lib/incus/.initialized ]; then
    # ==========================================================================
    # FRESH INSTALL: No existing data, initialize new Incus instance
    # ==========================================================================
    # Initialize with ZFS storage if using persistent disk
    if [ "$USE_PERSISTENT_DISK" = "true" ] && zpool list incus-pool &>/dev/null; then
        # Clean up any stale incus-pool/containers dataset from a previous
        # failed init. Without this, `incus admin init --preseed` fails:
        #   Error: Failed to create storage pool "default": Provided ZFS pool
        #   (or dataset) isn't empty
        # when a prior install crashed after creating the dataset but before
        # finishing init (e.g., apt failure on a different package). We're
        # safe to destroy here because the recovery branch above already ran
        # — if real container data existed, ZFS_HAS_DATA would be true and
        # we'd be in that branch, not here.
        if zfs list incus-pool/containers &>/dev/null; then
            echo "==> Found stale incus-pool/containers from a failed prior init; cleaning up..."
            zfs destroy -r incus-pool/containers || {
                echo "⚠ Could not destroy stale dataset; init will likely fail"
            }
        fi

        # Initialize with ZFS storage pool
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
    source: incus-pool/containers
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
      size: 50GB
cluster: null
EOF
        echo "✓ Incus initialized with ZFS storage (quotas ENFORCED)"
        echo "  - Default container quota: 50GB"
        echo "  - Compression: lz4 (saves ~30% disk space)"
        echo "  - Snapshots: instant copy-on-write"
    else
        # Standard initialization (dir driver, no quotas)
        incus admin init --auto
        echo "✓ Incus initialized with local storage"
        echo "  ⚠ WARNING: Disk quotas NOT enforced with 'dir' driver"
    fi

    touch /var/lib/incus/.initialized
else
    echo "✓ Incus already initialized"
fi

# Use ZFS refquota instead of quota for container disk limits.
# refquota counts ONLY live data; quota counts data + snapshots.
# Without this, daily backup snapshots eat into the container's visible
# disk size (user asks for 500GB, sees 150GB after a heavy delete).
# Idempotent; no-op for non-ZFS pools.
incus storage set default volume.zfs.use_refquota true 2>/dev/null || true

# Configure Incus networking
echo "==> Configuring Incus network..."
# Ensure bridge is created with proper subnet
if ! incus network show incusbr0 &> /dev/null; then
    incus network create incusbr0 \
        ipv4.address=10.0.3.1/24 \
        ipv4.nat=true \
        ipv6.address=none
    echo "✓ Created incusbr0 bridge (10.0.3.0/24)"
else
    echo "✓ incusbr0 bridge already exists"
fi

# Load kernel modules for Docker support in containers
echo "==> Loading kernel modules for Docker support..."
MODULES=(
    "overlay"
    "br_netfilter"
    "nf_nat"
    "xt_conntrack"
    "ip_tables"
    "iptable_nat"
)

for mod in "$${MODULES[@]}"; do
    if ! lsmod | grep -q "^$mod "; then
        modprobe "$mod"
        echo "$mod" >> /etc/modules-load.d/containarium.conf
        echo "✓ Loaded $mod"
    fi
done

# Configure sysctl for containers and Docker
echo "==> Configuring sysctl for containers..."
cat > /etc/sysctl.d/99-containarium.conf <<EOF
# Enable IP forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Bridge netfilter
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1

# Increase inotify limits (for many containers)
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 524288
EOF

sysctl --system
echo "✓ Sysctl configured"

# Configure SSH for security
echo "==> Hardening SSH configuration..."
cat > /etc/ssh/sshd_config.d/containarium.conf <<EOF
# Containarium SSH hardening
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20s
EOF

systemctl restart ssh
echo "✓ SSH hardened"

# Set up admin users (from Terraform variable)
echo "==> Setting up admin users..."
IFS=',' read -ra USERS <<< "$ADMIN_USERS"
for username in "$${USERS[@]}"; do
    if ! id "$username" &>/dev/null; then
        # Create user without creating a new primary group (use existing or create with different name)
        useradd -m -s /bin/bash -N -G sudo "$username" || useradd -m -s /bin/bash -g users -G sudo "$username"
        echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$username"
        chmod 0440 /etc/sudoers.d/"$username"
        echo "✓ Created user: $username"
    else
        echo "✓ User already exists: $username"
        # Ensure user is in sudo group
        usermod -aG sudo "$username" 2>/dev/null || true
    fi
done

# Install monitoring agents (if enabled)
if [ "$ENABLE_MONITORING" = "true" ]; then
    echo "==> Installing Google Cloud monitoring agent..."
    curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
    bash add-google-cloud-ops-agent-repo.sh --also-install
    rm add-google-cloud-ops-agent-repo.sh
    echo "✓ Monitoring agent installed"
fi

# Create containarium directory structure
echo "==> Creating Containarium directory structure..."
mkdir -p /opt/containarium/{bin,config,logs}
chmod 755 /opt/containarium

# Install Containarium daemon
echo "==> Installing Containarium daemon..."
CONTAINARIUM_VERSION="${containarium_version}"
CONTAINARIUM_BINARY_URL="${containarium_binary_url}"
SENTINEL_BINARY_URL="${sentinel_binary_url}"

BINARY_INSTALLED=false

# Try sentinel binary server first (internal network, fast)
if [ -n "$SENTINEL_BINARY_URL" ] && [ "$BINARY_INSTALLED" = "false" ]; then
    echo "Downloading from sentinel: $SENTINEL_BINARY_URL"
    # Retry up to 10 times (sentinel may still be booting)
    for i in {1..10}; do
        if curl -fsSL --connect-timeout 5 "$SENTINEL_BINARY_URL" -o /usr/local/bin/containarium; then
            chmod +x /usr/local/bin/containarium
            echo "✓ Containarium downloaded from sentinel"
            BINARY_INSTALLED=true
            break
        fi
        echo "  Sentinel not ready yet, retrying... ($i/10)"
        sleep 10
    done
fi

# Fallback to explicit URL (e.g., GitHub releases, GCS)
if [ -n "$CONTAINARIUM_BINARY_URL" ] && [ "$BINARY_INSTALLED" = "false" ]; then
    echo "Downloading from: $CONTAINARIUM_BINARY_URL"
    curl -fsSL "$CONTAINARIUM_BINARY_URL" -o /usr/local/bin/containarium
    chmod +x /usr/local/bin/containarium
    echo "✓ Containarium daemon downloaded"
    BINARY_INSTALLED=true
fi

if [ "$BINARY_INSTALLED" = "false" ]; then
    echo "⚠ No Containarium binary source available, daemon not installed"
    echo "  You can manually install it later by copying the binary to /usr/local/bin/containarium"
fi

# Verify installation
if [ -f /usr/local/bin/containarium ]; then
    /usr/local/bin/containarium version || echo "Containarium binary installed (version command not available)"
    echo "✓ Containarium daemon ready"
fi

# Create welcome message
cat > /etc/motd <<'EOF'
   ____            _        _                 _
  / ___|___  _ __ | |_ __ _(_)_ __   __ _ _ __(_)_   _ _ __ ___
 | |   / _ \| '_ \| __/ _` | | '_ \ / _` | '__| | | | | '_ ` _ \
 | |__| (_) | | | | || (_| | | | | | (_| | |  | | |_| | | | | | |
  \____\___/|_| |_|\__\__,_|_|_| |_|\__,_|_|  |_|\__,_|_| |_| |_|

  SSH Jump Server + LXC Container Platform

  Documentation: https://github.com/footprintai/Containarium

  Quick Start:
    - List containers:     incus list
    - Create container:    containarium create <username>
    - View daemon status:  systemctl status containarium
    - View logs:           journalctl -u containarium -f

  Daemon API:   0.0.0.0:50051 (gRPC)
  Network:      10.0.3.0/24 (incusbr0)

EOF

echo "✓ Welcome message created"

# Generate TLS certificates for mTLS
echo "==> Generating mTLS certificates..."
CERTS_DIR="/etc/containarium/certs"
mkdir -p "$CERTS_DIR"

if [ -f /usr/local/bin/containarium ]; then
    # Generate certificates if they don't exist
    if [ ! -f "$CERTS_DIR/ca.crt" ]; then
        /usr/local/bin/containarium cert generate \
            --org "Containarium" \
            --dns "containarium-daemon,localhost" \
            --output "$CERTS_DIR" \
            2>&1 | logger -t containarium-setup

        if [ -f "$CERTS_DIR/ca.crt" ]; then
            echo "✓ mTLS certificates generated in $CERTS_DIR"
            chmod 644 "$CERTS_DIR"/*.crt
            chmod 600 "$CERTS_DIR"/*.key
        else
            echo "⚠ Failed to generate certificates, daemon will run in insecure mode"
        fi
    else
        echo "✓ Certificates already exist in $CERTS_DIR"
    fi
fi

# Configure JWT secret for REST API
echo "==> Configuring JWT secret for REST API..."
mkdir -p /etc/containarium
chmod 0700 /etc/containarium
if [ -n "$JWT_SECRET" ]; then
    echo "$JWT_SECRET" > /etc/containarium/jwt.secret
    chmod 600 /etc/containarium/jwt.secret
    echo "✓ JWT secret configured from Terraform variable"
elif [ ! -f /etc/containarium/jwt.secret ]; then
    # Generate a random JWT secret so the daemon can start
    openssl rand -base64 32 > /etc/containarium/jwt.secret
    chmod 600 /etc/containarium/jwt.secret
    echo "✓ JWT secret auto-generated"
else
    echo "✓ JWT secret already exists"
fi

# Phase 0.4/0.5: sentinel↔daemon shared HMAC secret. Lives in an
# EnvironmentFile loaded by the daemon's systemd unit (drop-in
# written below). Mode 0600 root-only so the value doesn't leak via
# `ps`, container introspection, or `systemctl cat`. The matching
# value is written on the sentinel by startup-sentinel.sh; both
# come from the same terraform variable so they always agree.
SENTINEL_AUTH_SECRET="${sentinel_auth_secret}"
if [ -n "$SENTINEL_AUTH_SECRET" ]; then
    umask 077
    cat > /etc/containarium/env.secrets <<EOF
CONTAINARIUM_SENTINEL_AUTH_SECRET=$SENTINEL_AUTH_SECRET
EOF
    chmod 0600 /etc/containarium/env.secrets
    echo "✓ /etc/containarium/env.secrets written (Phase 0.4/0.6 enabled)"
else
    rm -f /etc/containarium/env.secrets
    echo "⚠ sentinel_auth_secret terraform var is empty — daemon will accept unsigned /sentinel/peers responses with a warning (audit C-CRIT-2 still open)"
fi

# Phase 0.5: tell the daemon where the sentinel's HTTPS binary
# server lives so peer-to-peer traffic uses TLS pinned to the
# sentinel-issued CA. When enable_peer_mtls=true the sentinel
# auto-generates the CA on first boot and exposes HTTPS on the
# port below (8889 by default). Daemons without this var set
# stay on plain HTTP — backwards-compatible rollout.
%{ if enable_peer_mtls && sentinel_internal_ip != "" ~}
cat >> /etc/containarium/env.secrets <<EOF
CONTAINARIUM_SENTINEL_URL=https://${sentinel_internal_ip}:8889
EOF
echo "✓ daemon will use HTTPS sentinel URL (Phase 0.5 peer mTLS)"
%{ endif ~}

# Install containarium-shell wrapper so sshd accepts logins for container
# users. The daemon creates host accounts with shell=containarium-shell;
# without this file present, sshd rejects every login with
# "User X not allowed because shell /usr/local/bin/containarium-shell does
# not exist". Mirrors scripts/setup-ssh-container-proxy.sh; keep in sync.
echo "==> Installing containarium-shell wrapper..."
cat > /usr/local/bin/containarium-shell <<'SHELLEOF'
#!/bin/bash
# containarium-shell: Proxy SSH sessions into Incus containers

USERNAME="$(whoami)"
CONTAINER="$${USERNAME}-container"

if ! sudo incus info "$CONTAINER" &>/dev/null; then
    echo "Error: Container $CONTAINER not found" >&2
    exit 1
fi

STATE=$(sudo incus info "$CONTAINER" 2>/dev/null | grep "^Status:" | awk '{print $2}')
if [ "$STATE" != "RUNNING" ]; then
    echo "Error: Container $CONTAINER is not running (status: $STATE)" >&2
    exit 1
fi

# Three invocation modes: SSH_ORIGINAL_COMMAND set, -c <cmd> arg, or
# interactive.
COMMAND="$${SSH_ORIGINAL_COMMAND}"
if [ -z "$COMMAND" ] && [ "$1" = "-c" ]; then
    COMMAND="$2"
fi

if [ -n "$COMMAND" ]; then
    exec sudo incus exec "$CONTAINER" --mode non-interactive -- su - "$USERNAME" -c "$COMMAND"
fi

exec sudo incus exec "$CONTAINER" -t -- su -l "$USERNAME"
SHELLEOF
chmod 755 /usr/local/bin/containarium-shell

# /etc/shells gate: sshd refuses any user whose shell is not listed here.
if ! grep -qxF /usr/local/bin/containarium-shell /etc/shells 2>/dev/null; then
    echo /usr/local/bin/containarium-shell >> /etc/shells
fi

# Sudoers for passwordless `incus exec/info`.
cat > /etc/sudoers.d/containarium-incus <<'SUDOEOF'
ALL ALL=(root) NOPASSWD: /usr/bin/incus exec *, /usr/bin/incus info *
SUDOEOF
chmod 0440 /etc/sudoers.d/containarium-incus

# Suppress host MOTD for container users (admin users keep theirs).
SSHD_DROPIN=/etc/ssh/sshd_config.d/containarium-motd.conf
if [ -d /etc/ssh/sshd_config.d ]; then
    cat > "$SSHD_DROPIN" <<'SSHDEOF'
Match User *,!ubuntu,!root
    PrintMotd no
    PrintLastLog no
SSHDEOF
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
fi
echo "✓ containarium-shell wrapper installed"

# Install systemd service via the binary's built-in command if available,
# otherwise create the service file directly.
echo "==> Installing Containarium systemd service..."
if [ -f /usr/local/bin/containarium ]; then
    if /usr/local/bin/containarium service install 2>/dev/null; then
        echo "✓ Containarium daemon service installed via built-in command"
    else
        echo "⚠ 'service install' not available, creating service file directly..."
        cat > /etc/systemd/system/containarium.service <<'SVCEOF'
[Unit]
Description=Containarium Container Management Daemon
Documentation=https://github.com/footprintai/Containarium
After=network.target incus.service
Requires=incus.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium daemon --address 0.0.0.0 --rest --http-port 8080 --jwt-secret-file /etc/containarium/jwt.secret
Restart=on-failure
RestartSec=5s
User=root
Group=root

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=/var/lib/incus /etc /home /var/lock /run/lock

StandardOutput=journal
StandardError=journal
SyslogIdentifier=containarium

LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
SVCEOF
        systemctl daemon-reload
        systemctl enable containarium.service
        systemctl start containarium.service
        echo "✓ Containarium daemon service created and started"
    fi

    # ---------------------------------------------------------------
    # Optional override.conf for --app-hosting and/or --proxy-protocol.
    #
    # We can't put these flags in the primary ExecStart written above,
    # because `containarium service install` (the preferred install
    # path, called at the top of this block) generates its own
    # ExecStart and we shouldn't second-guess it. The systemd
    # drop-in pattern (override.conf with `ExecStart=` to clear the
    # parent, then a fresh `ExecStart=...`) is the supported way to
    # extend it without forking the unit file.
    #
    # PROXY v2 trusted CIDRs: rejected by the daemon if any entry is
    # 0.0.0.0/0 (anti-spoofing). Wildcards must be filtered out
    # upstream — the module-level var.proxy_protocol_trusted_cidrs
    # gets validated at apply time too via the daemon's startup logs.
    # ---------------------------------------------------------------
%{ if enable_app_hosting || enable_proxy_protocol ~}
    mkdir -p /etc/systemd/system/containarium.service.d
    cat > /etc/systemd/system/containarium.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/containarium daemon --address 0.0.0.0 --rest --http-port 8080 --jwt-secret-file /etc/containarium/jwt.secret%{ if enable_app_hosting } --app-hosting%{ if base_domain != "" } --base-domain ${base_domain}%{ endif }%{ endif }%{ if enable_proxy_protocol } --proxy-protocol --proxy-protocol-trusted=${join(",", proxy_protocol_trusted_cidrs)}%{ endif }
EOF
    echo "✓ wrote override.conf for app-hosting / proxy-protocol"
    systemctl daemon-reload
    systemctl restart containarium.service
%{ endif ~}

    # Phase 0.4/0.5 secrets drop-in. EnvironmentFile=- prefix tells
    # systemd to silently ignore the file if absent — daemons
    # without the secret yet still boot, just without the security
    # layer. See startup-sentinel.sh for the matching write on the
    # other end.
    mkdir -p /etc/systemd/system/containarium.service.d
    cat > /etc/systemd/system/containarium.service.d/secrets.conf <<'EOF'
[Service]
EnvironmentFile=-/etc/containarium/env.secrets
EOF
    chmod 0644 /etc/systemd/system/containarium.service.d/secrets.conf
    systemctl daemon-reload
    systemctl restart containarium.service
    echo "✓ wrote secrets.conf systemd drop-in"

    # Check status
    sleep 2
    if systemctl is-active --quiet containarium; then
        echo "✓ Containarium daemon is running"
    else
        echo "⚠ Containarium daemon failed to start, check: journalctl -u containarium"
    fi
else
    echo "⚠ Containarium binary not found, service not started"
    echo "  Install binary manually and run: containarium service install"
fi

# Set up logrotate
cat > /etc/logrotate.d/containarium <<'EOF'
/opt/containarium/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 root root
    sharedscripts
}
EOF

echo "✓ Logrotate configured"

# Create info script
cat > /usr/local/bin/containarium-info <<'SCRIPT'
#!/bin/bash
# Display Containarium system information

echo "=== Containarium System Information ==="
echo ""
echo "Host:"
echo "  Hostname: $(hostname)"
echo "  IP: $(hostname -I | awk '{print $1}')"
echo "  OS: $(lsb_release -d | cut -f2)"
echo "  Kernel: $(uname -r)"
echo ""
echo "Incus:"
echo "  Version: $(incus --version)"
echo "  Containers: $(incus list --format csv | wc -l)"
echo "  Running: $(incus list --format csv | grep -c RUNNING || echo 0)"
echo "  Stopped: $(incus list --format csv | grep -c STOPPED || echo 0)"
echo ""
echo "Resources:"
echo "  CPUs: $(nproc)"
echo "  Memory: $(free -h | awk '/^Mem:/ {print $2}')"
echo "  Disk: $(df -h / | awk 'NR==2 {print $2}')"
echo ""
echo "Network:"
echo "  Bridge: incusbr0 (10.0.3.1/24)"
echo ""
SCRIPT

chmod +x /usr/local/bin/containarium-info

# Final system status
echo ""
echo "================================================"
echo "Containarium Setup Complete!"
echo "================================================"
echo ""
incus --version
incus network list
echo ""
echo "Kernel modules loaded:"
lsmod | grep -E "(overlay|br_netfilter|nf_nat)"
echo ""
echo "Jump server is ready for containers!"
echo "Run 'containarium-info' to see system status"
echo ""

# Copy jump server SSH key for ProxyJump support
echo "==> Setting up jump server SSH key for containers..."
for user_dir in /home/*; do
    username=$(basename "$user_dir")
    if [ -d "$user_dir/.ssh" ]; then
        for key_file in "$user_dir/.ssh/id_ed25519.pub" "$user_dir/.ssh/id_rsa.pub" "$user_dir/.ssh/id_ecdsa.pub"; do
            if [ -f "$key_file" ]; then
                mkdir -p /etc/containarium
                cp "$key_file" /etc/containarium/jump_server_key.pub
                chmod 644 /etc/containarium/jump_server_key.pub
                echo "✓ Jump server SSH key copied from $key_file"
                echo "  Containers will automatically support ProxyJump"
                break 2
            fi
        done
    fi
done

# =============================================================================
# CRITICAL: Restore jump server accounts from persisted containers
# =============================================================================
if [ "$USE_PERSISTENT_DISK" = "true" ] && [ -f /usr/local/bin/containarium ]; then
    echo "==> Checking for persisted containers to restore jump server accounts..."

    # Wait for Incus to be fully ready
    for i in {1..30}; do
        if incus list --format=csv 2>/dev/null | head -1 >/dev/null; then
            break
        fi
        echo "Waiting for Incus to be ready... ($i/30)"
        sleep 2
    done

    # Check if there are existing containers (indicating this is a restart)
    if incus list --format=csv --columns=n 2>/dev/null | grep -q .; then
        echo "  Found persisted containers, syncing jump server accounts..."

        # Temporarily stop google-guest-agent to avoid lock conflicts
        systemctl stop google-guest-agent 2>/dev/null || true
        sleep 2

        # Run the sync-accounts command
        if /usr/local/bin/containarium sync-accounts --verbose; then
            echo "✓ Jump server accounts restored successfully"
        else
            echo "⚠ Some accounts may have failed to restore"
            echo "  You can manually run: containarium sync-accounts"
        fi

        # Restart google-guest-agent
        systemctl start google-guest-agent 2>/dev/null || true
    else
        echo "  No persisted containers found, skipping account restoration"
    fi
else
    echo "==> Skipping account restoration (persistent disk not enabled or containarium not installed)"
fi

# Mark setup as complete
touch /opt/containarium/.setup_complete
date > /opt/containarium/.setup_timestamp

exit 0
