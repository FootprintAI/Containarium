#!/bin/bash
#
# Containarium GCE Startup Script
# This script runs once when the GCE instance first boots
# It installs and configures Incus, Docker kernel modules, and sets up the jump server
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

# System info
echo "System: $(uname -a)"
echo "Ubuntu: $(lsb_release -d | cut -f2)"

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

# Start and enable fail2ban
systemctl enable fail2ban
systemctl start fail2ban

echo "✓ fail2ban configured and started"
echo "  - Max retries: 3 failed attempts"
echo "  - Find time: 10 minutes"
echo "  - Ban time: 1 hour"

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

# Install or upgrade Incus
if [ -n "$INCUS_VERSION" ]; then
    echo "Installing Incus version: $INCUS_VERSION"
    DEBIAN_FRONTEND=noninteractive apt-get install -y incus="$INCUS_VERSION" incus-tools incus-client
else
    echo "Installing latest stable Incus (6.19+)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y incus incus-tools incus-client
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

# Install ZFS for disk quota enforcement
echo "==> Installing ZFS for disk quota support..."
if ! command -v zpool &> /dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y zfsutils-linux
    modprobe zfs
    echo "✓ ZFS installed"
else
    echo "✓ ZFS already installed"
fi

# Initialize Incus with ZFS storage
echo "==> Initializing Incus with ZFS..."
if [ ! -f /var/lib/incus/.initialized ]; then
    # Create ZFS pool on boot disk for container storage
    # This enables disk quota enforcement
    if ! zpool list incus-local &>/dev/null; then
        # Create a ZFS pool using a file-based vdev
        # This allows ZFS features (quotas, compression) without a separate disk
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
        echo "✓ ZFS pool created (file-backed, 50GB)"
    fi

    # Initialize Incus with ZFS
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
    echo "✓ Incus initialized with ZFS (quotas ENFORCED)"
else
    echo "✓ Incus already initialized"
fi

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
cat >> /etc/ssh/sshd_config.d/containarium.conf <<EOF
# Containarium SSH hardening
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20s
EOF

systemctl restart sshd
echo "✓ SSH hardened"

# Set up admin users (from Terraform variable)
echo "==> Setting up admin users..."
IFS=',' read -ra USERS <<< "$ADMIN_USERS"
for username in "$${USERS[@]}"; do
    if ! id "$username" &>/dev/null; then
        useradd -m -s /bin/bash -G sudo "$username"
        echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$username"
        chmod 0440 /etc/sudoers.d/"$username"
        echo "✓ Created user: $username"
    else
        echo "✓ User already exists: $username"
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

if [ -n "$CONTAINARIUM_BINARY_URL" ]; then
    # Download from specified URL (e.g., GitHub releases)
    echo "Downloading from: $CONTAINARIUM_BINARY_URL"
    curl -fsSL "$CONTAINARIUM_BINARY_URL" -o /usr/local/bin/containarium
    chmod +x /usr/local/bin/containarium
    echo "✓ Containarium daemon downloaded"
else
    echo "⚠ No Containarium binary URL provided, daemon not installed"
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

# Create systemd service for containarium daemon
echo "==> Creating systemd service for Containarium daemon..."
cat > /etc/systemd/system/containarium.service <<'EOF'
[Unit]
Description=Containarium Container Management Daemon
Documentation=https://github.com/footprintai/Containarium
After=network.target incus.service
Requires=incus.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium daemon --address 0.0.0.0 --port 50051
Restart=on-failure
RestartSec=5s
User=root
Group=root

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/incus

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=containarium

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Enable and start daemon if binary is installed
if [ -f /usr/local/bin/containarium ]; then
    systemctl daemon-reload
    systemctl enable containarium.service
    systemctl start containarium.service
    echo "✓ Containarium daemon service enabled and started"

    # Check status
    sleep 2
    if systemctl is-active --quiet containarium; then
        echo "✓ Containarium daemon is running on port 50051"
    else
        echo "⚠ Containarium daemon failed to start, check: journalctl -u containarium"
    fi
else
    echo "⚠ Containarium binary not found, service not started"
    echo "  Install binary manually and run: systemctl start containarium"
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

# Mark setup as complete
touch /opt/containarium/.setup_complete
date > /opt/containarium/.setup_timestamp

exit 0
