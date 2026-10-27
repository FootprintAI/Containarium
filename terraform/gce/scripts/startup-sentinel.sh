#!/bin/bash
set -euo pipefail

# Sentinel VM startup script — minimal setup
# Only installs the containarium binary and runs it in sentinel mode.
# No Incus, no Caddy, no ZFS — just networking and the binary.

exec 1> >(logger -s -t containarium-sentinel-startup) 2>&1
echo "=== Containarium Sentinel Startup ==="

# Template variables
ADMIN_USERS="${join(",", admin_users)}"
CONTAINARIUM_BINARY_URL="${containarium_binary_url}"
SPOT_VM_NAME="${spot_vm_name}"
ZONE="${zone}"
PROJECT_ID="${project_id}"

# Trim unnecessary services that consume 150-200 MB on the e2-micro sentinel (#770).
# snapd (~38 MB), multipathd (~27 MB), update-notifier/check-new-release (~90 MB
# transient) are irrelevant on a pure-forwarder VM.
systemctl stop snapd.service snapd.socket 2>/dev/null || true
systemctl disable snapd.service snapd.socket 2>/dev/null || true
apt-get purge -y -qq snapd 2>/dev/null || true
apt-get purge -y -qq update-notifier update-notifier-common 2>/dev/null || true
systemctl stop multipathd.service multipathd.socket 2>/dev/null || true
systemctl disable multipathd.service multipathd.socket 2>/dev/null || true
systemctl mask multipathd.service multipathd.socket 2>/dev/null || true

# Disable apt auto-upgrade timers — manual patching only.
# Auto-upgrades on the e2-micro sentinel (955MB RAM, no swap) caused OOM
# hangs when unattended-upgrades + packagekit + sshpiper ran concurrently.
# Re-enable with: systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

# System update (minimal)
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl fail2ban > /dev/null

# Harden SSH — sshd listens on port 2222 ONLY (management/IAP access)
# Port 22 is now owned by sshpiper (SSH reverse proxy with fail-to-ban)
cat > /etc/ssh/sshd_config.d/containarium.conf <<EOF
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
EOF
# Set sshd to port 2222 only — port 22 is reserved for sshpiper
sed -i '/^Port /d' /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config
# Ubuntu 24.04 uses systemd socket activation — override ssh.socket too
mkdir -p /etc/systemd/system/ssh.socket.d
cat > /etc/systemd/system/ssh.socket.d/override.conf <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:2222
ListenStream=[::]:2222
EOF
systemctl daemon-reload
systemctl restart ssh.socket || true
systemctl restart ssh || systemctl restart sshd || true

# Create admin users
IFS=',' read -ra USERS <<< "$ADMIN_USERS"
for username in "$${USERS[@]}"; do
    username=$(echo "$username" | xargs)
    if [ -z "$username" ]; then continue; fi
    if ! id "$username" &>/dev/null; then
        # Create user without creating a new primary group (use existing or
        # fall back to "users") — a bare useradd tries to auto-create a
        # same-named primary group, which fails outright if a group of that
        # name already exists (e.g. "admin" collides with a pre-existing
        # system group shipped in the stock Ubuntu image; kafeido-infra#41).
        # This script runs under `set -euo pipefail`, so an unhandled
        # failure here previously aborted the ENTIRE sentinel bootstrap
        # (sshpiper, containarium, everything) over one bad username.
        useradd -m -s /bin/bash -N -G sudo "$username" || useradd -m -s /bin/bash -g users -G sudo "$username"
        echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$username"
        chmod 440 /etc/sudoers.d/"$username"
        mkdir -p /home/"$username"/.ssh
        chmod 700 /home/"$username"/.ssh
        chown -R "$username":"$username" /home/"$username"/.ssh
    fi
done

# Install sshpiper — SSH reverse proxy with built-in fail-to-ban
# sshpiper sits on port 22, sees real client IPs, and bans after failed auths
echo "==> Installing sshpiper..."
SSHPIPER_VERSION="v1.6.1"
# sha256 from the v1.6.1 release checksums.txt; keep in step with
# .github/workflows/ssh-ban.yml (scripts/ci/check-sentinel-sshpiper-checksum.sh).
SSHPIPER_SHA256="95d423a70e843a7512a72fbb16c0fa5dc59217cf064cb3e277520fddffded1e1"
if [ ! -f /usr/local/bin/sshpiperd ]; then
    cd /tmp
    curl -fsSL "https://github.com/tg123/sshpiper/releases/download/$${SSHPIPER_VERSION}/sshpiperd_with_plugins_linux_x86_64.tar.gz" \
      -o sshpiper.tar.gz
    # A mismatch fails the boot step (set -e) before anything is extracted.
    echo "$${SSHPIPER_SHA256}  sshpiper.tar.gz" | sha256sum -c -
    tar xzf sshpiper.tar.gz
    mv sshpiperd /usr/local/bin/sshpiperd
    chmod +x /usr/local/bin/sshpiperd
    # Plugins are separate binaries (yaml, failtoban, etc.)
    cp plugins/* /usr/local/bin/
    chmod +x /usr/local/bin/yaml /usr/local/bin/failtoban
    rm -rf sshpiper.tar.gz plugins LICENSE README.md
    echo "sshpiper $${SSHPIPER_VERSION} installed"
else
    echo "sshpiper already installed"
fi

# Generate sshpiper host key + upstream key for authenticating to spot VM
mkdir -p /etc/sshpiper/users
if [ ! -f /etc/sshpiper/host_key ]; then
    ssh-keygen -t ed25519 -f /etc/sshpiper/host_key -N ""
    echo "sshpiper host key generated"
fi
if [ ! -f /etc/sshpiper/upstream_key ]; then
    ssh-keygen -t ed25519 -f /etc/sshpiper/upstream_key -N ""
    echo "sshpiper upstream key generated"
fi

# Create sshpiper systemd service
cat > /etc/systemd/system/sshpiper.service <<'EOF'
[Unit]
Description=SSHPiper reverse proxy
After=network.target containarium-sentinel.service
BindsTo=containarium-sentinel.service
PartOf=containarium-sentinel.service

[Service]
ExecStart=/usr/local/bin/sshpiperd \
  -i /etc/sshpiper/host_key \
  -p 22 \
  --drop-hostkeys-message \
  --login-grace-time 90s \
  /usr/local/bin/containarium sentinel ssh-authz-plugin \
  --ssh-authz-grace 5m \
  --ssh-authz-timeout 3s \
  -- \
  /usr/local/bin/containarium sentinel ssh-session-plugin \
  --records-file /var/log/containarium/ssh-sessions.jsonl \
  --sshpiper-config /etc/sshpiper/config.yaml \
  -- \
  /usr/local/bin/containariumd sentinel ssh-upstream-plugin \
  --upstream-control-socket /run/containarium/ssh-upstream/control.sock \
  --plugin /usr/local/bin/yaml \
  --plugin-arg=--config \
  --plugin-arg=/etc/sshpiper/config.yaml \
  -- \
  /usr/local/bin/containariumd sentinel ssh-ban-plugin \
  --upstream-control-socket /run/containarium/ssh-upstream/control.sock \
  --max-failures 20 \
  --ban-duration 1h
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# SSH session sink rotation + retention (#2415, ISO 27001 A.8.15). See the
# module variant of this script for the full rationale: `create` + SIGHUP to the
# plugin (never copytruncate), delaycompress so the shipper can finish the
# rotated file's tail, and an ANCHORED pkill so sshpiperd itself is not signalled.
# Retention is N days. This script is not rendered with a retention template
# variable, so it reads the optional instance-metadata attribute
# `ssh-session-log-retention-days` and defaults to 90.
SSH_SESSION_LOG_RETENTION_DAYS="$(curl -fsS -H 'Metadata-Flavor: Google' \
    'http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-session-log-retention-days' 2>/dev/null || echo 90)"
case "$SSH_SESSION_LOG_RETENTION_DAYS" in
    ''|*[!0-9]*|0) SSH_SESSION_LOG_RETENTION_DAYS=90 ;;
esac
cat > /etc/logrotate.d/containarium-ssh-sessions <<LOGROTATE_EOF
/var/log/containarium/ssh-sessions.jsonl {
    daily
    rotate $SSH_SESSION_LOG_RETENTION_DAYS
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        pkill -HUP -f '^/usr/local/bin/containariumd? sentinel ssh-session-plugin' || true
    endscript
}
LOGROTATE_EOF
chmod 0644 /etc/logrotate.d/containarium-ssh-sessions

systemctl daemon-reload
systemctl enable sshpiper
# sshpiper will be started after config.yaml is generated by the sentinel key sync
echo "sshpiper service installed (will start after config is generated)"

# Download containariumd binary. The sentinel serves this SAME binary to
# recovered workhorses on :8888 (internal/sentinel/binaryserver.go's
# defaultBinaryPath, #1779), so it must be placed there, not the old name.
if [ -n "$CONTAINARIUM_BINARY_URL" ]; then
    echo "Downloading containariumd from $CONTAINARIUM_BINARY_URL"
    curl -fsSL "$CONTAINARIUM_BINARY_URL" -o /usr/local/bin/containariumd
    chmod +x /usr/local/bin/containariumd
    # Rollout Phase 1 (#1781): keep the old name working as a symlink so any
    # runbook/cron this inventory missed keeps working.
    ln -sf /usr/local/bin/containariumd /usr/local/bin/containarium
    echo "Containariumd version: $(/usr/local/bin/containariumd version 2>/dev/null || echo 'unknown')"
fi

# Install the shared controller policy before either guarded listener admits SSH.
install -d -m 0700 /etc/containarium/ssh-upstream
cat > /etc/containarium/ssh-upstream/policy.candidate.json <<'EOF'
{"initialDelay":"1s","maxDelay":"30s","window":"600s","setupTimeout":"30s","failureBudget":2,"riskPerAttempt":1,"maxBackends":1024,"maxPending":32,"maxConnections":4096,"jitter":0.25,"egressGroup":"sentinel"}
EOF
chmod 0600 /etc/containarium/ssh-upstream/policy.candidate.json
if [ ! -f /etc/containarium/ssh-upstream/policy.json ]; then
    mv /etc/containarium/ssh-upstream/policy.candidate.json /etc/containarium/ssh-upstream/policy.json
elif cmp -s /etc/containarium/ssh-upstream/policy.json /etc/containarium/ssh-upstream/policy.candidate.json; then
    rm -f /etc/containarium/ssh-upstream/policy.candidate.json /etc/containarium/ssh-upstream/policy.pending.json
else
    mv /etc/containarium/ssh-upstream/policy.candidate.json /etc/containarium/ssh-upstream/policy.pending.json
    logger -t ssh-upstream-reconcile "SSH upstream policy staged; apply through the maintenance procedure"
fi
install -d -m 0755 /etc/systemd/system/containarium-sentinel.service.d
cat > /etc/systemd/system/containarium-sentinel.service.d/ssh-upstream.conf <<'EOF'
[Service]
Environment=CONTAINARIUM_SSH_UPSTREAM_POLICY=/etc/containarium/ssh-upstream/policy.json
ExecStartPost=-/bin/systemctl --no-block start sshpiper.service sshpiper-anon.service
EOF

# Install and start sentinel service
if [ -f /usr/local/bin/containariumd ]; then
    /usr/local/bin/containariumd sentinel service install \
        --spot-vm "$SPOT_VM_NAME" \
        --zone "$ZONE" \
        --project "$PROJECT_ID"
    echo "Sentinel service installed and running"
else
    echo "WARNING: containariumd binary not found, sentinel not started"
fi

echo "=== Sentinel Startup Complete ==="
