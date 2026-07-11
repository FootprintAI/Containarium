#!/bin/bash
set -euo pipefail

# Sentinel VM startup script — minimal setup
# Only installs the containarium binary and runs it in sentinel mode.
# No Incus, no Caddy, no ZFS — just networking and the binary.

exec 1> >(logger -s -t containarium-sentinel-startup) 2>&1
echo "=== Containarium Sentinel Startup ==="

# Template variables
ADMIN_USERS="${join(",", admin_users)}"
CONTAINARIUM_VERSION="${containarium_version}"
CONTAINARIUM_BINARY_URL="${containarium_binary_url}"
SPOT_VM_NAME="${spot_vm_name}"
ZONE="${zone}"
PROJECT_ID="${project_id}"

# reconcile_containarium_binary installs/updates /usr/local/bin/containarium to
# the desired version (CONTAINARIUM_VERSION), then leaves the service
# install+restart below to pick it up. The sentinel serves this binary to
# recovered workhorses on :8888, so it must honor the requested version — and
# the previous unconditional `curl -o <live binary>` was both non-version-aware
# and unsafe (a failed download under `set -e` aborted the whole boot, and it
# overwrote the running binary in place). See #385.
#
# A real pinned version that already matches is a no-op (faster boots, and the
# sentinel won't re-pull a same-version binary). "dev"/unset keep the prior
# always-pull-from-URL behavior so the dev iteration loop is unchanged. Download
# is to a temp path + atomic swap, and the whole thing is best-effort.
reconcile_containarium_binary() {
    desired="$CONTAINARIUM_VERSION"
    current=""
    if [ -x /usr/local/bin/containarium ]; then
        current="$(/usr/local/bin/containarium version 2>/dev/null || true)"
    fi

    # Skip only for a real pinned version that already matches. "dev" and unset
    # always re-pull (preserving the sentinel's prior every-boot behavior).
    if [ -n "$desired" ] && [ "$desired" != "dev" ] && printf '%s' "$current" | grep -qF "$desired"; then
        echo "containarium already at desired version ($desired) — skipping download"
        return 0
    fi

    if [ -z "$CONTAINARIUM_BINARY_URL" ]; then
        if [ -x /usr/local/bin/containarium ]; then
            echo "no containarium_binary_url; keeping existing binary ($current)"
        else
            echo "WARNING: no containarium binary source available"
        fi
        return 0
    fi

    echo "Downloading containarium from $CONTAINARIUM_BINARY_URL"
    tmp=/usr/local/bin/.containarium.new
    rm -f "$tmp"
    if curl -fsSL "$CONTAINARIUM_BINARY_URL" -o "$tmp"; then
        chmod +x "$tmp"
        mv -f "$tmp" /usr/local/bin/containarium
        echo "Containarium version: $(/usr/local/bin/containarium version 2>/dev/null || echo unknown)"
    else
        rm -f "$tmp"
        if [ -x /usr/local/bin/containarium ]; then
            echo "WARNING: download failed; keeping existing binary ($current)"
        else
            echo "WARNING: download failed and no existing binary; sentinel will not start"
        fi
    fi
    return 0
}

# Trim unnecessary services that consume 150-200 MB on the sentinel (#770).
# snapd (~38 MB), multipathd (~27 MB), update-notifier/check-new-release (~90 MB
# transient) are irrelevant on a pure-forwarder VM. Removing them frees headroom
# so a reconnect storm or GC spike can't freeze the entire host.
systemctl stop snapd.service snapd.socket 2>/dev/null || true
systemctl disable snapd.service snapd.socket 2>/dev/null || true
apt-get purge -y -qq snapd 2>/dev/null || true
apt-get purge -y -qq update-notifier update-notifier-common 2>/dev/null || true
systemctl stop multipathd.service multipathd.socket 2>/dev/null || true
systemctl disable multipathd.service multipathd.socket 2>/dev/null || true
systemctl mask multipathd.service multipathd.socket 2>/dev/null || true

# Disable apt auto-upgrade timers — manual patching only.
# Auto-upgrades on a small sentinel VM caused OOM hangs when
# unattended-upgrades + packagekit + sshpiper ran concurrently.
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
SSHPIPER_VERSION="v1.5.3"
if [ ! -f /usr/local/bin/sshpiperd ]; then
    cd /tmp
    curl -fsSL "https://github.com/tg123/sshpiper/releases/download/$${SSHPIPER_VERSION}/sshpiperd_with_plugins_linux_x86_64.tar.gz" \
      -o sshpiper.tar.gz
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
After=network.target
# On a fresh deploy the routing config.yaml isn't written until the first
# container exists (keysync). sshpiper may therefore fail to start for a
# while; without disabling the start-rate limiter, Restart=always gives up
# after StartLimitBurst and the :22 listener never comes back. Keysync
# updates config but no longer restarts the service (see #404), so the
# service must be able to retry until the config is valid.
StartLimitIntervalSec=0

[Service]
ExecStart=/usr/local/bin/sshpiperd \
  -i /etc/sshpiper/host_key \
  -p 22 \
  --drop-hostkeys-message \
  yaml \
  --config /etc/sshpiper/config.yaml \
  -- \
  failtoban \
  --max-failures 100 \
  --ban-duration 5m
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sshpiper

# Seed a minimal (no-routes) config so sshpiper can bind :22 from boot;
# keysync overwrites it with real per-tenant pipes once the first
# container exists (the yaml plugin re-reads config.yaml per connection).
if [ ! -f /etc/sshpiper/config.yaml ]; then
    printf 'version: "1.0"\npipes: []\n' > /etc/sshpiper/config.yaml
    chmod 600 /etc/sshpiper/config.yaml
fi

# START it now — being merely 'enabled' isn't enough. Nothing else starts
# sshpiper (keysync stopped restarting it in #404), and Restart=always only
# applies to a service that has run at least once. With StartLimitIntervalSec=0
# above, this retries until config.yaml is valid even if the seed is rejected.
systemctl start sshpiper || true
echo "sshpiper service installed and started (config seeded; keysync populates routes)"

# Download/upgrade the containarium binary (version-aware + atomic +
# best-effort; the service install+restart below picks it up). #385.
# `|| true` also suspends set -e inside the function so a failed download
# can't abort the sentinel boot.
reconcile_containarium_binary || true

# --- Phase 0.4 / 0.5 secret + CA bootstrap --------------------------
#
# /etc/containarium holds the durable secret material the sentinel
# daemon reads via env vars (set in the systemd drop-in below).
# We use 0700 so an accidentally world-readable parent doesn't
# expose the key files; the files themselves are 0600/0400.
mkdir -p /etc/containarium
chmod 0700 /etc/containarium

# Sentinel↔daemon shared HMAC secret (Phase 0.4) lives in an
# EnvironmentFile that systemd loads when the unit starts. Mode
# 0600 root-only so it never appears in `ps` or in `systemctl cat`.
# Empty terraform var → file omitted → daemon logs a loud WARNING
# and the audit-known endpoints stay vulnerable.
SENTINEL_AUTH_SECRET="${sentinel_auth_secret}"
if [ -n "$SENTINEL_AUTH_SECRET" ]; then
    umask 077
    cat > /etc/containarium/env.secrets <<EOF
CONTAINARIUM_SENTINEL_AUTH_SECRET=$SENTINEL_AUTH_SECRET
EOF
    chmod 0600 /etc/containarium/env.secrets
    echo "✓ /etc/containarium/env.secrets written from terraform var"
else
    rm -f /etc/containarium/env.secrets
    echo "⚠ sentinel_auth_secret terraform var is empty — Phase 0.4/0.6 disabled, sentinel endpoints return 401 / unsigned"
fi

# Peer-CA private key (Phase 0.5). Auto-generated on first boot if
# enable_peer_mtls=true and the file doesn't already exist. We use
# `containarium pki generate-ca` once the binary is in place. The
# file is mode 0400 root-owned so only the sentinel daemon can
# read it. Replace this file on the host to rotate the CA (and
# every leaf cert in the fleet expires within 7 days afterwards).
#
# IMPORTANT: this key is not in Terraform state; back it up
# off-host (the audit-known operational gap is the only durable
# secret being on a single VM).
%{ if enable_peer_mtls ~}
if [ ! -f /etc/containarium/ca.key ] && [ -x /usr/local/bin/containarium ]; then
    echo "==> Generating peer-CA private key (one-time)..."
    umask 077
    if /usr/local/bin/containarium pki generate-ca > /etc/containarium/ca.key 2>/dev/null; then
        chmod 0400 /etc/containarium/ca.key
        echo "✓ /etc/containarium/ca.key generated (RSA-4096). BACK THIS UP OFF-HOST."
    else
        echo "⚠ 'containarium pki generate-ca' failed — Phase 0.5 disabled until ca.key is provisioned manually"
    fi
elif [ -f /etc/containarium/ca.key ]; then
    echo "✓ /etc/containarium/ca.key already present"
fi
%{ else ~}
echo "[sentinel] enable_peer_mtls=false — skipping CA bootstrap (Phase 0.5 off)"
%{ endif ~}

# Install and start sentinel service
if [ -f /usr/local/bin/containarium ]; then
    /usr/local/bin/containarium sentinel service install \
        --spot-vm "$SPOT_VM_NAME" \
        --zone "$ZONE" \
        --project "$PROJECT_ID"
    echo "Sentinel service installed and running"

    # Drop-in pulls Phase 0.4/0.5/0.6 env vars into the unit:
    #   - CONTAINARIUM_SENTINEL_AUTH_SECRET  (HMAC for /authorized-keys,
    #     /certs, /sentinel/ca, /sentinel/peer-cert; signs
    #     /sentinel/peers response)
    #   - CONTAINARIUM_CA_KEY_FILE           (peer-CA private key path)
    #
    # `EnvironmentFile=-/path` with the leading dash tells systemd to
    # ignore the file if absent (rollout-friendly: a sentinel that
    # hasn't been given the secret yet still boots, just without
    # the security layer). The secret file is mode 0600 so it
    # never appears in `ps` or `systemctl cat`.
    mkdir -p /etc/systemd/system/containarium-sentinel.service.d
    cat > /etc/systemd/system/containarium-sentinel.service.d/secrets.conf <<'EOF'
[Service]
EnvironmentFile=-/etc/containarium/env.secrets
EOF
%{ if enable_peer_mtls ~}
    cat >> /etc/systemd/system/containarium-sentinel.service.d/secrets.conf <<'EOF'
Environment=CONTAINARIUM_CA_KEY_FILE=/etc/containarium/ca.key
EOF
%{ endif ~}
    chmod 0644 /etc/systemd/system/containarium-sentinel.service.d/secrets.conf
    systemctl daemon-reload
    systemctl restart containarium-sentinel.service
    echo "✓ wrote secrets.conf systemd drop-in"

    # Optional override.conf for --proxy-protocol on the sentinel.
    #
    # `sentinel service install` generates a fixed ExecStart without
    # this flag. With --proxy-protocol the sentinel runs a userspace
    # TCP forwarder on :80/:443 (Containarium v0.16.7+) that prepends
    # a PROXY v2 frame to each connection, so the downstream Caddy
    # sees the real client IP. Without the flag, the sentinel
    # forwards via kernel iptables DNAT and the real source is lost
    # to MASQUERADE — apps then see the bridge gateway IP.
%{ if enable_proxy_protocol ~}
    mkdir -p /etc/systemd/system/containarium-sentinel.service.d
    cat > /etc/systemd/system/containarium-sentinel.service.d/proxyproto.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/containarium sentinel --spot-vm $SPOT_VM_NAME --zone $ZONE --project $PROJECT_ID --proxy-protocol
EOF
    echo "wrote proxyproto.conf for sentinel"
    systemctl daemon-reload
    systemctl restart containarium-sentinel.service
%{ endif ~}
else
    echo "WARNING: containarium binary not found, sentinel not started"
fi

echo "=== Sentinel Startup Complete ==="
