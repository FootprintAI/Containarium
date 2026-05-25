# Disaster Recovery Guide

This guide covers how to recover Containarium and all containers after the jump server instance is recreated (e.g., after spot instance termination or system failure).

## Overview

When using persistent storage (ZFS on external disk), your containers survive instance recreation. The `containarium recover` command automates the full recovery process.

## Prerequisites

- External disk with ZFS storage pool attached and mounted
- Containarium binary installed at `/usr/local/bin/containarium`
- Incus installed and running

## Recovery Process

### Quick Recovery (Recommended)

If a recovery config exists on the persistent storage:

```bash
# Auto-detect config from persistent storage
sudo containarium recover

# Or explicitly specify config file
sudo containarium recover --config /mnt/incus-data/containarium-recovery.yaml
```

### Manual Recovery

If no config file exists, specify parameters explicitly:

```bash
sudo containarium recover \
  --network-name incusbr0 \
  --network-cidr 10.0.3.1/24 \
  --storage-pool default \
  --storage-driver zfs \
  --zfs-source incus-pool/containers
```

### Dry Run

Preview what would be done without making changes:

```bash
sudo containarium recover --config /mnt/incus-data/containarium-recovery.yaml --dry-run
```

## What the Recovery Command Does

The `containarium recover` command performs these steps automatically:

### Step 1: Network Creation
Creates the `incusbr0` network bridge with the configured CIDR:
```bash
incus network create incusbr0 ipv4.address=10.0.3.1/24 ipv4.nat=true ipv6.address=none
```

### Step 2: Storage Pool Import
Imports the existing ZFS storage pool and recovers container definitions:
```bash
incus admin recover
# Answers: yes, default, zfs, incus-pool/containers, (empty), no, yes, yes
```

### Step 3: Default Profile Configuration
Adds the network device to the default profile:
```bash
incus profile device add default eth0 nic network=incusbr0 name=eth0
```

### Step 4: Start Containers
Starts all recovered containers:
```bash
incus start --all
```

### Step 5: Sync SSH Accounts
Restores jump server SSH accounts from container public keys:
```bash
containarium sync-accounts
```

## Recovery Config File

The daemon automatically saves a recovery config to persistent storage during startup. This file contains all parameters needed for recovery:

**Location:** `/mnt/incus-data/containarium-recovery.yaml`

**Example contents:**
```yaml
network_name: incusbr0
network_cidr: 10.0.3.1/24
storage_pool_name: default
storage_driver: zfs
zfs_source: incus-pool/containers
daemon:
  address: 0.0.0.0
  port: 50051
  http_port: 8080
  base_domain: <your-base-domain>
  caddy_admin_url: http://localhost:2019
  jwt_secret_file: /etc/containarium/jwt.secret
  app_hosting: true
  skip_infra_init: true
```

## Post-Recovery Steps

After running `containarium recover`, complete the setup:

### 1. Regenerate JWT Secret (if needed)

```bash
sudo mkdir -p /etc/containarium
sudo openssl rand -hex 32 | sudo tee /etc/containarium/jwt.secret > /dev/null
sudo chmod 600 /etc/containarium/jwt.secret
```

### 2. Create/Update Systemd Service

```bash
sudo tee /etc/systemd/system/containarium.service > /dev/null << 'SERVICE'
[Unit]
Description=Containarium Container Management Daemon
Documentation=https://github.com/footprintai/Containarium
After=network.target incus.service

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium daemon --address 0.0.0.0 --rest --http-port 8080 --jwt-secret-file /etc/containarium/jwt.secret --app-hosting --base-domain <your-base-domain> --caddy-admin-url http://localhost:2019 --skip-infra-init
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable containarium
sudo systemctl start containarium
```

### 3. Generate API Token

```bash
sudo containarium token generate \
  --username admin \
  --roles admin \
  --expiry 720h \
  --secret-file /etc/containarium/jwt.secret
```

### 4. Reload Caddy (if using app hosting)

```bash
sudo incus exec containarium-core-caddy -- caddy reload --config /etc/caddy/Caddyfile
```

## Troubleshooting

### "Storage pool directory already exists"

The storage pool is already imported. Use `--skip-infra-init` flag or check:
```bash
incus storage list
```

### "Network already exists"

The network is already created. Check:
```bash
incus network list
```

### Containers have no IP addresses

The default profile may be missing the eth0 device:
```bash
# Check profile
incus profile show default

# Add eth0 if missing
incus profile device add default eth0 nic network=incusbr0 name=eth0

# Restart containers to pick up the change
incus restart --all
```

### SSH jump not working

Run the sync-accounts command:
```bash
sudo containarium sync-accounts -v
```

## Best Practices

1. **Store recovery config on persistent disk**: The daemon auto-saves to `/mnt/incus-data/containarium-recovery.yaml`

2. **Use ZFS for container storage**: ZFS datasets survive instance recreation when on persistent disk

3. **Keep JWT secret on persistent storage**: Store `/etc/containarium/jwt.secret` on persistent disk or use a secrets manager

4. **Regular backups**: Even with persistent storage, maintain regular backups of container data

5. **Test recovery procedure**: Periodically test the recovery process to ensure it works
