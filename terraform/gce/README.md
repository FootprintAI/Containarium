# Containarium GCE Terraform Configuration

This directory contains Terraform configurations for deploying Containarium on Google Cloud Platform.

## Quick Start

### 1. Configure Variables

```bash
# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit with your settings
vim terraform.tfvars
```

### 2. Deploy

```bash
# Initialize Terraform
terraform init

# Review plan
terraform plan

# Deploy infrastructure
terraform apply

# Note the outputs (IP address, SSH commands, etc.)
```

### 3. Connect

```bash
# SSH to jump server (from terraform output)
ssh admin@35.x.x.x

# Verify Incus
incus --version
incus list
```

## Deployment Options

### Option 1: Single Regular VM (Simple)

**Use for**: < 50 users, can tolerate brief downtime

```hcl
# terraform.tfvars
use_spot_instance    = false
use_persistent_disk  = false
machine_type         = "n2-standard-8"  # 32GB RAM
```

**Cost**: ~$242/month

### Option 2: Spot VM + Persistent Disk (Recommended)

**Use for**: < 100 users, tight budget, can tolerate 2-5 min downtime

```hcl
# terraform.tfvars
use_spot_instance    = true   # 76% cheaper!
use_persistent_disk  = true   # Containers survive spot termination
machine_type         = "n2-standard-8"
data_disk_size       = 500    # GB
enable_disk_snapshots = true  # Daily backups
```

**Cost**: ~$98/month (spot VM + persistent disk)

**How it works**:
- Spot VM can be terminated by GCP at any time
- Persistent disk stores all container data
- When VM restarts, containers auto-resume from disk
- Downtime: 2-5 minutes during restart

### Option 3: Horizontal Scaling (Multiple Jump Servers)

**Use for**: > 100 users, need fault tolerance

```hcl
# terraform.tfvars
enable_horizontal_scaling = true
jump_server_count        = 3  # Deploy 3 jump servers
use_spot_instance        = true
```

**Cost**: ~$294/month (3x spot VMs + disks)

**Architecture**:
```
Load Balancer
  ├─ Jump-1 (50 users)
  ├─ Jump-2 (50 users)
  └─ Jump-3 (50 users)
```

## Files

- `main.tf` - Main GCE VM configuration
- `spot-instance.tf` - Spot instance + persistent disk setup
- `variables.tf` - Input variables
- `outputs.tf` - Output values (IPs, SSH commands)
- `terraform.tfvars.example` - Example configuration
- `scripts/startup.sh` - Regular VM initialization script
- `scripts/startup-spot.sh` - Spot VM initialization + recovery script

## Cost Comparison

| Setup | Users | Cost/Month | Cost/User |
|-------|-------|-----------|-----------|
| Single regular VM | 50 | $242 | $4.84 |
| Spot VM + disk | 50 | $98 | $1.96 |
| 3x spot VMs | 150 | $294 | $1.96 |
| Old way (1 VM/user) | 50 | $1,250 | $25.00 |

**Savings: 92%** vs traditional approach!

## Spot Instance Details

### What is a Spot Instance?

- **60-91% cheaper** than regular VMs
- Can be **terminated by GCP at any time** (usually runs days/weeks)
- Receives **30-second warning** before termination
- **Perfect for stateless or resilient workloads**

### How Containarium Handles Spot Termination

1. **Persistent Disk**: All container data on separate disk
2. **Auto-Recovery**: Containers automatically restart when VM restarts
3. **Auto-Start**: Containers marked with `boot.autostart=true` restart automatically
4. **Minimal Downtime**: Typically 2-5 minutes from termination to full recovery

### Mark Containers for Auto-Start

```bash
# Enable auto-start for a container
incus config set alice-container boot.autostart true

# Now if spot VM restarts, alice's container automatically starts
```

## Persistent Disk Strategy

### Disk Layout (with persistent disk)

```
GCE VM
├─ Boot Disk (100GB, ephemeral)
│   ├─ OS
│   ├─ Binaries
│   └─ /tmp
│
└─ Data Disk (500GB, persistent)
    └─ /var/lib/incus
        ├─ Container filesystems
        ├─ Container configs
        ├─ Images
        └─ Network state
```

### Snapshots

Automatic daily snapshots (if enabled):
- Taken at 3 AM daily
- Retained for 30 days
- Stored in same region
- Can be used to restore containers

### Restore from Snapshot

```bash
# List snapshots
gcloud compute snapshots list --filter="source_disk:incus-data"

# Create new disk from snapshot
gcloud compute disks create incus-data-restored \
  --source-snapshot incus-backup-20250115 \
  --zone us-central1-a

# Attach to VM
gcloud compute instances attach-disk containarium-jump \
  --disk incus-data-restored \
  --device-name incus-data \
  --zone us-central1-a
```

## Security

### SSH Access Restrictions

**Development** (terraform.tfvars):
```hcl
allowed_ssh_sources = ["0.0.0.0/0"]  # WARNING: Open to internet
```

**Production** (recommended):
```hcl
allowed_ssh_sources = [
  "203.0.113.0/24",   # Office IP range
  "198.51.100.5/32",  # VPN server
]
```

### Admin SSH Keys

```hcl
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3... admin@example.com"
  alice = "ssh-ed25519 AAAAC3... alice@example.com"
}
```

## Outputs

After `terraform apply`, you'll see:

```
Outputs:

jump_server_ip = "35.x.x.x"
ssh_command = "ssh admin@35.x.x.x"

ssh_config_snippet = <<EOT
Host containarium-jump
    HostName 35.x.x.x
    User admin
EOT

setup_commands = <<EOT
1. SSH to jump server:
   ssh admin@35.x.x.x

2. Verify Incus:
   incus --version

3. Copy containarium CLI:
   scp bin/containarium-linux-amd64 admin@35.x.x.x:/tmp/
   ...
EOT
```

## Troubleshooting

### Spot instance was terminated

Check logs:
```bash
# On VM (after it restarts)
journalctl -u containarium-autostart
cat /opt/containarium/logs/spot-recovery.log
```

Verify containers restarted:
```bash
incus list
```

### Persistent disk not mounting

```bash
# Check if disk is attached
lsblk

# Check mount
df -h | grep incus

# Manual mount
mount /dev/disk/by-id/google-incus-data /var/lib/incus
```

### Container didn't auto-start

```bash
# Check if boot.autostart is set
incus config get alice-container boot.autostart

# Enable it
incus config set alice-container boot.autostart true

# Manually start
incus start alice-container
```

## Next Steps

1. ✅ Deploy infrastructure: `terraform apply`
2. ✅ SSH to jump server
3. ✅ Build and copy containarium CLI
4. ✅ Create your first container: `containarium create alice`
5. ✅ Configure users' SSH access (see `../docs/SSH-JUMP-SERVER-SETUP.md`)

## Documentation

- [SSH Jump Server Setup](../../docs/SSH-JUMP-SERVER-SETUP.md)
- [Spot Instances & Scaling](../../docs/SPOT-INSTANCES-AND-SCALING.md)
- [Implementation Plan](../../IMPLEMENTATION-PLAN.md)
