# Horizontal Scaling Quick Start Guide

This guide shows you how to deploy and use Containarium with **Approach 1: Independent Jump Servers**.

## Architecture Overview

```
                  Load Balancer
                  (35.x.x.x)
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
  Jump-1          Jump-2          Jump-3
  35.1.1.1        35.2.2.2        35.3.3.3
  │               │               │
  ├─ alice        ├─ bob          ├─ charlie
  ├─ dave         ├─ eve          ├─ frank
  └─ (48 more)    └─ (48 more)    └─ (48 more)
```

**Key Points**:
- Each jump server is independent
- Load balancer distributes SSH connections
- ~50 users per jump server
- Containers stay on their assigned jump server

---

## Step 1: Deploy Infrastructure

### Choose Your Configuration

**Small (20-50 users)**: Single spot VM
```bash
cp examples/single-server-spot.tfvars terraform.tfvars
```

**Medium (100-150 users)**: 3 jump servers
```bash
cp examples/horizontal-scaling-3-servers.tfvars terraform.tfvars
```

**Large (200-250 users)**: 5 jump servers
```bash
cp examples/horizontal-scaling-5-servers.tfvars terraform.tfvars
```

### Edit Configuration

```bash
vim terraform.tfvars
```

**Required changes**:
```hcl
# 1. Set your GCP project
project_id = "my-actual-project-id"

# 2. Add your SSH key
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3... your-actual-key"
}

# 3. Restrict SSH access (production)
allowed_ssh_sources = [
  "YOUR.OFFICE.IP.RANGE/24"  # Your actual IPs
]
```

### Deploy

```bash
# Initialize Terraform
terraform init

# Review what will be created
terraform plan

# Deploy (takes 3-5 minutes)
terraform apply

# Save the outputs!
```

---

## Step 2: Understand the Outputs

After `terraform apply`, you'll see:

```
Outputs:

horizontal_scaling_enabled = true
jump_servers_count = 3

jump_servers_ips = {
  "jump-1" = "35.1.1.1"
  "jump-2" = "35.2.2.2"
  "jump-3" = "35.3.3.3"
}

load_balancer_ip = "35.x.x.x"

ssh_connection_methods = <<EOT
=== Connection Methods ===

1. Via Load Balancer (Recommended):
   ssh admin@35.x.x.x

2. Direct to Specific Server:
   ssh admin@35.1.1.1  # jump-1
   ssh admin@35.2.2.2  # jump-2
   ssh admin@35.3.3.3  # jump-3
EOT

capacity_info = {
  servers         = 3
  estimated_users = 150
  using_spot      = true
  load_balanced   = true
}
```

---

## Step 3: Initial Setup

### Connect to Load Balancer

```bash
# Connect via load balancer (goes to any healthy server)
ssh admin@35.x.x.x

# You're now on jump-1, jump-2, or jump-3 (load balancer decides)
```

### Verify Setup

```bash
# Check Incus is running
incus --version

# Check containers (should be empty initially)
incus list

# Check system info
containarium-info
```

### Install Containarium CLI

```bash
# On your local machine - build for Linux
cd Containarium
make build-linux

# Copy to jump server (via load balancer)
scp bin/containarium-linux-amd64 admin@35.x.x.x:/tmp/

# SSH and install
ssh admin@35.x.x.x
sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium
sudo chmod +x /usr/local/bin/containarium

# Verify
containarium version
```

**Repeat for each jump server** (if not using load balancer):
```bash
scp bin/containarium-linux-amd64 admin@35.1.1.1:/tmp/
ssh admin@35.1.1.1 "sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium"

# Repeat for jump-2, jump-3...
```

---

## Step 4: Distribute Users Across Servers

You need to decide which users go on which jump server.

### Strategy 1: By Team

```
Jump-1 → Engineering Team (50 users)
Jump-2 → Product Team (40 users)
Jump-3 → QA Team (30 users)
```

### Strategy 2: Alphabetically

```
Jump-1 → Users A-H
Jump-2 → Users I-P
Jump-3 → Users Q-Z
```

### Strategy 3: Round-Robin

```
Jump-1 → alice (1), dave (4), greg (7), ...
Jump-2 → bob (2), eve (5), hannah (8), ...
Jump-3 → charlie (3), frank (6), iris (9), ...
```

---

## Step 5: Create Containers

### Create on Specific Jump Server

```bash
# SSH to jump-1 directly
ssh admin@35.1.1.1

# Create containers for Engineering team
containarium create alice --ssh-key ~/.ssh/alice.pub
containarium create dave --ssh-key ~/.ssh/dave.pub

# Enable auto-start (for spot instance recovery)
incus config set alice-container boot.autostart true
incus config set dave-container boot.autostart true

# List containers
incus list
```

Repeat for jump-2, jump-3 with their assigned users.

### Track Assignment

Create a simple tracking file:

```bash
# assignment.txt
Jump-1 (35.1.1.1):
  - alice
  - dave
  - greg
  (47 more...)

Jump-2 (35.2.2.2):
  - bob
  - eve
  - hannah
  (47 more...)

Jump-3 (35.3.3.3):
  - charlie
  - frank
  - iris
  (47 more...)
```

---

## Step 6: User SSH Configuration

Users need to know which jump server hosts their container.

### Method 1: Load Balancer (Session Affinity)

Load balancer keeps user connected to same server based on source IP.

**User's ~/.ssh/config**:
```ssh-config
# Containarium Jump Server
Host containarium-jump
    HostName 35.x.x.x  # Load balancer IP
    User admin
    IdentityFile ~/.ssh/id_rsa

# My dev container
Host my-dev
    HostName 10.0.3.100
    User alice
    ProxyJump containarium-jump
    IdentityFile ~/.ssh/alice_key
```

**Connect**:
```bash
ssh my-dev
# Load balancer routes to same jump server each time
```

### Method 2: Direct Assignment

Tell each user their specific jump server.

**Engineering team (Jump-1) gets**:
```ssh-config
Host containarium-jump
    HostName 35.1.1.1  # Jump-1 IP
    User admin

Host my-dev
    HostName 10.0.3.100
    User alice
    ProxyJump containarium-jump
```

**Product team (Jump-2) gets**:
```ssh-config
Host containarium-jump
    HostName 35.2.2.2  # Jump-2 IP
    User admin
```

---

## Step 7: Automation Script

Automate container creation across servers:

```bash
#!/bin/bash
# create-all-users.sh

USERS_JUMP1=("alice" "dave" "greg")
USERS_JUMP2=("bob" "eve" "hannah")
USERS_JUMP3=("charlie" "frank" "iris")

# Create on Jump-1
for user in "${USERS_JUMP1[@]}"; do
  ssh admin@35.1.1.1 "containarium create $user && incus config set ${user}-container boot.autostart true"
done

# Create on Jump-2
for user in "${USERS_JUMP2[@]}"; do
  ssh admin@35.2.2.2 "containarium create $user && incus config set ${user}-container boot.autostart true"
done

# Create on Jump-3
for user in "${USERS_JUMP3[@]}"; do
  ssh admin@35.3.3.3 "containarium create $user && incus config set ${user}-container boot.autostart true"
done
```

---

## Step 8: Monitoring & Management

### Check All Servers

```bash
#!/bin/bash
# check-all-servers.sh

SERVERS=("35.1.1.1" "35.2.2.2" "35.3.3.3")

for server in "${SERVERS[@]}"; do
  echo "=== $server ==="
  ssh admin@$server "incus list --format compact"
  echo ""
done
```

### View Capacity

```bash
# On each jump server
ssh admin@35.1.1.1 "free -h && incus list | wc -l"
```

### Health Check

```bash
# Test SSH to load balancer
ssh -o ConnectTimeout=5 admin@35.x.x.x "echo 'OK'"

# Test each server
for ip in 35.1.1.1 35.2.2.2 35.3.3.3; do
  ssh -o ConnectTimeout=5 admin@$ip "echo 'OK'" && echo "$ip: healthy"
done
```

---

## Common Operations

### Add Capacity (Add New Jump Server)

```bash
# Edit terraform.tfvars
jump_server_count = 4  # Was 3

# Apply
terraform apply

# New server: jump-4 at 35.4.4.4
# Copy containarium CLI and start creating containers
```

### Remove Capacity

```bash
# 1. Migrate containers off jump-3 first (manual)
ssh admin@35.3.3.3
incus export alice-container alice-backup.tar.gz
# Copy backup and import on jump-1 or jump-2

# 2. Reduce count
jump_server_count = 2

# 3. Apply
terraform apply
```

### Spot Instance Recovery

Containers automatically restart when spot instance recovers:

```bash
# Check recovery log
ssh admin@35.1.1.1
cat /opt/containarium/logs/spot-recovery.log

# Example output:
# 2025-12-29 10:23:15: Spot instance recovered, 48 containers restarted
```

---

## Troubleshooting

### User Can't Connect

```bash
# 1. Check which jump server has their container
ssh admin@35.1.1.1 "incus list | grep alice"
ssh admin@35.2.2.2 "incus list | grep alice"

# 2. Found on jump-2, verify SSH
ssh admin@35.2.2.2 "incus exec alice-container -- systemctl status ssh"

# 3. Test ProxyJump
ssh -J admin@35.2.2.2 alice@10.0.3.100
```

### Load Balancer Not Working

```bash
# Check health
gcloud compute forwarding-rules describe containarium-jump-ssh-lb --region=us-central1

# Check backend health
gcloud compute backend-services get-health containarium-jump-backend --region=us-central1
```

### Container Missing After Spot Termination

```bash
# Check if auto-start was enabled
ssh admin@35.1.1.1
incus config get alice-container boot.autostart

# If false, enable it
incus config set alice-container boot.autostart true

# Start manually
incus start alice-container
```

---

## Cost Breakdown (3 Jump Servers Example)

```
Component                Cost/Month
---------------------------------
3x n2-standard-8 (spot)  $174
3x 500GB disks           $120
Load balancer            $18
---------------------------------
TOTAL                    $312/month

Per User (150 users)     $2.08/month
```

**Savings**: 92% vs traditional approach ($3,750/month)

---

## Next Steps

1. ✅ Deploy infrastructure: `terraform apply`
2. ✅ Verify all jump servers accessible
3. ✅ Install containarium CLI on each
4. ✅ Decide user distribution strategy
5. ✅ Create containers on assigned servers
6. ✅ Distribute SSH configs to users
7. ✅ Monitor and adjust as needed

---

## Summary

**Approach 1 (Independent Jump Servers)**:
- ✅ Simple to understand and manage
- ✅ Strong fault isolation
- ✅ Easy to scale (add more servers)
- ✅ No cross-VM jumping needed
- ✅ Perfect for 100-300 users

**Trade-off**: Users must be assigned to specific servers.

**Best practice**: Use load balancer with session affinity for seamless experience.
