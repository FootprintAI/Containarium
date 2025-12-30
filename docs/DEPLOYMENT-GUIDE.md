# Containarium Deployment Guide

Complete step-by-step guide from zero to running containers.

## Overview

**What happens during deployment**:

1. **Terraform** deploys GCE VM with Incus installed (automatic)
2. **You** build and copy the `containarium` CLI to the VM (manual, one-time)
3. **You** create containers using `containarium create` (per user)
4. **Users** SSH to their containers (ongoing use)

---

## Step-by-Step Deployment

### Phase 1: Deploy Infrastructure (5 minutes)

#### 1.1. Configure Terraform

```bash
cd terraform/gce

# Copy example configuration
cp examples/horizontal-scaling-3-servers.tfvars terraform.tfvars

# Edit with your details
vim terraform.tfvars
```

**Required changes in `terraform.tfvars`**:
```hcl
# Your GCP project ID
project_id = "my-actual-gcp-project"  # CHANGE THIS

# Your SSH key for admin access
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3NzaC... your-actual-key"  # CHANGE THIS
}

# Security: Restrict SSH access (production)
allowed_ssh_sources = [
  "203.0.113.0/24"  # Your office/VPN IP range - CHANGE THIS
]
```

#### 1.2. Deploy with Terraform

```bash
# Initialize Terraform (first time only)
terraform init

# Review what will be created
terraform plan

# Deploy (takes 3-5 minutes)
terraform apply

# Type 'yes' when prompted
```

#### 1.3. Save the Outputs

After `terraform apply` completes, you'll see:

```
Outputs:

jump_server_ip = "35.203.123.45"

jump_servers_ips = {
  "jump-1" = "35.203.123.45"
  "jump-2" = "35.203.124.46"
  "jump-3" = "35.203.125.47"
}

load_balancer_ip = "35.203.130.50"

ssh_command = "ssh admin@35.203.130.50"
```

**Save these IPs!** You'll need them.

#### 1.4. What Terraform Created

At this point, you have:
- ✅ GCE VMs running Ubuntu 24.04
- ✅ Incus installed and initialized
- ✅ Persistent disks attached
- ✅ Load balancer configured
- ✅ Firewall rules set up
- ✅ SSH access ready
- ✅ Kernel modules loaded for Docker

**What you DON'T have yet**:
- ❌ `containarium` CLI (you'll install this next)
- ❌ Containers (you'll create these after)

---

### Phase 2: Install Containarium CLI (5 minutes)

#### 2.1. Build the Binary

On your **local machine**:

```bash
cd Containarium

# Build for Linux (your jump servers are Linux)
make build-linux

# Verify binary was created
ls -lh bin/containarium-linux-amd64
# Should show ~16MB binary
```

#### 2.2. Copy Binary to Jump Server(s)

**Option A: Single Jump Server**

```bash
# Copy to jump server
scp bin/containarium-linux-amd64 admin@35.203.123.45:/tmp/

# SSH and install
ssh admin@35.203.123.45

# On the jump server:
sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium
sudo chmod +x /usr/local/bin/containarium

# Verify installation
containarium version
# Output: Containarium dev

# Exit back to your local machine
exit
```

**Option B: Multiple Jump Servers (Horizontal Scaling)**

If you deployed 3 jump servers, install on each:

```bash
# Create a script to deploy to all servers
cat > deploy-cli.sh <<'EOF'
#!/bin/bash
SERVERS=("35.203.123.45" "35.203.124.46" "35.203.125.47")

for server in "${SERVERS[@]}"; do
  echo "Deploying to $server..."
  scp bin/containarium-linux-amd64 admin@$server:/tmp/
  ssh admin@$server "sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium"
  echo "✓ Deployed to $server"
done
EOF

chmod +x deploy-cli.sh
./deploy-cli.sh
```

#### 2.3. Verify Incus is Running

SSH to a jump server and check:

```bash
ssh admin@35.203.123.45

# Check Incus is running
sudo incus --version
# Output: 6.0.0 (or similar)

# Check network is configured
sudo incus network list
# Should show incusbr0 with 10.0.3.1/24

# Check no containers exist yet
sudo incus list
# Should be empty

# Exit
exit
```

---

### Phase 3: Create Containers (1 minute per user)

Now you can create containers!

#### 3.1. Decide User Distribution

**For single server**:
- All users on one server

**For horizontal scaling (3 servers)**:
- Jump-1 → Team A (alice, dave, greg...)
- Jump-2 → Team B (bob, eve, hannah...)
- Jump-3 → Team C (charlie, frank, iris...)

#### 3.2. Create First Container

```bash
# SSH to jump-1
ssh admin@35.203.123.45

# Create container for alice (with SSH key)
sudo containarium create alice --ssh-key ~/.ssh/alice.pub --verbose

# Output shows progress:
Creating container for user: alice
  [1/6] Creating container...
  [2/6] Starting container...
  [3/6] Waiting for network...
  Container IP: 10.0.3.100
  [4/6] Installing Docker, SSH, and tools...
  [5/6] Creating user: alice...
  [6/6] Adding SSH keys (1 keys)...

✓ Container alice-container created successfully!

Container Information:
  Name:         alice-container
  Username:     alice
  IP Address:   10.0.3.100
  State:        Running
  CPU:          4 cores
  Memory:       4GB
  Docker:       true
  Auto-start:   enabled
```

**This takes ~60 seconds** and does everything automatically:
- Creates Ubuntu 24.04 container
- Installs Docker, SSH, sudo, git, vim, etc.
- Creates user `alice` with sudo privileges
- Adds alice to docker group
- Configures SSH key
- Enables auto-start (for spot recovery)

#### 3.3. Create More Containers

```bash
# On jump-1 - Team A
sudo containarium create dave --ssh-key ~/.ssh/dave.pub
sudo containarium create greg --ssh-key ~/.ssh/greg.pub

# List containers
sudo containarium list
# Output:
# CONTAINER NAME         STATUS     IP ADDRESS      CPU/MEMORY
# alice-container        Running    10.0.3.100      4c/4GB
# dave-container         Running    10.0.3.101      4c/4GB
# greg-container         Running    10.0.3.102      4c/4GB
```

For horizontal scaling, repeat on jump-2 and jump-3:

```bash
# SSH to jump-2
ssh admin@35.203.124.46
sudo containarium create bob --ssh-key ~/.ssh/bob.pub
sudo containarium create eve --ssh-key ~/.ssh/eve.pub

# SSH to jump-3
ssh admin@35.203.125.47
sudo containarium create charlie --ssh-key ~/.ssh/charlie.pub
sudo containarium create frank --ssh-key ~/.ssh/frank.pub
```

#### 3.4. Automate Container Creation (Optional)

Create a script to create many containers:

```bash
# create-team-containers.sh
#!/bin/bash

JUMP_SERVER="35.203.123.45"
USERS=("alice" "bob" "charlie" "dave" "eve")

for user in "${USERS[@]}"; do
  echo "Creating container for $user..."
  ssh admin@$JUMP_SERVER "sudo containarium create $user"
done
```

---

### Phase 4: Configure User Access (Per User)

#### 4.1. Get Container IP

From the jump server:

```bash
sudo containarium info alice

# Output shows:
# IP Address: 10.0.3.100
```

#### 4.2. Give Users Their SSH Config

Send this to alice:

```ssh-config
# Add to ~/.ssh/config

# Jump server
Host containarium-jump
    HostName 35.203.123.45
    User admin
    IdentityFile ~/.ssh/id_rsa

# Your dev container
Host my-dev
    HostName 10.0.3.100
    User alice
    ProxyJump containarium-jump
    IdentityFile ~/.ssh/alice_key
```

#### 4.3. User Connects

Alice runs on her laptop:

```bash
ssh my-dev

# Alice is now in her Ubuntu container!
alice@alice-container:~$ docker run hello-world
# Docker works!

alice@alice-container:~$ sudo apt install nodejs
# She has sudo access

alice@alice-container:~$ docker-compose up -d
# Everything works!
```

---

## Complete Workflow Summary

```
┌─────────────────────────────────────────────────────────────┐
│ 1. YOU: terraform apply                                     │
│    → Creates GCE VMs with Incus                             │
│    → Takes 3-5 minutes                                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. YOU: Build containarium CLI                              │
│    → make build-linux                                       │
│    → Takes 30 seconds                                       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. YOU: Copy CLI to jump server(s)                          │
│    → scp + ssh + mv to /usr/local/bin/                     │
│    → One-time setup, takes 1 minute                         │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. YOU: Create containers for users                         │
│    → ssh to jump server                                     │
│    → sudo containarium create <username>                    │
│    → Takes 60 seconds per user                              │
│    → Automated: Docker + SSH + user setup                   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. USERS: SSH to their containers                           │
│    → Configure ~/.ssh/config with ProxyJump                 │
│    → ssh my-dev                                             │
│    → Use Docker, install packages, develop!                 │
└─────────────────────────────────────────────────────────────┘
```

---

## What Each Component Does

### Terraform Startup Script

Located at `terraform/gce/scripts/startup.sh`, this runs **once** when the VM boots:

```bash
# What it does:
1. Updates system packages
2. Installs Incus
3. Initializes Incus (creates storage pool, network)
4. Loads kernel modules (overlay, br_netfilter for Docker)
5. Configures sysctl
6. Hardens SSH
7. Creates admin users
8. Sets up systemd service for container auto-start
```

**You don't run this manually** - Terraform does it automatically.

### Containarium CLI

The `containarium` binary you install:

```bash
# What it does:
containarium create alice
  1. Creates LXC container via Incus API
  2. Starts the container
  3. Waits for network to be ready
  4. Runs apt-get update && apt-get install (Docker, SSH, etc.)
  5. Creates user alice with sudo
  6. Adds SSH keys
  7. Configures auto-start
  8. Returns IP address
```

**You run this** for each user you want to create.

---

## Common Questions

### Q: Do I need to create LXC containers manually?

**A: NO!** The `containarium create` command does it all automatically.

You do **NOT** need to run:
- ❌ `incus launch ubuntu:24.04`
- ❌ `incus config set ...`
- ❌ `incus exec ... apt-get install`

Just run:
- ✅ `containarium create alice --ssh-key ~/.ssh/alice.pub`

### Q: Do I need to install Incus manually?

**A: NO!** Terraform's startup script installs Incus automatically.

When you SSH to the jump server, Incus is already:
- ✅ Installed
- ✅ Initialized
- ✅ Network configured (incusbr0, 10.0.3.0/24)
- ✅ Ready to create containers

### Q: Do I need to copy the binary every time?

**A: NO!** Only once per jump server.

After the first install, you can create unlimited containers:
```bash
sudo containarium create user1
sudo containarium create user2
sudo containarium create user3
# ... etc
```

### Q: What if I update the containarium code?

**A: Rebuild and re-copy the binary:**

```bash
# On local machine
make build-linux

# Copy to jump server
scp bin/containarium-linux-amd64 admin@35.203.123.45:/tmp/
ssh admin@35.203.123.45 "sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium"
```

Existing containers are NOT affected.

### Q: Can I automate the binary deployment?

**A: YES!** Add it to Terraform:

In `terraform/gce/main.tf`, add a `null_resource`:

```hcl
resource "null_resource" "deploy_containarium" {
  depends_on = [google_compute_instance.jump_server]

  provisioner "local-exec" {
    command = <<-EOT
      sleep 30  # Wait for instance to be ready
      scp -o StrictHostKeyChecking=no bin/containarium-linux-amd64 admin@${google_compute_address.jump_server_ip.address}:/tmp/
      ssh -o StrictHostKeyChecking=no admin@${google_compute_address.jump_server_ip.address} "sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium"
    EOT
  }
}
```

**But** you need to build the binary first with `make build-linux` before running `terraform apply`.

---

## Checklist: First Deployment

Use this checklist for your first deployment:

```
Infrastructure:
□ Edited terraform.tfvars with project_id, SSH keys, allowed IPs
□ Ran terraform init
□ Ran terraform apply
□ Saved jump server IP addresses from output

CLI Installation:
□ Ran make build-linux on local machine
□ Copied binary to jump server(s) with scp
□ Moved to /usr/local/bin/containarium on jump server
□ Verified: containarium version works
□ Verified: sudo incus list shows no containers

Container Creation:
□ Decided user distribution across servers
□ Created first test container: sudo containarium create alice
□ Verified container is running: sudo containarium list
□ Got container IP: sudo containarium info alice

User Access:
□ Configured ~/.ssh/config with ProxyJump
□ Tested SSH: ssh alice@<container-ip> (from jump server)
□ Tested SSH with ProxyJump: ssh my-dev (from laptop)
□ Verified Docker works: docker run hello-world
□ Verified sudo works: sudo apt update

Documentation:
□ Documented jump server IPs for team
□ Created user onboarding guide with SSH config
□ Set up container request process
```

---

## Quick Reference Commands

**On your local machine:**
```bash
# Deploy infrastructure
cd terraform/gce && terraform apply

# Build CLI
make build-linux

# Copy to server
scp bin/containarium-linux-amd64 admin@<ip>:/tmp/
```

**On jump server:**
```bash
# Install CLI (one-time)
sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium
sudo chmod +x /usr/local/bin/containarium

# Create containers
sudo containarium create alice --ssh-key ~/.ssh/alice.pub
sudo containarium create bob --ssh-key ~/.ssh/bob.pub

# Manage containers
sudo containarium list
sudo containarium info alice
sudo containarium delete alice

# Direct Incus access (if needed)
sudo incus list
sudo incus exec alice-container -- bash
```

**User's machine:**
```bash
# SSH to container (via ProxyJump)
ssh my-dev

# Or direct (from jump server)
ssh alice@10.0.3.100
```

---

## Next Steps

After successful deployment:

1. **Create containers for all users** on their assigned jump servers
2. **Distribute SSH configs** to users
3. **Monitor resources**: `sudo incus list` on each jump server
4. **Set up backups**: GCE snapshots run automatically (if enabled)
5. **Scale when needed**: Add more jump servers with `jump_server_count = 5`

---

**That's it!** You now have a complete understanding of the deployment workflow.

**Summary**: Terraform creates infrastructure → You copy containarium binary → You create containers → Users SSH to their containers!
