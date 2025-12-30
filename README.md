# Containarium

> SSH Jump Server + LXC Container Platform for Multi-User Development Environments

**Containarium** is a production-ready platform that provides isolated development environments using LXC containers on cloud VMs. It combines infrastructure-as-code (Terraform), type-safe operations (Protobuf + Go), and container efficiency (LXC) to deliver **92% cost savings** compared to traditional VM-per-user approaches.

## 🚀 Key Features

- **💰 Massive Cost Savings**: 92% reduction in cloud costs vs VM-per-user
  - Single VM: **$98/month** for 50 users (vs $1,250 traditional)
  - 3 Servers: **$312/month** for 150 users (vs $3,750 traditional)
- **⚡ Fast Provisioning**: Create isolated environments in < 60 seconds
- **📈 Horizontal Scaling**: Deploy multiple jump servers with load balancing
- **🔒 Strong Isolation**: Unprivileged LXC containers with resource limits
- **🛡️ Secure Multi-Tenant**: Proxy-only jump server accounts (no shell access)
  - Separate jump account per user with `/usr/sbin/nologin`
  - SSH ProxyJump transparency
  - Automatic account lifecycle management
- **🐳 Docker Support**: Each container can run Docker containers
- **☁️ Spot Instances**: 76% cheaper with automatic recovery from termination
- **💾 Persistent Storage**: Containers survive spot instance restarts
- **🏗️ Infrastructure as Code**: Deploy with Terraform (GCE ready, AWS coming)
- **🛠️ Type-Safe**: Protobuf contracts for all operations
- **📦 Unified Binary**: Single binary for local and remote operations
  - **Local Mode**: Direct Incus access via Unix socket
  - **Remote Mode**: gRPC + mTLS from anywhere (CI/CD ready)
  - **Daemon Mode**: Systemd service for remote management

## 📊 Architecture Design

### Overview

Containarium provides a multi-layer architecture combining cloud infrastructure, container management, and secure access:

```
┌─────────────────────────────────────────────────────────────────┐
│                          Users (SSH)                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   GCE Load Balancer (Optional)                   │
│                   • SSH Traffic Distribution                     │
│                   • Health Checks (Port 22)                      │
│                   • Session Affinity                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   Jump Server 1  │  │   Jump Server 2  │  │   Jump Server 3  │
│  (Spot Instance) │  │  (Spot Instance) │  │  (Spot Instance) │
├──────────────────┤  ├──────────────────┤  ├──────────────────┤
│ • Debian 12      │  │ • Debian 12      │  │ • Debian 12      │
│ • Incus LXC      │  │ • Incus LXC      │  │ • Incus LXC      │
│ • ZFS Storage    │  │ • ZFS Storage    │  │ • ZFS Storage    │
│ • Containarium   │  │ • Containarium   │  │ • Containarium   │
└────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
         │                     │                     │
         ▼                     ▼                     ▼
  ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
  │ Persistent  │       │ Persistent  │       │ Persistent  │
  │ Disk (ZFS)  │       │ Disk (ZFS)  │       │ Disk (ZFS)  │
  └─────────────┘       └─────────────┘       └─────────────┘
         │                     │                     │
    ┌────┴────┐           ┌────┴────┐           ┌────┴────┐
    ▼    ▼    ▼           ▼    ▼    ▼           ▼    ▼    ▼
  [C1] [C2] [C3]...     [C1] [C2] [C3]...     [C1] [C2] [C3]...
  50 Containers         50 Containers         50 Containers
```

### Architecture Layers

#### 1. **Infrastructure Layer** (Terraform + GCE)
- **Compute**: Spot instances with persistent disks
- **Storage**: ZFS on dedicated persistent disks (survives termination)
- **Network**: VPC with firewall rules, optional load balancer
- **HA**: Auto-start on boot, snapshot backups

#### 2. **Container Layer** (Incus + LXC)
- **Runtime**: Unprivileged LXC containers
- **Storage**: ZFS with compression (lz4) and quotas
- **Network**: Bridge networking with isolated namespaces
- **Security**: AppArmor profiles, resource limits

#### 3. **Management Layer** (Containarium CLI)
- **Language**: Go with Protobuf contracts
- **Operations**: Create, delete, list, info
- **API**: Local CLI + optional gRPC daemon
- **Automation**: Automated container lifecycle

#### 4. **Access Layer** (SSH)
- **Jump Server**: SSH bastion host
- **ProxyJump**: Transparent container access
- **Authentication**: SSH key-based only
- **Isolation**: Per-user containers

### Component Interaction

```
┌─────────────────────────────────────────────────────────────┐
│ User Machine                                                 │
│                                                              │
│  $ ssh my-dev                                               │
│      │                                                       │
│      └─→ ProxyJump via Jump Server                         │
│             │                                                │
│             └─→ SSH to Container IP (10.0.3.x)             │
│                    │                                         │
│                    └─→ User in isolated Ubuntu container    │
│                           with Docker installed             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Terraform Workflow                                           │
│                                                              │
│  terraform apply                                            │
│      │                                                       │
│      ├─→ Create GCE instances (spot + persistent disk)     │
│      ├─→ Configure ZFS on persistent disk                  │
│      ├─→ Install Incus from official repo                  │
│      ├─→ Setup firewall rules                              │
│      └─→ Optional: Deploy containarium daemon              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Containarium CLI Workflow                                    │
│                                                              │
│  containarium create alice --ssh-key ~/.ssh/alice.pub       │
│      │                                                       │
│      ├─→ Generate container profile (ZFS quota, limits)    │
│      ├─→ Launch Incus container (Ubuntu 24.04)             │
│      ├─→ Configure networking (get IP from pool)           │
│      ├─→ Inject SSH key for user                           │
│      ├─→ Install Docker and dev tools                      │
│      └─→ Return container IP and SSH command               │
└─────────────────────────────────────────────────────────────┘
```

### Deployment Topologies

#### Single Server (20-50 users)

```
Internet
   │
   ▼
┌─────────────────────────────────┐
│ GCE Spot Instance               │
│ • n2-standard-8 (32GB RAM)      │
│ • 100GB boot + 100GB data disk  │
│ • ZFS pool on data disk         │
│ • 50 containers @ 500MB each    │
└─────────────────────────────────┘

Cost: $98/month | $1.96/user
Availability: ~99% (with auto-restart)
```

#### Horizontal Scaling (100-250 users)

```
                  Load Balancer
                  (SSH Port 22)
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
  Jump-1          Jump-2          Jump-3
  (50 users)      (50 users)      (50 users)
     │               │               │
     ▼               ▼               ▼
Persistent-1    Persistent-2    Persistent-3
(100GB ZFS)     (100GB ZFS)     (100GB ZFS)

Cost: $312/month | $2.08/user (150 users)
Availability: 99.9% (multi-server)
```

Each jump server is independent with its own containers and persistent storage.

### Data Flow

#### Container Creation Flow

```
1. User: containarium create alice --ssh-key alice.pub
2. CLI: Read SSH public key from file
3. CLI: Call Incus API to launch container
4. Incus: Pull Ubuntu 24.04 image (cached after first use)
5. Incus: Create ZFS dataset with quota (default 20GB)
6. Incus: Assign IP from pool (10.0.3.x)
7. CLI: Wait for container network ready
8. CLI: Inject SSH key into container
9. CLI: Install Docker and dev tools
10. CLI: Return IP and connection info
```

#### SSH Connection Flow

```
1. User: ssh my-dev (from ~/.ssh/config)
2. SSH: Connect to jump server as alice (ProxyJump)
3. Jump: Authenticate alice's key (proxy-only account, no shell)
4. SSH: Forward connection to container IP (10.0.3.x)
5. Container: Authenticate alice's key (same key!)
6. User: Shell access in isolated container
```

**Secure Multi-Tenant Architecture:**

```
┌──────────────────────────────────────────────────────────────┐
│ User's Local Machine                                          │
│                                                               │
│ ~/.ssh/config:                                               │
│   Host my-dev                                                │
│     HostName 10.0.3.100                                      │
│     User alice                                               │
│     IdentityFile ~/.ssh/containarium  ← ALICE'S KEY          │
│     ProxyJump containarium-jump                              │
│                                                               │
│   Host containarium-jump                                     │
│     HostName 35.229.246.67                                  │
│     User alice                        ← ALICE'S ACCOUNT!     │
│     IdentityFile ~/.ssh/containarium  ← SAME KEY             │
└──────────────────────────────────────────────────────────────┘
                     │
                     │ (1) SSH as alice (proxy-only)
                     ▼
┌──────────────────────────────────────────────────────────────┐
│ GCE Instance (Jump Server)                                   │
│                                                               │
│ /home/admin/.ssh/authorized_keys:                            │
│   ssh-ed25519 AAAA... admin@laptop  ← ADMIN ONLY             │
│   Shell: /bin/bash                   ← FULL ACCESS           │
│                                                               │
│ /home/alice/.ssh/authorized_keys:                            │
│   ssh-ed25519 AAAA... alice@laptop  ← ALICE'S KEY            │
│   Shell: /usr/sbin/nologin           ← NO SHELL ACCESS!      │
│                                                               │
│ /home/bob/.ssh/authorized_keys:                              │
│   ssh-ed25519 AAAA... bob@laptop    ← BOB'S KEY              │
│   Shell: /usr/sbin/nologin           ← NO SHELL ACCESS!      │
│                                                               │
│ ✓ Alice authenticated for proxy only                         │
│ ✗ Cannot execute commands on jump server                     │
│ ✓ ProxyJump forwards connection to container                 │
│ ✓ Audit log: alice@jump-server → 10.0.3.100                 │
└──────────────────────────────────────────────────────────────┘
                     │
                     │ (2) SSH with same key
                     ▼
┌──────────────────────────────────────────────────────────────┐
│ Guest Container (alice-container)                             │
│                                                               │
│ /home/alice/.ssh/authorized_keys:                            │
│   ssh-ed25519 AAAA... alice@laptop  ← SAME KEY               │
│                                                               │
│ ✓ Alice authenticated                                        │
│ ✓ Shell access granted                                       │
│ ✓ Audit log: alice@alice-container                           │
└──────────────────────────────────────────────────────────────┘
```

**Security Architecture:**
- **Separate accounts**: Each user has their own account on jump server
- **No shell access**: User accounts use `/usr/sbin/nologin` (proxy-only)
- **Same key**: Users use one key for both jump server and container
- **Admin isolation**: Only admin can access jump server shell
- **Audit trail**: Each user's connections logged separately
- **DDoS protection**: fail2ban can block malicious users per account
- **Zero trust**: Users cannot see other containers or inspect system

#### Spot Instance Recovery Flow

```
1. GCE: Spot instance terminated (preemption)
2. GCE: Persistent disk detached (data preserved)
3. GCE: Instance restarts (within 5 minutes)
4. Startup: Mount persistent disk to /var/lib/incus
5. Startup: Import existing ZFS pool (incus-pool)
6. Incus: Auto-start containers (boot.autostart=true)
7. Total downtime: 2-5 minutes
8. Data: 100% preserved
```

## 🎯 Use Cases

- **Development Teams**: Isolated dev environments for each developer (100+ users)
- **Training & Education**: Spin up temporary environments for students
- **CI/CD Runners**: Ephemeral build and test environments
- **Testing**: Isolated test environments with Docker support
- **Multi-Tenancy**: Safe isolation between users, teams, or projects

## 💰 Cost Comparison

| Users | Traditional VMs | Containarium | Savings |
|-------|----------------|-------------|---------|
| 50 | $1,250/mo | **$98/mo** | **92%** |
| 150 | $3,750/mo | **$312/mo** | **92%** |
| 250 | $6,250/mo | **$508/mo** | **92%** |

**How?**
- LXC containers: 10x more density than VMs
- Spot instances: 76% cheaper than regular VMs
- Persistent disks: Survive spot termination
- Single infrastructure: No VM-per-user overhead

## 📦 Quick Start

### 1. Deploy Infrastructure

Choose your deployment size:

**Small Team (20-50 users)**:
```bash
cd terraform/gce
cp examples/single-server-spot.tfvars terraform.tfvars
vim terraform.tfvars  # Add your project_id and SSH keys
terraform init
terraform apply
```

**Medium Team (100-150 users)**:
```bash
cp examples/horizontal-scaling-3-servers.tfvars terraform.tfvars
vim terraform.tfvars  # Configure
terraform apply
```

**Large Team (200-250 users)**:
```bash
cp examples/horizontal-scaling-5-servers.tfvars terraform.tfvars
terraform apply
```

### 2. Build and Deploy CLI

**Option A: Deploy for Local Mode (SSH to server)**
```bash
# Build containarium CLI for Linux
make build-linux

# Copy to jump server(s)
scp bin/containarium-linux-amd64 admin@<jump-server-ip>:/tmp/
ssh admin@<jump-server-ip>
sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium
sudo chmod +x /usr/local/bin/containarium
```

**Option B: Setup for Remote Mode (Run from anywhere)**
```bash
# Build containarium for your platform
make build  # macOS/Linux on your laptop

# Setup daemon on server
scp bin/containarium-linux-amd64 admin@<jump-server-ip>:/tmp/
ssh admin@<jump-server-ip>
sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium
sudo chmod +x /usr/local/bin/containarium

# Generate mTLS certificates
sudo containarium cert generate \
    --server-ip <jump-server-ip> \
    --output-dir /etc/containarium/certs

# Start daemon (via systemd or manually)
sudo systemctl start containarium

# Copy client certificates to your machine
exit
mkdir -p ~/.config/containarium/certs
scp admin@<jump-server-ip>:/etc/containarium/certs/{ca.crt,client.crt,client.key} \
    ~/.config/containarium/certs/
```

### 3. Create Containers

**Option A: Local Mode (SSH to server)**
```bash
# SSH to jump server
ssh admin@<jump-server-ip>

# Create container for a user
sudo containarium create alice --ssh-key ~/.ssh/alice.pub

# Output:
# ✓ Creating container for user: alice
# ✓ [1/7] Creating container...
# ✓ [2/7] Starting container...
# ✓ [3/7] Creating jump server account (proxy-only)...
#   ✓ Jump server account created: alice (no shell access, proxy-only)
# ✓ [4/7] Waiting for network...
#   Container IP: 10.0.3.100
# ✓ [5/7] Installing Docker, SSH, and tools...
# ✓ [6/7] Creating user: alice...
# ✓ [7/7] Adding SSH keys (including jump server key for ProxyJump)...
# ✓ Container alice-container created successfully!
#
# Container Details:
#   Name: alice-container
#   User: alice
#   IP: 10.0.3.100
#   Disk: 50GB
#   Auto-start: enabled
#
# Jump Server Account (Secure Multi-Tenant):
#   Username: alice
#   Shell: /usr/sbin/nologin (proxy-only, no shell access)
#   SSH ProxyJump: enabled
#
# SSH Access (via ProxyJump):
#   ssh alice-dev  # (after SSH config setup)

# List containers
sudo containarium list
# +------------------+---------+----------------------+------+-----------+
# | NAME             | STATE   | IPV4                 | TYPE | SNAPSHOTS |
# +------------------+---------+----------------------+------+-----------+
# | alice-container  | RUNNING | 10.0.3.100 (eth0)    | C    | 0         |
# +------------------+---------+----------------------+------+-----------+
```

**Option B: Remote Mode (from your laptop)**
```bash
# No SSH required - direct gRPC call with mTLS
containarium create alice --ssh-key ~/.ssh/alice.pub \
    --server 35.229.246.67:50051 \
    --certs-dir ~/.config/containarium/certs \
    --cpu 4 --memory 8GB -v

# List containers remotely
containarium list \
    --server 35.229.246.67:50051 \
    --certs-dir ~/.config/containarium/certs

# Export SSH config remotely (run on server)
ssh admin@<jump-server-ip>
sudo containarium export alice --jump-ip 35.229.246.67 >> ~/.ssh/config
```

### 4. Setup SSH Keys for Users

Each user needs their own SSH key pair for container access.

**User generates SSH key (on their local machine):**

```bash
# Generate new SSH key pair
ssh-keygen -t ed25519 -C "alice@company.com" -f ~/.ssh/containarium_alice

# Output:
# ~/.ssh/containarium_alice      (private key - keep secret!)
# ~/.ssh/containarium_alice.pub  (public key - share with admin)
```

**Admin creates container with user's public key:**

```bash
# User sends their public key to admin
# Admin receives: alice_id_ed25519.pub

# SSH to jump server
ssh admin@<jump-server-ip>

# Create container with user's public key
sudo containarium create alice --ssh-key /path/to/alice_id_ed25519.pub

# Or if key is on admin's local machine, copy it first:
scp alice_id_ed25519.pub admin@<jump-server-ip>:/tmp/
ssh admin@<jump-server-ip>
sudo containarium create alice --ssh-key /tmp/alice_id_ed25519.pub
```

### 5. User Access (SSH ProxyJump) - Secure Multi-Tenant Architecture

**Containarium implements a secure proxy-only jump server architecture:**

#### Security Model
- ✅ Each user has a **separate jump server account** with `/usr/sbin/nologin` shell
- ✅ Jump server accounts are **proxy-only** (no direct shell access)
- ✅ SSH ProxyJump works transparently through the jump server
- ✅ Users cannot access jump server data or see other users
- ✅ Automatic jump server account creation when container is created
- ✅ Jump server accounts deleted when container is deleted

#### Architecture Flow
```
User's Laptop                Jump Server                Container
     │                            │                         │
     │   SSH to alice-jump       │                         │
     ├──────────────────────────>│ (alice account:       │
     │   (ProxyJump)              │  /usr/sbin/nologin)   │
     │                            │  ┌─> Blocks shell     │
     │                            │  └─> Allows proxy     │
     │                            │         │              │
     │                            │         │  SSH forward │
     │                            │         └─────────────>│
     │                                                      │
     │   Direct SSH to container (10.0.3.100)             │
     │<────────────────────────────────────────────────────┘
```

**Users configure SSH on their local machine:**

Add to `~/.ssh/config`:

```ssh-config
# Jump server (proxy-only account - NO shell access)
Host containarium-jump
    HostName <jump-server-ip>
    User alice  # Each user has their own jump account
    IdentityFile ~/.ssh/containarium_alice

# Your dev container
Host alice-dev
    HostName 10.0.3.100
    User alice
    IdentityFile ~/.ssh/containarium_alice
    ProxyJump containarium-jump
    StrictHostKeyChecking accept-new
```

**Test the setup:**
```bash
# This will FAIL (proxy-only account - no shell)
ssh containarium-jump
# Output: "This account is currently not available."

# This WORKS (ProxyJump to container)
ssh alice-dev
# Output: alice@alice-container:~$
```

**Connect:**
```bash
ssh my-dev
# Alice is now in her Ubuntu container with Docker!

# First connection will ask to verify host key:
# The authenticity of host '10.0.3.100 (<no hostip for proxy command>)' can't be established.
# ED25519 key fingerprint is SHA256:...
# Are you sure you want to continue connecting (yes/no)? yes
```

### 6. Managing SSH Keys in Containers

#### Add Additional SSH Keys (After Container Creation)

```bash
# Method 1: Using incus exec
sudo incus exec alice-container -- bash -c "echo 'ssh-ed25519 AAAA...' >> /home/alice/.ssh/authorized_keys"

# Method 2: Using incus file push
echo 'ssh-ed25519 AAAA...' > /tmp/new_key.pub
sudo incus file push /tmp/new_key.pub alice-container/home/alice/.ssh/authorized_keys --mode 0600 --uid 1000 --gid 1000

# Method 3: SSH into container and add manually
ssh alice@10.0.3.100   # (from jump server)
echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys
```

#### Replace SSH Key

```bash
# Overwrite authorized_keys with new key
echo 'ssh-ed25519 NEW_KEY_AAAA...' | sudo incus exec alice-container -- \
  tee /home/alice/.ssh/authorized_keys > /dev/null

# Set correct permissions
sudo incus exec alice-container -- chown alice:alice /home/alice/.ssh/authorized_keys
sudo incus exec alice-container -- chmod 600 /home/alice/.ssh/authorized_keys
```

#### Remove SSH Key

```bash
# Edit authorized_keys file
sudo incus exec alice-container -- bash -c \
  "sed -i '/alice@old-laptop/d' /home/alice/.ssh/authorized_keys"
```

#### View Current SSH Keys

```bash
# List all authorized keys for a user
sudo incus exec alice-container -- cat /home/alice/.ssh/authorized_keys
```

## 🏗️ Project Structure

```
Containarium/
├── proto/                   # Protobuf contracts (type-safe)
│   └── containarium/v1/
│       ├── container.proto  # Container operations
│       └── config.proto     # System configuration
│
├── cmd/containarium/        # CLI entry point
├── internal/
│   ├── cmd/                 # CLI commands (create, list, delete, info)
│   ├── container/           # Container management logic
│   ├── incus/               # Incus API wrapper
│   └── ssh/                 # SSH key management
│
├── terraform/
│   ├── gce/                 # GCP deployment
│   │   ├── main.tf          # Main infrastructure
│   │   ├── horizontal-scaling.tf # Multi-server setup
│   │   ├── spot-instance.tf # Spot VM + persistent disk
│   │   ├── examples/        # Ready-to-use configurations
│   │   └── scripts/         # Startup scripts
│   └── embed/               # Terraform file embedding for tests
│       ├── terraform.go     # go:embed declarations
│       └── README.md        # Embedding documentation
│
├── test/integration/        # E2E tests
│   ├── e2e_terraform_test.go # Terraform-based E2E tests
│   ├── e2e_reboot_test.go   # gcloud-based E2E tests
│   ├── TERRAFORM-E2E.md     # Terraform testing guide
│   └── E2E-README.md        # gcloud testing guide
│
├── docs/                    # Documentation
│   ├── HORIZONTAL-SCALING-QUICKSTART.md
│   ├── SSH-JUMP-SERVER-SETUP.md
│   └── SPOT-INSTANCES-AND-SCALING.md
│
├── Makefile                 # Build automation
└── IMPLEMENTATION-PLAN.md   # Detailed roadmap
```

## 🛠️ Development

### Build Commands

```bash
# Show all commands
make help

# Build for current platform
make build

# Build for Linux (deployment)
make build-linux

# Generate protobuf code
make proto

# Run tests
make test

# Run E2E tests (requires GCP credentials)
export GCP_PROJECT=your-project-id
make test-e2e

# Lint and format
make lint fmt
```

### Local Testing

```bash
# Build and run locally
make run-local

# Test commands
./bin/containarium create alice
./bin/containarium list
./bin/containarium info alice
```

## 🧪 Testing Architecture

Containarium uses a comprehensive testing strategy with real infrastructure validation:

### E2E Testing with Terraform

The E2E test suite leverages the same Terraform configuration used for production deployments:

```
test/integration/
├── e2e_terraform_test.go    # Terraform-based E2E tests
├── e2e_reboot_test.go       # Alternative gcloud-based tests
├── TERRAFORM-E2E.md         # Terraform E2E documentation
└── E2E-README.md            # gcloud E2E documentation

terraform/embed/
├── terraform.go             # Embeds Terraform files (go:embed)
└── README.md                # Embedding documentation
```

**Key Features:**
- ✅ **go:embed Integration**: Terraform files embedded in test binary for portability
- ✅ **ZFS Persistence**: Verifies data survives spot instance reboots
- ✅ **No Hardcoded Values**: All configuration from Terraform outputs
- ✅ **Reproducible**: Same Terraform config as production
- ✅ **Automatic Cleanup**: Infrastructure destroyed after tests

**Running E2E Tests:**

```bash
# Set GCP project
export GCP_PROJECT=your-gcp-project-id

# Run full E2E test (25-30 min)
make test-e2e

# Test workflow:
# 1. Deploy infrastructure with Terraform
# 2. Wait for instance ready
# 3. Verify ZFS setup
# 4. Create container with test data
# 5. Reboot instance (stop/start)
# 6. Verify data persisted
# 7. Cleanup infrastructure
```

**Test Reports:**
- Creates temporary Terraform workspace
- Verifies ZFS pool status
- Validates container quota enforcement
- Confirms data persistence across reboots

See [test/integration/TERRAFORM-E2E.md](test/integration/TERRAFORM-E2E.md) for detailed documentation.

## 🔒 Security: Audit Logging & Intrusion Prevention

### Audit Logging

With separate user accounts, every SSH connection is logged with the actual username:

**SSH Audit Logs** (`/var/log/auth.log`):
```bash
# Alice connects to her container
Jan 10 14:23:15 jump-server sshd[12345]: Accepted publickey for alice from 203.0.113.10
Jan 10 14:23:15 jump-server sshd[12345]: pam_unix(sshd:session): session opened for user alice

# Bob connects to his container
Jan 10 14:25:32 jump-server sshd[12346]: Accepted publickey for bob from 203.0.113.11
Jan 10 14:25:32 jump-server sshd[12346]: pam_unix(sshd:session): session opened for user bob

# Failed login attempt
Jan 10 14:30:01 jump-server sshd[12347]: Failed publickey for charlie from 203.0.113.12
Jan 10 14:30:05 jump-server sshd[12348]: Failed publickey for charlie from 203.0.113.12
Jan 10 14:30:09 jump-server sshd[12349]: Failed publickey for charlie from 203.0.113.12
```

**View Audit Logs:**

```bash
# SSH to jump server as admin
ssh admin@<jump-server-ip>

# View all SSH connections
sudo journalctl -u sshd -f

# View connections for specific user
sudo journalctl -u sshd | grep "for alice"

# View failed login attempts
sudo journalctl -u sshd | grep "Failed"

# View connections from specific IP
sudo journalctl -u sshd | grep "from 203.0.113.10"

# Export logs for security audit
sudo journalctl -u sshd --since "2025-01-01" --until "2025-01-31" > ssh-audit-jan-2025.log
```

### fail2ban Configuration

Automatically block brute force attacks and unauthorized access attempts:

**Install fail2ban** (added to startup script):

```bash
# Automatically installed by Terraform startup script
sudo apt install -y fail2ban
```

**Configure fail2ban for SSH** (`/etc/fail2ban/jail.d/sshd.conf`):

```ini
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3          # Block after 3 failed attempts
findtime = 600        # Within 10 minutes
bantime = 3600        # Ban for 1 hour
banaction = iptables-multiport
```

**Monitor fail2ban:**

```bash
# Check fail2ban status
sudo fail2ban-client status

# Check SSH jail status
sudo fail2ban-client status sshd

# Output:
# Status for the jail: sshd
# |- Filter
# |  |- Currently failed:  2
# |  |- Total failed:      15
# |  `- File list:         /var/log/auth.log
# `- Actions
#    |- Currently banned:  1
#    |- Total banned:      3
#    `- Banned IP list:    203.0.113.12

# View banned IPs
sudo fail2ban-client get sshd banip

# Unban IP manually (if needed)
sudo fail2ban-client set sshd unbanip 203.0.113.12
```

**fail2ban Logs:**

```bash
# View fail2ban activity
sudo tail -f /var/log/fail2ban.log

# Example output:
# 2025-01-10 14:30:15,123 fail2ban.filter  [12345]: INFO    [sshd] Found 203.0.113.12 - 2025-01-10 14:30:09
# 2025-01-10 14:30:20,456 fail2ban.actions [12346]: NOTICE  [sshd] Ban 203.0.113.12
# 2025-01-10 15:30:20,789 fail2ban.actions [12347]: NOTICE  [sshd] Unban 203.0.113.12
```

### Security Monitoring Dashboard

**Create monitoring script** (`/usr/local/bin/security-monitor.sh`):

```bash
#!/bin/bash

echo "=== Containarium Security Status ==="
echo ""

echo "📊 Active SSH Sessions:"
who
echo ""

echo "🚫 Banned IPs (fail2ban):"
sudo fail2ban-client status sshd | grep "Banned IP"
echo ""

echo "⚠️  Recent Failed Login Attempts:"
sudo journalctl -u sshd --since "1 hour ago" | grep "Failed" | tail -10
echo ""

echo "✅ Successful Logins (last hour):"
sudo journalctl -u sshd --since "1 hour ago" | grep "Accepted publickey" | tail -10
echo ""

echo "👥 Unique Users Connected Today:"
sudo journalctl -u sshd --since "today" | grep "Accepted publickey" | \
  awk '{print $9}' | sort -u
```

**Run monitoring:**

```bash
# Make executable
sudo chmod +x /usr/local/bin/security-monitor.sh

# Run manually
sudo /usr/local/bin/security-monitor.sh

# Add to cron for daily reports
echo "0 9 * * * /usr/local/bin/security-monitor.sh | mail -s 'Daily Security Report' admin@company.com" | sudo crontab -
```

### Per-User Connection Tracking

Since each user has their own account, you can track:

**User-specific metrics:**

```bash
# Count connections per user
sudo journalctl -u sshd --since "today" | grep "Accepted publickey" | \
  awk '{print $9}' | sort | uniq -c | sort -rn

# Output:
#  45 alice
#  32 bob
#  18 charlie
#   5 david

# View all of Alice's connections
sudo journalctl -u sshd | grep "for alice" | grep "Accepted publickey"

# Find when Bob last connected
sudo journalctl -u sshd | grep "for bob" | grep "Accepted publickey" | tail -1
```

### DDoS Protection Benefits

With separate accounts, DDoS attacks are isolated:

**Scenario: Alice's laptop is compromised and spams connections**

```bash
# fail2ban detects excessive failed attempts from alice's IP
2025-01-10 15:00:00 fail2ban.filter [12345]: INFO [sshd] Found alice from 203.0.113.10
2025-01-10 15:00:05 fail2ban.filter [12346]: INFO [sshd] Found alice from 203.0.113.10
2025-01-10 15:00:10 fail2ban.filter [12347]: INFO [sshd] Found alice from 203.0.113.10
2025-01-10 15:00:15 fail2ban.actions [12348]: NOTICE [sshd] Ban 203.0.113.10

# Result:
# ✅ Alice's IP is banned (her laptop is blocked)
# ✅ Bob, Charlie, and other users are NOT affected
# ✅ Service continues for everyone else
# ✅ Admin can investigate Alice's account specifically
```

**Without separate accounts (everyone uses 'admin'):**
```bash
# ❌ Can't tell which user is causing the issue
# ❌ Banning the IP might affect legitimate users behind NAT
# ❌ No per-user accountability
```

### Compliance & Security Audits

Export security logs for compliance:

```bash
# Export all SSH activity for user 'alice' in January
sudo journalctl -u sshd --since "2025-01-01" --until "2025-02-01" | \
  grep "for alice" > alice-ssh-audit-jan-2025.log

# Export all failed login attempts
sudo journalctl -u sshd --since "2025-01-01" --until "2025-02-01" | \
  grep "Failed" > failed-logins-jan-2025.log

# Export fail2ban bans
sudo fail2ban-client get sshd banhistory > ban-history-jan-2025.log
```

### Best Practices

1. **Regular Log Reviews**: Check logs weekly for suspicious activity
2. **fail2ban Tuning**: Adjust `maxretry` and `bantime` based on your security needs
3. **Alert on Anomalies**: Set up alerts for unusual patterns (100+ connections from one user)
4. **Log Retention**: Keep logs for at least 90 days for compliance
5. **Separate Admin Access**: Never use user accounts for admin tasks
6. **Monitor fail2ban**: Ensure fail2ban service is always running

## 👥 User Onboarding Workflow

Complete end-to-end workflow for adding a new user:

### Step 1: User Generates SSH Key Pair

**User (on their local machine):**

```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "alice@company.com" -f ~/.ssh/containarium_alice

# Output:
# Generating public/private ed25519 key pair.
# Enter passphrase (empty for no passphrase): [optional]
# Your identification has been saved in ~/.ssh/containarium_alice
# Your public key has been saved in ~/.ssh/containarium_alice.pub

# View and copy public key to send to admin
cat ~/.ssh/containarium_alice.pub
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqL+XYZ... alice@company.com
```

### Step 2: Admin Creates Container

**Admin receives public key and creates container:**

```bash
# Save user's public key to file
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqL... alice@company.com' > /tmp/alice.pub

# SSH to jump server
ssh admin@<jump-server-ip>

# Create container with user's public key
# This automatically:
#   1. Creates jump server account for alice (proxy-only, no shell)
#   2. Creates alice-container with SSH access
#   3. Sets up SSH keys for both
sudo containarium create alice --ssh-key /tmp/alice.pub

# Output:
# ✓ Creating jump server account: alice (proxy-only)
# ✓ Creating container for user: alice
# ✓ Container started: alice-container
# ✓ IP Address: 10.0.3.100
# ✓ Installing Docker and dev tools
# ✓ Container alice-container created successfully!
#
# ✓ Jump server account: alice@35.229.246.67 (proxy-only, no shell)
# ✓ Container access: alice@10.0.3.100
#
# Send this to user:
#   Jump Server: 35.229.246.67 (user: alice)
#   Container IP: 10.0.3.100
#   Username: alice

# Enable auto-start for spot instance recovery
sudo incus config set alice-container boot.autostart true
```

### Step 3: Admin Sends Connection Info to User

**Method 1: Export SSH Config (Recommended)**

```bash
# Admin exports SSH configuration
sudo containarium export alice --jump-ip 35.229.246.67 --key ~/.ssh/containarium_alice > alice-ssh-config.txt

# Send alice-ssh-config.txt to user via email/Slack
```

**Method 2: Manual SSH Config**

**Admin sends to user via email/Slack:**

```
Your development container is ready!

Jump Server IP: 35.229.246.67
Your Username: alice (for both jump server and container)
Container IP: 10.0.3.100

Add this to your ~/.ssh/config:

Host containarium-jump
    HostName 35.229.246.67
    User alice                              # ← Your own username!
    IdentityFile ~/.ssh/containarium_alice

Host alice-dev
    HostName 10.0.3.100
    User alice                              # ← Same username
    IdentityFile ~/.ssh/containarium_alice  # ← Same key
    ProxyJump containarium-jump

Then connect with: ssh alice-dev

Note: Your jump server account is proxy-only (no shell access).
You can only access your container, not the jump server itself.
```

### Step 4: User Configures SSH and Connects

**User (on their local machine):**

**Method 1: Using Exported Config (Recommended)**

```bash
# Add exported config to your SSH config
cat alice-ssh-config.txt >> ~/.ssh/config

# Connect to container
ssh alice-dev

# You're now in your container!
alice@alice-container:~$ docker run hello-world
alice@alice-container:~$ sudo apt install vim git tmux
```

**Method 2: Manual Configuration**

```bash
# Add to ~/.ssh/config
vim ~/.ssh/config

# Paste the configuration provided by admin

# Connect to container
ssh alice-dev

# First time: verify host key
# The authenticity of host '10.0.3.100' can't be established.
# ED25519 key fingerprint is SHA256:...
# Are you sure you want to continue connecting (yes/no)? yes

# You're now in your container!
alice@alice-container:~$ docker run hello-world
alice@alice-container:~$ sudo apt install vim git tmux
```

### Step 5: User Adds Additional Devices (Optional)

**User wants to access from second laptop:**

```bash
# On second laptop, generate new key
ssh-keygen -t ed25519 -C "alice@home-laptop" -f ~/.ssh/containarium_alice_home

# Send new public key to admin
cat ~/.ssh/containarium_alice_home.pub
```

**Admin adds second key:**

```bash
# Add second key to container (keeps existing keys)
NEW_KEY='ssh-ed25519 AAAAC3... alice@home-laptop'
sudo incus exec alice-container -- bash -c \
  "echo '$NEW_KEY' >> /home/alice/.ssh/authorized_keys"
```

**User can now connect from both laptops!**

## 📚 CLI Command Reference

Containarium provides a simple, intuitive CLI for container management.

### Unified Binary Architecture

**Containarium uses a single binary that operates in two modes:**

#### 🖥️ **Local Mode** (Direct Incus Access)
```bash
# Execute directly on the jump server (requires sudo)
sudo containarium create alice --ssh-key ~/.ssh/alice.pub
sudo containarium list
sudo containarium delete bob
```
- ✅ Direct Incus API access via Unix socket
- ✅ No daemon required
- ✅ Fastest execution
- ❌ Must be run on the server
- ❌ Requires sudo/root privileges

#### 🌐 **Remote Mode** (gRPC + mTLS)
```bash
# Execute from anywhere (laptop, CI/CD, etc.)
containarium create alice --ssh-key ~/.ssh/alice.pub \
    --server 35.229.246.67:50051 \
    --certs-dir ~/.config/containarium/certs

containarium list --server 35.229.246.67:50051 \
    --certs-dir ~/.config/containarium/certs
```
- ✅ Remote execution from any machine
- ✅ Secure mTLS authentication
- ✅ No SSH required
- ✅ Perfect for automation/CI/CD
- ❌ Requires daemon running on server
- ❌ Requires certificate setup

#### 🔄 **Daemon Mode** (Server Component)
```bash
# Run as systemd service on the jump server
containarium daemon --address 0.0.0.0 --port 50051 --mtls

# Systemd service configuration
sudo systemctl start containarium
sudo systemctl enable containarium
sudo systemctl status containarium
```
- Listens on port 50051 (gRPC)
- Enforces mTLS client authentication
- Manages concurrent container operations
- Automatically started via systemd

### Certificate Setup for Remote Mode

**Generate mTLS certificates:**
```bash
# On server: Generate server and client certificates
containarium cert generate \
    --server-ip 35.229.246.67 \
    --output-dir /etc/containarium/certs

# Copy client certificates to local machine
scp admin@35.229.246.67:/etc/containarium/certs/{ca.crt,client.crt,client.key} \
    ~/.config/containarium/certs/
```

**Verify connection:**
```bash
# Test remote connection
containarium list \
    --server 35.229.246.67:50051 \
    --certs-dir ~/.config/containarium/certs
```

### Basic Commands

#### Create Container

```bash
# Basic usage
sudo containarium create <username> --ssh-key <path-to-public-key>

# Example
sudo containarium create alice --ssh-key ~/.ssh/alice.pub

# With custom disk quota
sudo containarium create bob --ssh-key ~/.ssh/bob.pub --disk-quota 50GB

# Enable auto-start on boot
sudo containarium create charlie --ssh-key ~/.ssh/charlie.pub --autostart
```

**Output:**
```
✓ Creating container for user: alice
✓ Launching Ubuntu 24.04 container
✓ Container started: alice-container
✓ IP Address: 10.0.3.100
✓ Installing Docker and dev tools
✓ Configuring SSH access
✓ Container alice-container created successfully!

Container Details:
  Name: alice-container
  User: alice
  IP: 10.0.3.100
  Disk Quota: 20GB (ZFS)
  SSH: ssh alice@10.0.3.100
```

#### List Containers

```bash
# List all containers
sudo containarium list

# Example output
NAME              STATUS    IP            QUOTA   AUTOSTART
alice-container   Running   10.0.3.100    20GB    Yes
bob-container     Running   10.0.3.101    50GB    Yes
charlie-container Stopped   -             20GB    No
```

#### Get Container Info

```bash
# Get detailed information
sudo containarium info alice

# Example output
Container: alice-container
Status: Running
User: alice
IP Address: 10.0.3.100
Disk Quota: 20GB
Disk Used: 4.2GB (21%)
Memory: 512MB / 2GB
CPU Usage: 5%
Uptime: 3 days
Auto-start: Enabled
```

#### Delete Container

```bash
# Delete container (with confirmation)
sudo containarium delete alice

# Force delete (no confirmation)
sudo containarium delete bob --force

# Delete with data backup
sudo containarium delete charlie --backup
```

#### Export SSH Configuration

```bash
# Export to stdout (copy/paste to ~/.ssh/config)
sudo containarium export alice --jump-ip 35.229.246.67

# Export to file
sudo containarium export alice --jump-ip 35.229.246.67 --output ~/.ssh/config.d/containarium-alice

# With custom SSH key path
sudo containarium export alice --jump-ip 35.229.246.67 --key ~/.ssh/containarium_alice

# Append directly to SSH config
sudo containarium export alice --jump-ip 35.229.246.67 >> ~/.ssh/config
```

**Output:**
```
# Containarium SSH Configuration
# User: alice
# Generated: 2026-01-10 08:43:18

# Jump server (GCE instance with proxy-only account)
Host containarium-jump
    HostName 35.229.246.67
    User alice
    IdentityFile ~/.ssh/containarium_alice
    # No shell access - proxy-only account

# User's development container
Host alice-dev
    HostName 10.0.3.100
    User alice
    IdentityFile ~/.ssh/containarium_alice
    ProxyJump containarium-jump
```

**Usage:**
```bash
# After exporting, connect with:
ssh alice-dev
```

### SSH Key Management

#### Generate SSH Keys for Users

```bash
# User generates their own key pair
ssh-keygen -t ed25519 -C "user@company.com" -f ~/.ssh/containarium

# Output files:
# ~/.ssh/containarium      (private - never share!)
# ~/.ssh/containarium.pub  (public - give to admin)

# View public key (to send to admin)
cat ~/.ssh/containarium.pub
```

#### Create Container with Custom SSH Key

```bash
# Method 1: Admin has key file locally
sudo containarium create alice --ssh-key /path/to/alice.pub

# Method 2: Admin receives key via secure channel
# User sends their public key:
cat ~/.ssh/containarium.pub
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqL... alice@company.com

# Admin creates container with key inline
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqL... alice@company.com' > /tmp/alice.pub
sudo containarium create alice --ssh-key /tmp/alice.pub

# Method 3: Multiple users with different keys
sudo containarium create alice --ssh-key /tmp/alice.pub
sudo containarium create bob --ssh-key /tmp/bob.pub
sudo containarium create charlie --ssh-key /tmp/charlie.pub
```

#### Add SSH Key to Existing Container

```bash
# Add additional key (keep existing keys)
NEW_KEY='ssh-ed25519 AAAAC3... user@laptop'
sudo incus exec alice-container -- bash -c \
  "echo '$NEW_KEY' >> /home/alice/.ssh/authorized_keys"

# Verify key was added
sudo incus exec alice-container -- cat /home/alice/.ssh/authorized_keys
```

#### Replace SSH Key

```bash
# Replace all keys with new key
NEW_KEY='ssh-ed25519 AAAAC3... alice@new-laptop'
echo "$NEW_KEY" | sudo incus exec alice-container -- \
  tee /home/alice/.ssh/authorized_keys > /dev/null

# Fix permissions
sudo incus exec alice-container -- chown alice:alice /home/alice/.ssh/authorized_keys
sudo incus exec alice-container -- chmod 600 /home/alice/.ssh/authorized_keys
```

#### Manage Multiple SSH Keys per User

```bash
# Add work laptop key
WORK_KEY='ssh-ed25519 AAAAC3... alice@work-laptop'
sudo incus exec alice-container -- bash -c \
  "echo '$WORK_KEY' >> /home/alice/.ssh/authorized_keys"

# Add home laptop key
HOME_KEY='ssh-ed25519 AAAAC3... alice@home-laptop'
sudo incus exec alice-container -- bash -c \
  "echo '$HOME_KEY' >> /home/alice/.ssh/authorized_keys"

# View all keys
sudo incus exec alice-container -- cat /home/alice/.ssh/authorized_keys
# ssh-ed25519 AAAAC3... alice@work-laptop
# ssh-ed25519 AAAAC3... alice@home-laptop
```

#### Remove Specific SSH Key

```bash
# Remove key by comment (last part of key)
sudo incus exec alice-container -- bash -c \
  "sed -i '/alice@old-laptop/d' /home/alice/.ssh/authorized_keys"

# Remove key by fingerprint pattern
sudo incus exec alice-container -- bash -c \
  "sed -i '/AAAAC3NzaC1lZDI1NTE5AAAAIAbc123/d' /home/alice/.ssh/authorized_keys"
```

#### Troubleshoot SSH Key Issues

```bash
# Check authorized_keys permissions
sudo incus exec alice-container -- ls -la /home/alice/.ssh/
# Should show:
# drwx------ 2 alice alice 4096 ... .ssh
# -rw------- 1 alice alice  123 ... authorized_keys

# Fix permissions if wrong
sudo incus exec alice-container -- chown -R alice:alice /home/alice/.ssh
sudo incus exec alice-container -- chmod 700 /home/alice/.ssh
sudo incus exec alice-container -- chmod 600 /home/alice/.ssh/authorized_keys

# Test SSH from jump server
ssh -v alice@10.0.3.100
# -v shows verbose output for debugging

# Check SSH logs in container
sudo incus exec alice-container -- tail -f /var/log/auth.log
```

### Advanced Operations

#### Using Incus Directly

```bash
# Execute command in container
sudo incus exec alice-container -- df -h

# Shell into container
sudo incus exec alice-container -- su - alice

# View container logs
sudo incus console alice-container --show-log

# Snapshot container
sudo incus snapshot alice-container snap1

# Restore snapshot
sudo incus restore alice-container snap1

# Copy container
sudo incus copy alice-container alice-backup
```

#### Resource Management

```bash
# Set memory limit
sudo incus config set alice-container limits.memory 4GB

# Set CPU limit
sudo incus config set alice-container limits.cpu 2

# View container metrics
sudo incus info alice-container

# Resize disk quota
sudo containarium resize alice --disk-quota 100GB
```

### Terraform Commands

#### Deploy Infrastructure

```bash
cd terraform/gce

# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Deploy infrastructure
terraform apply

# Deploy with custom variables
terraform apply -var-file=examples/horizontal-scaling-3-servers.tfvars

# Show outputs
terraform output

# Get specific output
terraform output jump_server_ip
```

#### Manage Infrastructure

```bash
# Update infrastructure
terraform apply

# Destroy specific resource
terraform destroy -target=google_compute_instance.jump_server_spot[0]

# Destroy everything
terraform destroy

# Import existing resource
terraform import google_compute_instance.jump_server projects/my-project/zones/us-central1-a/instances/my-instance

# Refresh state
terraform refresh
```

### Maintenance Commands

#### Backup and Recovery

```bash
# Backup ZFS pool
sudo zfs snapshot incus-pool@backup-$(date +%Y%m%d)

# List snapshots
sudo zfs list -t snapshot

# Rollback to snapshot
sudo zfs rollback incus-pool@backup-20240115

# Export container
sudo incus export alice-container alice-backup.tar.gz

# Import container
sudo incus import alice-backup.tar.gz
```

#### Monitoring

```bash
# Check ZFS pool status
sudo zpool status

# Check disk usage
sudo zfs list

# Check container resource usage
sudo incus list --columns ns4mDcup

# View system load
htop

# Check Incus daemon status
sudo systemctl status incus
```

#### Troubleshooting

##### Common Issues

**1. "cannot lock /etc/passwd" Error**

This occurs when `google_guest_agent` is managing users while Containarium tries to create jump server accounts.

**Solution**: Containarium includes automatic retry logic with exponential backoff:
- ✅ Pre-checks for lock files before attempting
- ✅ 6 retry attempts with exponential backoff (500ms → 30s)
- ✅ Jitter to prevent thundering herd
- ✅ Smart error detection (only retries lock errors)

If retries are exhausted, check agent activity:
```bash
# Check what google_guest_agent is doing
sudo journalctl -u google-guest-agent --since "5 minutes ago" | grep -E "account|user|Updating"

# Temporarily disable account management (if needed)
sudo systemctl stop google-guest-agent
sudo containarium create alice --ssh-key ~/.ssh/alice.pub
sudo systemctl start google-guest-agent

# Or wait and retry - agent usually releases lock within 30-60 seconds
```

**2. Container Network Issues**

```bash
# View Incus logs
sudo journalctl -u incus -f

# Check container network
sudo incus network list
sudo incus network show incusbr0

# Restart Incus daemon
sudo systemctl restart incus
```

**3. Infrastructure Issues**

```bash
# Check startup script logs (GCE)
gcloud compute instances get-serial-port-output <instance-name> --zone=<zone>

# Verify ZFS health
sudo zpool scrub incus-pool
sudo zpool status -v
```

### gRPC Daemon Management

**Check daemon status:**
```bash
# View daemon status
sudo systemctl status containarium

# View daemon logs
sudo journalctl -u containarium -f

# Restart daemon
sudo systemctl restart containarium

# Test daemon connection (with mTLS)
containarium list \
    --server 35.229.246.67:50051 \
    --certs-dir ~/.config/containarium/certs
```

**Direct gRPC testing with grpcurl:**
```bash
# Install grpcurl if needed
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services (with mTLS)
grpcurl -cacert /etc/containarium/certs/ca.crt \
    -cert /etc/containarium/certs/client.crt \
    -key /etc/containarium/certs/client.key \
    35.229.246.67:50051 list

# Create container via gRPC (with mTLS)
grpcurl -cacert /etc/containarium/certs/ca.crt \
    -cert /etc/containarium/certs/client.crt \
    -key /etc/containarium/certs/client.key \
    -d '{"username": "alice", "ssh_keys": ["ssh-ed25519 AAA..."]}' \
    35.229.246.67:50051 containarium.v1.ContainerService/CreateContainer
```

### Batch Operations

```bash
# Create multiple containers
for user in alice bob charlie; do
  sudo containarium create $user --ssh-key ~/.ssh/${user}.pub
done

# Enable autostart for all containers
sudo incus list --format csv -c n | while read name; do
  sudo incus config set $name boot.autostart true
done

# Snapshot all containers
for container in $(sudo incus list --format csv -c n); do
  sudo incus snapshot $container "backup-$(date +%Y%m%d)"
done
```

## 🌩️ Infrastructure Deployment

### Single Server (Development)

```hcl
# terraform.tfvars
use_spot_instance    = true   # 76% cheaper
use_persistent_disk  = true   # Survives restarts
machine_type         = "n2-standard-8"  # 32GB RAM, 50 users
```

### Horizontal Scaling (Production)

```hcl
# terraform.tfvars
enable_horizontal_scaling = true
jump_server_count         = 3        # 3 independent servers
enable_load_balancer      = true     # SSH load balancing
use_spot_instance         = true
```

Deploy:
```bash
cd terraform/gce
terraform init
terraform plan
terraform apply
```

## 📖 Documentation

### Essential Guides
- **[Deployment Guide](docs/DEPLOYMENT-GUIDE.md)** - **START HERE!** Complete workflow from zero to running containers
- **[Production Deployment](PRODUCTION-DEPLOYMENT.md)** - **PRODUCTION READY!** Remote state, secrets management, CI/CD
- [Horizontal Scaling Quick Start](docs/HORIZONTAL-SCALING-QUICKSTART.md) - Deploy 3-5 jump servers
- [SSH Jump Server Setup](docs/SSH-JUMP-SERVER-SETUP.md) - SSH configuration guide

### Advanced Topics
- [Spot Instances & Scaling](docs/SPOT-INSTANCES-AND-SCALING.md) - Cost optimization
- [Horizontal Scaling Architecture](docs/HORIZONTAL-SCALING-ARCHITECTURE.md) - Scaling strategies
- [Terraform GCE README](terraform/gce/README.md) - Deployment details
- [Implementation Plan](IMPLEMENTATION-PLAN.md) - Architecture & roadmap
- [Testing Architecture](test/integration/TERRAFORM-E2E.md) - E2E testing with Terraform

## 💡 Why Containarium?

### Traditional Approach (Wasteful)

```
❌ Create 1 GCE VM per user
❌ Each VM: 2-4GB RAM (most unused)
❌ Cost: $25-50/month per user
❌ Slow: 30-60 seconds to provision
❌ Unmanageable: 50+ VMs to maintain
```

### Containarium Approach (Efficient)

```
✅ 1 GCE VM hosts 50 containers
✅ Each container: 100-500MB RAM (efficient)
✅ Cost: $1.96-2.08/month per user
✅ Fast: <60 seconds to provision
✅ Scalable: Add servers as you grow
✅ Resilient: Spot instances + persistent storage
```

## 📊 Resource Efficiency

| Metric | VM-per-User | Containarium | Improvement |
|--------|-------------|--------------|-------------|
| Memory/User | 2-4 GB | 100-500 MB | **10x** |
| Startup Time | 30-60s | 2-5s | **12x** |
| Density | 2-3/host | 150/host | **50x** |
| Cost (50 users) | $1,250/mo | $98/mo | **92% savings** |

## 🔐 Security Features

### Access Control
- **Separate User Accounts**: Each user has proxy-only account on jump server
- **No Shell Access**: User accounts use `/usr/sbin/nologin` (cannot execute commands on jump server)
- **SSH Key Auth**: Password authentication disabled globally
- **Per-User Isolation**: Users can only access their own containers
- **Admin Separation**: Only admin account has jump server shell access

### Container Security
- **Unprivileged Containers**: Container root ≠ host root (UID mapping)
- **Resource Limits**: CPU, memory, disk quotas per container
- **Network Isolation**: Separate network namespace per container
- **AppArmor Profiles**: Additional security layer per container

### Network Security
- **Firewall Rules**: Restrict SSH access to known IPs
- **fail2ban Integration**: Auto-block brute force attacks per user account
- **DDoS Protection**: Per-account rate limiting
- **Private Container IPs**: Only jump server has public IP

### Audit & Monitoring
- **SSH Audit Logging**: Track all connections by user account
- **Per-User Logs**: Separate logs for each user (alice@jump → container)
- **Container Access Logs**: Track who accessed which container and when
- **Security Event Alerts**: Monitor for suspicious activity

### Data Protection
- **Persistent Disk Encryption**: Data encrypted at rest
- **Automated Backups**: Daily snapshots with 30-day retention
- **ZFS Checksums**: Detect data corruption automatically

## 🚀 Deployment Options

| Configuration | Users | Servers | Cost/Month | Use Case |
|--------------|-------|---------|-----------|----------|
| **Dev/Test** | 20-50 | 1 spot | $98 | Development, testing |
| **Small Team** | 50-100 | 1 regular | $242 | Production, small team |
| **Medium Team** | 100-150 | 3 spot | $312 | Production, medium team |
| **Large Team** | 200-250 | 5 spot | $508 | Production, large team |
| **Enterprise** | 500+ | 10+ or cluster | Custom | Enterprise scale |

## 🗺️ Roadmap

- [x] **Phase 1**: Protobuf contracts
- [x] **Phase 2**: Go CLI framework
- [x] **Phase 3**: Terraform GCE deployment
- [x] **Phase 4**: Spot instances + persistent disk
- [x] **Phase 5**: Horizontal scaling with load balancer
- [ ] **Phase 6**: Container management implementation (Incus integration)
- [ ] **Phase 7**: End-to-end testing
- [ ] **Phase 8**: AWS support
- [ ] **Phase 9**: Web UI dashboard
- [ ] **Phase 10**: gRPC API for automation

## 🎯 Production Features

### Spot Instance Auto-Recovery

Containers automatically restart when spot instances recover:

```bash
# Spot VM terminated → Containers stop
# VM restarts → Containers auto-start (boot.autostart=true)
# Downtime: 2-5 minutes
# Data: Preserved on persistent disk
```

### Daily Backups

```bash
# Automatic snapshots enabled by default
enable_disk_snapshots = true

# 30-day retention
# Point-in-time recovery available
```

### Load Balancing

```bash
# SSH traffic distributed across healthy servers
# Session affinity keeps users on same server
# Health checks on port 22
```

## ❓ FAQ

### SSH Key Management

**Q: Can multiple users share the same SSH key?**

A: **No, never!** Each user must have their own SSH key pair. Sharing keys:
- Violates security best practices
- Makes it impossible to revoke access for one user
- Prevents audit logging of who accessed what
- Creates compliance issues

**Q: What's the difference between admin and user accounts?**

A: Containarium uses **separate user accounts** for security:
- **Admin account**: Full access to jump server shell, can manage containers
- **User accounts**: Proxy-only (no shell), can only connect to their container

Example:
```
/home/admin/.ssh/authorized_keys    (admin - full shell access)
/home/alice/.ssh/authorized_keys    (alice - proxy only, /usr/sbin/nologin)
/home/bob/.ssh/authorized_keys      (bob - proxy only, /usr/sbin/nologin)
```

**Q: Can I use the same key for both jump server and my container?**

A: **Yes, and that's the recommended approach!** Each user has ONE key that works for both:
- Simpler for users (one key to manage)
- Same key authenticates to jump server account (proxy-only)
- Same key authenticates to container (full access)
- Users cannot access jump server shell (secured by `/usr/sbin/nologin`)
- Admin can still track per-user activity in logs

**Q: How do I rotate SSH keys?**

A:
```bash
# User generates new key
ssh-keygen -t ed25519 -C "alice@company.com" -f ~/.ssh/containarium_alice_new

# Admin replaces old key with new key
NEW_KEY='ssh-ed25519 AAAAC3... alice@new-laptop'
echo "$NEW_KEY" | sudo incus exec alice-container -- \
  tee /home/alice/.ssh/authorized_keys > /dev/null
```

**Q: Can users access the jump server itself?**

A: **No!** User accounts are configured with `/usr/sbin/nologin`:
- Users can proxy through jump server to their container
- Users CANNOT get a shell on the jump server
- Users CANNOT see other containers or system processes
- Users CANNOT inspect other users' data
- Only admin has shell access to jump server

**Q: Can one user access another user's container?**

A: **No!** Each user only has SSH keys for their own container. Users cannot:
- Access other users' containers (no SSH keys for them)
- Become admin on the jump server (no shell access)
- See other users' data or processes (isolated)
- Execute commands on jump server (nologin shell)

**Q: How does fail2ban protect against attacks?**

A: With separate user accounts, fail2ban provides granular protection:
- **Per-user banning**: If alice's IP attacks, only alice is blocked
- **Other users unaffected**: bob, charlie continue working normally
- **Audit trail**: Logs show which user account was targeted
- **DDoS isolation**: Attacks on one user don't impact others
- **Automatic recovery**: Banned IPs are unbanned after timeout

**Q: Why is separate user accounts more secure than shared admin?**

A: Shared admin account (everyone uses `admin`) has serious flaws:

❌ **Without separate accounts:**
- All users can execute commands on jump server
- All users can see all containers (`incus list`)
- All users can inspect system processes (`ps aux`)
- All users can spy on other users
- Logs show only "admin" - can't tell who did what
- Banning one attacker affects all users

✅ **With separate accounts (our design):**
- Users cannot execute commands (nologin shell)
- Users cannot see other containers
- Users cannot inspect system
- Each user's activity logged separately
- Per-user banning without affecting others
- Follows principle of least privilege

**Q: What happens if I lose my SSH private key?**

A: You'll need to:
1. Generate a new SSH key pair
2. Send new public key to admin
3. Admin updates your container with new key
4. Old key is automatically invalid

**Q: Can I have different keys for work laptop and home laptop?**

A: **Yes!** You can have multiple public keys in your container:

```bash
# Admin adds second key for same user
sudo incus exec alice-container -- bash -c \
  "echo 'ssh-ed25519 AAAAC3... alice@home-laptop' >> /home/alice/.ssh/authorized_keys"
```

### General Questions

**Q: What happens when a spot instance is terminated?**

A: Containers automatically restart:
1. Spot instance terminated (by GCP)
2. Persistent disk preserved (data safe)
3. Instance restarts within ~5 minutes
4. Containers auto-start (`boot.autostart=true`)
5. Users can reconnect
6. **Downtime**: 2-5 minutes
7. **Data loss**: None

**Q: How many containers can fit on one server?**

A: Depends on machine type:
- **e2-standard-2** (8GB RAM): 10-15 containers
- **n2-standard-4** (16GB RAM): 20-30 containers
- **n2-standard-8** (32GB RAM): 40-60 containers

Each container uses ~100-500MB RAM depending on workload.

**Q: Can containers run Docker?**

A: **Yes!** Each container has Docker pre-installed and working.

```bash
# Inside your container
docker run hello-world
docker-compose up -d
```

**Q: Is my data backed up?**

A: If you enabled snapshots:
```hcl
# In terraform.tfvars
enable_disk_snapshots = true
```

Automatic daily snapshots with 30-day retention.

**Q: Can I resize my container's disk quota?**

A: Yes:
```bash
# Increase quota to 50GB
sudo containarium resize alice --disk-quota 50GB
```

**Q: How do I install software in my container?**

A:
```bash
# SSH to your container
ssh my-dev

# Install packages as usual
sudo apt update
sudo apt install vim git tmux htop

# Or use Docker
docker run -it ubuntu bash
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Read the [Implementation Plan](IMPLEMENTATION-PLAN.md)
2. Check existing issues and PRs
3. Follow the existing code style
4. Add tests for new features
5. Update documentation

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Incus](https://linuxcontainers.org/incus/) - Modern LXC container manager
- [Protocol Buffers](https://protobuf.dev/) - Type-safe data contracts
- [Cobra](https://cobra.dev/) - Powerful CLI framework
- [Terraform](https://terraform.io/) - Infrastructure as Code

## 📞 Support & Contact

- **Documentation**: See [docs/](docs/) directory
- **Issues**: [GitHub Issues](https://github.com/footprintai/Containarium/issues)
- **Organization**: [FootprintAI](https://github.com/footprintai)

## ⚡ Quick Links

- 📘 [Horizontal Scaling Guide](docs/HORIZONTAL-SCALING-QUICKSTART.md)
- 🔧 [SSH Setup Guide](docs/SSH-JUMP-SERVER-SETUP.md)
- 💰 [Cost & Scaling Strategies](docs/SPOT-INSTANCES-AND-SCALING.md)
- 🏗️ [Implementation Plan](IMPLEMENTATION-PLAN.md)
- 🌩️ [Terraform Examples](terraform/gce/examples/)

## 🌟 Getting Started in 10 Minutes

### Step 1: Deploy Infrastructure (3-5 min)

```bash
# Clone repo
git clone https://github.com/footprintai/Containarium.git
cd Containarium/terraform/gce

# Choose your size and configure
cp examples/single-server-spot.tfvars terraform.tfvars
vim terraform.tfvars  # Add: project_id, admin_ssh_keys, allowed_ssh_sources

# Deploy to GCP
terraform init
terraform apply  # Creates VM with Incus pre-installed

# Save the jump server IP from output!
```

### Step 2: Install Containarium CLI (2 min, one-time)

```bash
# Build for Linux
cd ../..
make build-linux

# Copy to jump server
scp bin/containarium-linux-amd64 admin@<jump-server-ip>:/tmp/

# SSH and install
ssh admin@<jump-server-ip>
sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium
sudo chmod +x /usr/local/bin/containarium
exit
```

### Step 3: Create Containers (1 min per user)

**Each user must generate their own SSH key pair first:**

```bash
# User generates their key (on their local machine)
ssh-keygen -t ed25519 -C "alice@company.com" -f ~/.ssh/containarium_alice
# User sends public key file to admin: ~/.ssh/containarium_alice.pub
```

**Admin creates containers with users' public keys:**

```bash
# SSH to jump server
ssh admin@<jump-server-ip>

# Save users' public keys (received from users)
echo 'ssh-ed25519 AAAAC3... alice@company.com' > /tmp/alice.pub
echo 'ssh-ed25519 AAAAC3... bob@company.com' > /tmp/bob.pub

# Create containers with users' keys
sudo containarium create alice --ssh-key /tmp/alice.pub --image images:ubuntu/24.04
sudo containarium create bob --ssh-key /tmp/bob.pub --image images:ubuntu/24.04
sudo containarium create charlie --ssh-key /tmp/charlie.pub --image images:ubuntu/24.04

# Output:
# ✓ Container alice-container created successfully!
# ✓ Jump server account: alice (proxy-only, no shell access)
# IP Address: 10.0.3.166

# Enable auto-start (survive spot instance restarts)
sudo incus config set alice-container boot.autostart true
sudo incus config set bob-container boot.autostart true
sudo incus config set charlie-container boot.autostart true

# Export SSH configs for users
sudo containarium export alice --jump-ip <jump-server-ip> > alice-ssh-config.txt
sudo containarium export bob --jump-ip <jump-server-ip> > bob-ssh-config.txt
sudo containarium export charlie --jump-ip <jump-server-ip> > charlie-ssh-config.txt

# Send config files to users
# List all containers
sudo containarium list
```

### Step 4: Users Connect

**Admin sends exported SSH config to each user:**
- Send `alice-ssh-config.txt` to Alice
- Send `bob-ssh-config.txt` to Bob
- Send `charlie-ssh-config.txt` to Charlie

**Users add to their `~/.ssh/config`:**

```bash
# Alice on her laptop
cat alice-ssh-config.txt >> ~/.ssh/config

# Connect!
ssh alice-dev
# Alice is now in her Ubuntu container with Docker!
docker run hello-world
```

**Done! 🎉**

**See [Deployment Guide](docs/DEPLOYMENT-GUIDE.md) for complete details.**

---

**Made with ❤️ by the FootprintAI team**

**Save 92% on cloud costs. Deploy in 5 minutes. Scale to 250+ users.**
