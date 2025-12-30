# Containarium: SSH Jump Server + LXC Container Platform

## Overview

**Containarium** is a production-ready platform for providing isolated development environments using LXC containers on a single cloud VM, with infrastructure-as-code deployment.

**Goal**: Deploy a single GCE VM (or AWS EC2) that acts as an SSH jump server and hosts multiple LXC containers. Each user gets their own Ubuntu container with Docker support.

**Benefits**:
- 💰 **10x cost savings** vs 1 VM per user
- 🚀 **10x resource efficiency** (150 containers vs 30 VMs on same hardware)
- 🔒 **Strong isolation** with unprivileged LXC containers
- 🏗️ **Infrastructure as Code** with Terraform
- 🛠️ **Type-safe** management with Go + Protobuf
- 📦 **Single binary** deployment (Go CLI tool)
- ☁️ **Multi-cloud ready** (GCE first, AWS later)

---

## Architecture

### High-Level Architecture

```
                    ┌─────────────────────────┐
                    │   Terraform (IaC)       │
                    │  - GCE deployment       │
                    │  - Networking           │
                    │  - Firewall rules       │
                    └───────────┬─────────────┘
                                ↓
                    ┌─────────────────────────┐
Internet  ────────► │  GCE VM (Jump Server)   │
                    │  - Ubuntu 24.04         │
                    │  - Incus (LXC runtime)  │
                    │  - Containarium CLI     │
                    └───────────┬─────────────┘
                                ↓
        ┌───────────────────────┼───────────────────────┐
        ↓                       ↓                       ↓
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│ alice-container│      │ bob-container │      │ charlie-...   │
│ Ubuntu + Docker│      │ Ubuntu + Docker│      │ Ubuntu + Docker│
│ 4GB RAM, 4 CPU │      │ 4GB RAM, 4 CPU │      │ 4GB RAM, 4 CPU │
└───────────────┘      └───────────────┘      └───────────────┘
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Containarium Platform                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Infrastructure Layer (Terraform)                        │
│     ├─ terraform/gce/    - GCE deployment                   │
│     └─ terraform/aws/    - AWS deployment (future)          │
│                                                              │
│  2. Data Layer (Protobuf)                                   │
│     └─ proto/containarium.proto - Type-safe contracts       │
│                                                              │
│  3. Application Layer (Go)                                  │
│     ├─ cmd/containarium/     - CLI entry point              │
│     ├─ internal/container/   - Container management         │
│     ├─ internal/incus/       - Incus API wrapper            │
│     └─ pkg/pb/               - Generated protobuf code      │
│                                                              │
│  4. Runtime Layer (Incus/LXC)                               │
│     └─ LXC containers with Docker support                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Infrastructure** | Terraform | Deploy GCE VM, networking, firewall |
| **Data Contracts** | Protobuf | Type-safe data structures |
| **CLI Tool** | Go (Golang) | Container management CLI |
| **Container Runtime** | Incus/LXC | Lightweight OS containers |
| **Guest OS** | Ubuntu 24.04 | Container operating system |
| **Container Engine** | Docker | Application containers inside LXC |
| **Cloud Provider** | GCE (AWS later) | Cloud infrastructure |

---

## Project Structure

```
Containarium/
├── README.md
├── IMPLEMENTATION-PLAN.md
├── Makefile
│
├── proto/
│   └── containarium/
│       └── v1/
│           ├── container.proto       # Container data structures
│           ├── user.proto           # User data structures
│           └── config.proto         # Configuration structures
│
├── terraform/
│   ├── gce/
│   │   ├── main.tf                  # GCE VM deployment
│   │   ├── variables.tf             # Input variables
│   │   ├── outputs.tf               # Output values
│   │   ├── networking.tf            # VPC, firewall rules
│   │   └── startup-script.sh        # VM initialization script
│   │
│   └── aws/                         # Future AWS support
│       └── (similar structure)
│
├── cmd/
│   └── containarium/
│       └── main.go                  # CLI entry point
│
├── internal/
│   ├── container/
│   │   ├── manager.go               # Container lifecycle management
│   │   ├── creator.go               # Container creation logic
│   │   └── lister.go                # Container listing
│   │
│   ├── incus/
│   │   ├── client.go                # Incus API wrapper
│   │   └── config.go                # Incus configuration
│   │
│   └── ssh/
│       └── keys.go                  # SSH key management
│
├── pkg/
│   └── pb/                          # Generated protobuf code
│       └── containarium/
│           └── v1/
│               ├── container.pb.go
│               ├── user.pb.go
│               └── config.pb.go
│
├── scripts/
│   ├── setup-incus.sh               # Initialize Incus on VM
│   └── load-kernel-modules.sh      # Load Docker kernel modules
│
├── docs/
│   ├── USER-GUIDE.md                # User documentation
│   ├── ADMIN-GUIDE.md               # Admin documentation
│   └── API.md                       # Protobuf contract docs
│
├── go.mod
├── go.sum
└── buf.yaml                         # Protobuf build config
```

---

## Implementation Phases

### Phase 1: Infrastructure Setup (Terraform) ✅ CURRENT

**Goal**: Deploy GCE VM with Terraform

**Deliverables**:
- Terraform configuration for GCE
- VM with Ubuntu 24.04
- Firewall rules (SSH access)
- Startup script to install Incus
- Output VM IP and connection info

**Commands**:
```bash
cd terraform/gce
terraform init
terraform plan
terraform apply
# Output: VM IP address
```

### Phase 2: Protobuf Contracts

**Goal**: Define type-safe data structures

**Deliverables**:
- `container.proto` - Container configuration, state, resources
- `user.proto` - User information, SSH keys
- `config.proto` - System configuration
- Generated Go code

**Example Contract**:
```protobuf
message Container {
  string name = 1;
  string username = 2;
  ContainerState state = 3;
  ResourceLimits resources = 4;
  repeated string ssh_keys = 5;
}
```

### Phase 3: Go CLI Tool

**Goal**: Build `containarium` CLI tool

**Deliverables**:
- CLI with subcommands:
  - `containarium create <user>` - Create container
  - `containarium list` - List containers
  - `containarium delete <user>` - Delete container
  - `containarium add-key <user> <key>` - Add SSH key
  - `containarium info <user>` - Show container info
- Single binary output
- Cross-platform build (Linux, macOS)

### Phase 4: Integration & Testing

**Goal**: End-to-end workflow

**Deliverables**:
- Deploy infrastructure with Terraform
- Install containarium CLI on VM
- Create test containers
- Verify SSH access
- Documentation

### Phase 5: AWS Support (Future)

**Goal**: Multi-cloud support

**Deliverables**:
- Terraform configuration for AWS EC2
- Same containarium CLI works on both platforms

---

## Deployment Workflow

### 1. Deploy Infrastructure

```bash
# From your local machine
cd terraform/gce

# Initialize Terraform
terraform init

# Review deployment plan
terraform plan -var="project_id=my-gcp-project"

# Deploy
terraform apply -var="project_id=my-gcp-project"

# Output:
# vm_ip = "34.x.x.x"
# ssh_command = "ssh admin@34.x.x.x"
```

### 2. Build and Deploy Containarium CLI

```bash
# Build for Linux (target platform)
GOOS=linux GOARCH=amd64 go build -o containarium cmd/containarium/main.go

# Copy to VM
scp containarium admin@34.x.x.x:/usr/local/bin/

# SSH to VM
ssh admin@34.x.x.x
```

### 3. Create Containers

```bash
# On the GCE VM
sudo containarium create alice --ssh-key ~/.ssh/alice.pub --cpu 4 --memory 4GB

# Output:
# ✓ Container alice-container created
# IP: 10.x.x.100
# SSH: ssh alice@10.x.x.100
```

### 4. Users Access Their Containers

```bash
# From user's local machine
# Add to ~/.ssh/config:
Host my-dev
    HostName 10.x.x.100
    User alice
    ProxyJump admin@34.x.x.x

# Connect
ssh my-dev

# User is now in their Ubuntu container with Docker
docker run hello-world
```

---

## Protobuf Contract Design

### Container Message

```protobuf
syntax = "proto3";

package containarium.v1;

enum ContainerState {
  CONTAINER_STATE_UNSPECIFIED = 0;
  CONTAINER_STATE_RUNNING = 1;
  CONTAINER_STATE_STOPPED = 2;
  CONTAINER_STATE_FROZEN = 3;
}

message ResourceLimits {
  string cpu = 1;        // e.g., "4"
  string memory = 2;     // e.g., "4GB"
  string disk = 3;       // e.g., "50GB"
}

message Container {
  string name = 1;
  string username = 2;
  ContainerState state = 3;
  ResourceLimits resources = 4;
  repeated string ssh_keys = 5;
  string ip_address = 6;
  int64 created_at = 7;  // Unix timestamp
  map<string, string> labels = 8;
}

message CreateContainerRequest {
  string username = 1;
  ResourceLimits resources = 2;
  repeated string ssh_keys = 3;
  map<string, string> labels = 4;
}

message CreateContainerResponse {
  Container container = 1;
  string message = 2;
}

message ListContainersRequest {}

message ListContainersResponse {
  repeated Container containers = 1;
}

message DeleteContainerRequest {
  string username = 1;
}

message DeleteContainerResponse {
  string message = 1;
}
```

---

## CLI Commands Reference

### Create Container

```bash
containarium create <username> [flags]

Flags:
  --ssh-key string     Path to SSH public key
  --cpu string         CPU limit (default: "4")
  --memory string      Memory limit (default: "4GB")
  --disk string        Disk limit (default: "50GB")

Example:
  containarium create alice --ssh-key ~/.ssh/alice.pub --cpu 2 --memory 2GB
```

### List Containers

```bash
containarium list [flags]

Flags:
  --format string      Output format: table, json (default: "table")
  --state string       Filter by state: running, stopped, all (default: "all")

Example:
  containarium list --format json
```

### Delete Container

```bash
containarium delete <username> [flags]

Flags:
  --force              Force delete without confirmation

Example:
  containarium delete alice --force
```

### Add SSH Key

```bash
containarium add-key <username> <ssh-key-path>

Example:
  containarium add-key alice ~/.ssh/new-key.pub
```

### Show Container Info

```bash
containarium info <username>

Example:
  containarium info alice
```

---

## Resource Planning

### Small Team (10-20 Users)

**GCE VM**:
- Machine Type: `n2-standard-8` (8 vCPU, 32GB RAM)
- Cost: ~$240/month
- Capacity: 20-30 containers

**Savings vs 1 VM per user**:
- Old: 20 × `e2-small` = 20 × $25 = $500/month
- New: 1 × `n2-standard-8` = $240/month
- **Savings: $260/month (52%)**

### Medium Team (50 Users)

**GCE VM**:
- Machine Type: `n2-standard-16` (16 vCPU, 64GB RAM)
- Cost: ~$480/month
- Capacity: 50-80 containers

**Savings**:
- Old: 50 × $25 = $1,250/month
- New: $480/month
- **Savings: $770/month (62%)**

---

## Security Best Practices

1. **Infrastructure Level (Terraform)**:
   - Restrict SSH access to known IPs
   - Use VPC with private networking
   - Enable Cloud Armor (DDoS protection)
   - Automated backups with snapshots

2. **Container Level (Incus)**:
   - Unprivileged containers only
   - Resource limits (CPU, memory, disk)
   - AppArmor security profiles
   - Network isolation between containers

3. **Access Level (SSH)**:
   - SSH keys only (no passwords)
   - Per-user SSH keys
   - Audit logging for all SSH sessions
   - ProxyJump for two-factor access

4. **Application Level (containarium)**:
   - Type-safe operations (protobuf)
   - Input validation
   - Error handling
   - Audit logs

---

## Next Steps

### Immediate (Phase 1)

1. ✅ Update plan document (this file)
2. ⏳ Create protobuf contracts
3. ⏳ Create Terraform configuration for GCE
4. ⏳ Create Go project structure
5. ⏳ Implement containarium CLI

### Short-term

1. Test deployment on GCE
2. Create user documentation
3. Build CI/CD pipeline
4. Add monitoring and alerting

### Long-term

1. AWS support
2. Web UI for container management
3. gRPC API for automation
4. Multi-region support
5. Kubernetes integration option

---

## Success Criteria

**Infrastructure**:
- ✅ Deploy GCE VM with one Terraform command
- ✅ VM ready with Incus installed
- ✅ Firewall configured correctly

**Container Management**:
- ✅ Create container in < 60 seconds
- ✅ Single binary CLI tool
- ✅ Type-safe operations

**User Experience**:
- ✅ Users SSH to containers seamlessly
- ✅ Docker works out of the box
- ✅ Familiar Ubuntu environment

**Operations**:
- ✅ 10x cost savings vs VM-per-user
- ✅ Support 50+ users on single VM
- ✅ Easy to backup and restore

---

## Comparison: Before vs After

### Before (Current Approach)

```
❌ Create 1 GCE VM per user manually
❌ Each VM costs $25-50/month
❌ Complex to manage 10+ VMs
❌ Slow provisioning (10+ minutes per VM)
❌ Low resource utilization
```

### After (Containarium)

```
✅ Terraform deploys infrastructure
✅ Single VM hosts all containers
✅ Create container with one command
✅ 60-second provisioning
✅ 10x cost savings
✅ Type-safe operations
✅ Production-ready Go tool
```

---

## References

- [Incus Documentation](https://linuxcontainers.org/incus/docs/main/)
- [Terraform GCE Provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [Protocol Buffers](https://protobuf.dev/)
- [Cobra CLI Framework](https://cobra.dev/)
- [Docker in LXC](https://ubuntu.com/tutorials/how-to-run-docker-inside-lxd-containers)
