# Horizontal Scaling Architecture Guide

This document explains the two different horizontal scaling architectures and how SSH jumping works in each.

## Table of Contents

1. [Approach 1: Independent Jump Servers (Simpler)](#approach-1-independent-jump-servers)
2. [Approach 2: Central Jump + Backend Hosts (More Complex)](#approach-2-central-jump--backend-hosts)
3. [When to Use Which](#when-to-use-which)
4. [Implementation Details](#implementation-details)

---

## Approach 1: Independent Jump Servers

### Architecture

```
                     Load Balancer (35.x.x.x)
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
  ┌──────────┐        ┌──────────┐        ┌──────────┐
  │ Jump-1   │        │ Jump-2   │        │ Jump-3   │
  │ 35.1.1.1 │        │ 35.2.2.2 │        │ 35.3.3.3 │
  ├──────────┤        ├──────────┤        ├──────────┤
  │ LXC      │        │ LXC      │        │ LXC      │
  │ alice    │        │ bob      │        │ charlie  │
  │ dave     │        │ eve      │        │ frank    │
  │ (50)     │        │ (50)     │        │ (50)     │
  └──────────┘        └──────────┘        └──────────┘
```

### How It Works

**Each jump server is completely independent**:
- Jump-1 hosts containers for users 1-50 (e.g., Team A)
- Jump-2 hosts containers for users 51-100 (e.g., Team B)
- Jump-3 hosts containers for users 101-150 (e.g., Team C)

**NO cross-VM jumping needed** - users only access containers on their assigned jump server.

### User SSH Flow

**Alice (on Jump-1)**:
```
Alice's laptop → Jump-1 (35.1.1.1) → alice-container (10.0.3.100 on Jump-1)
```

**Bob (on Jump-2)**:
```
Bob's laptop → Jump-2 (35.2.2.2) → bob-container (10.0.3.100 on Jump-2)
```

Note: Same IP (10.0.3.100) can exist on different jump servers - they're isolated networks.

### SSH Config (User Side)

**Option A: With Load Balancer**
```ssh-config
# ~/.ssh/config
Host containarium-jump
    HostName 35.x.x.x  # Load balancer IP
    User admin

Host alice-dev
    HostName 10.0.3.100
    User alice
    ProxyJump containarium-jump
```

Load balancer maintains session affinity (same user → same jump server).

**Option B: Assigned to Specific Jump Server**
```ssh-config
# Team A members use Jump-1
Host containarium-jump
    HostName 35.1.1.1  # Jump-1 IP
    User admin

# Team B members use Jump-2
Host containarium-jump
    HostName 35.2.2.2  # Jump-2 IP
    User admin
```

### Container Distribution

**Manual Assignment** (simplest):
```bash
# Create containers on Jump-1 for Team A
ssh admin@35.1.1.1
containarium create alice
containarium create dave

# Create containers on Jump-2 for Team B
ssh admin@35.2.2.2
containarium create bob
containarium create eve
```

### Pros & Cons

**Pros**:
- ✅ Simple architecture
- ✅ Complete isolation between jump servers
- ✅ No cross-VM networking needed
- ✅ Easy to manage
- ✅ Fault isolated (Jump-1 failure doesn't affect Jump-2)

**Cons**:
- ❌ Users must know which jump server they're on
- ❌ Can't easily move containers between jump servers
- ❌ Uneven distribution if teams have different sizes

---

## Approach 2: Central Jump + Backend Hosts

### Architecture

```
                     User's Laptop
                           │
                           ▼
              ┌────────────────────┐
              │ Central Jump Server│
              │ (Bastion Only)     │
              │ 35.x.x.x           │
              └─────────┬──────────┘
                        │
        ┌───────────────┼───────────────────┐
        ▼               ▼                   ▼
  ┌──────────┐    ┌──────────┐       ┌──────────┐
  │Backend-1 │    │Backend-2 │       │Backend-3 │
  │10.1.1.1  │    │10.1.1.2  │       │10.1.1.3  │
  ├──────────┤    ├──────────┤       ├──────────┤
  │ LXC      │    │ LXC      │       │ LXC      │
  │ alice    │    │ bob      │       │ charlie  │
  │ dave     │    │ eve      │       │ frank    │
  │ (50)     │    │ (50)     │       │ (50)     │
  └──────────┘    └──────────┘       └──────────┘
  10.0.3.x        10.0.4.x           10.0.5.x
```

### How It Works

**Central jump server**:
- Only handles SSH access (no containers)
- Routes users to backend hosts
- Maintains SSH keys for all backends

**Backend hosts**:
- Run LXC containers
- Private IPs only (not internet accessible)
- Connected via VPC private network

### User SSH Flow

**Alice (container on Backend-1)**:
```
Alice's laptop
  → Jump Server (35.x.x.x)
    → Backend-1 (10.1.1.1)
      → alice-container (10.0.3.100 on Backend-1)
```

This is a **double SSH jump** (two hops).

### SSH Config (User Side)

**Method 1: Nested ProxyJump**
```ssh-config
# ~/.ssh/config

# Central jump server
Host jump
    HostName 35.x.x.x
    User admin
    IdentityFile ~/.ssh/jump_key

# Backend-1 (via jump)
Host backend-1
    HostName 10.1.1.1
    User admin
    ProxyJump jump
    IdentityFile ~/.ssh/backend_key

# Alice's container (via jump → backend-1)
Host alice-dev
    HostName 10.0.3.100
    User alice
    ProxyJump backend-1
    IdentityFile ~/.ssh/alice_key
```

Connect:
```bash
ssh alice-dev
# Automatically: laptop → jump → backend-1 → alice-container
```

**Method 2: Chained ProxyJump (Simpler)**
```ssh-config
# ~/.ssh/config
Host jump
    HostName 35.x.x.x
    User admin

Host alice-dev
    HostName 10.0.3.100
    User alice
    ProxyJump jump,admin@10.1.1.1  # Chain two jumps
```

**Method 3: SSH Command Line**
```bash
# Direct command (no config needed)
ssh -J admin@35.x.x.x,admin@10.1.1.1 alice@10.0.3.100
```

### Jump Server Setup (Central)

The central jump server needs:

1. **SSH keys for all backends**:
```bash
# On jump server
ssh-keygen -t ed25519 -f ~/.ssh/backend_key

# Copy to all backends
ssh-copy-id -i ~/.ssh/backend_key admin@10.1.1.1
ssh-copy-id -i ~/.ssh/backend_key admin@10.1.1.2
ssh-copy-id -i ~/.ssh/backend_key admin@10.1.1.3
```

2. **Routing configuration** (for ProxyJump to work):
```bash
# On jump server - add backend routes
ip route add 10.0.3.0/24 via 10.1.1.1  # Backend-1 containers
ip route add 10.0.4.0/24 via 10.1.1.2  # Backend-2 containers
ip route add 10.0.5.0/24 via 10.1.1.3  # Backend-3 containers
```

Or use VPC routing (GCP handles this automatically if in same VPC).

### GCP Networking Setup

**VPC Configuration**:
```hcl
# terraform/gce/central-jump-backend.tf

# Jump server with public IP
resource "google_compute_instance" "central_jump" {
  name         = "central-jump"
  machine_type = "e2-small"  # Small, just for routing

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.jump_ip.address
    }
  }
}

# Backend hosts with private IPs only
resource "google_compute_instance" "backends" {
  count        = 3
  name         = "backend-${count.index + 1}"
  machine_type = "n2-standard-8"

  network_interface {
    network = "default"
    # NO access_config = private IP only
  }
}

# Firewall: Allow SSH from jump to backends
resource "google_compute_firewall" "jump_to_backends" {
  name    = "jump-to-backends"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_tags = ["jump-server"]
  target_tags = ["backend-host"]
}
```

### Container Distribution

**Option A: Manual Assignment**
```bash
# SSH to specific backend and create container there
ssh admin@backend-1
containarium create alice

ssh admin@backend-2
containarium create bob
```

**Option B: Automated Distribution (Smart)**
```bash
# containarium CLI auto-picks least-loaded backend
ssh admin@jump
containarium create alice --auto-place

# CLI checks:
# - Backend-1: 30 containers
# - Backend-2: 25 containers ← picks this one
# - Backend-3: 35 containers
```

### Pros & Cons

**Pros**:
- ✅ Centralized access control
- ✅ Single jump server to manage
- ✅ Backend hosts can be private (more secure)
- ✅ Easy to add/remove backends
- ✅ Users don't need to know which backend

**Cons**:
- ❌ More complex networking
- ❌ Double SSH hop (slightly slower)
- ❌ Jump server is single point of failure
- ❌ Requires VPC routing setup
- ❌ More moving parts

---

## When to Use Which

| Scenario | Recommendation |
|----------|---------------|
| **10-150 users, simple setup** | Approach 1 (Independent Jump Servers) |
| **Teams are clearly separated** | Approach 1 (one jump per team) |
| **Need maximum simplicity** | Approach 1 |
| **Users distributed across backends** | Approach 2 (Central Jump) |
| **Want centralized access control** | Approach 2 |
| **Backend hosts should be private** | Approach 2 |
| **Need dynamic container placement** | Approach 2 |
| **150+ users, enterprise** | Approach 2 + Incus Clustering |

---

## Implementation Details

### Approach 1: Deploy Independent Jump Servers

```bash
# terraform.tfvars
enable_horizontal_scaling = true
jump_server_count         = 3
enable_load_balancer      = true
use_spot_instance         = true
```

Deploy:
```bash
cd terraform/gce
terraform apply
```

Result:
- 3 independent jump servers
- Load balancer in front
- Each with own containers

### Approach 2: Deploy Central Jump + Backends

```bash
# terraform.tfvars
deployment_architecture = "central-jump-backend"
central_jump_instance   = "e2-small"
backend_count           = 3
backend_instance        = "n2-standard-8"
```

Deploy:
```bash
cd terraform/gce
terraform apply -var-file=central-jump.tfvars
```

Result:
- 1 small jump server (public)
- 3 large backend hosts (private)
- VPC networking configured

---

## Hybrid Approach (Best of Both)

Combine both approaches for large deployments:

```
              Load Balancer
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   Jump-1      Jump-2      Jump-3
   (Public)    (Public)    (Public)
        │           │           │
    ┌───┴───┐   ┌───┴───┐   ┌───┴───┐
    ▼       ▼   ▼       ▼   ▼       ▼
 Back-1  Back-2  ...
(Private)
```

- Multiple jump servers for HA
- Multiple backends per jump server
- Best fault tolerance and scalability

---

## Migration Path

**Start Simple → Grow Complex**:

1. **Start**: Single VM (0-50 users)
2. **Grow**: Vertical scaling (50-100 users)
3. **Scale Out**: Independent jump servers (100-200 users)
4. **Enterprise**: Central jump + backends (200+ users)
5. **Massive**: Hybrid + Incus clustering (500+ users)

---

## Recommendation

**For most use cases (100-300 users):**
- Use **Approach 1** (Independent Jump Servers)
- 3-5 jump servers with load balancer
- Each jump server hosts 50-60 users
- Simple, reliable, easy to manage

**For enterprise (300+ users):**
- Use **Approach 2** (Central Jump + Backends)
- 1-2 jump servers (HA)
- 5-10 backend hosts
- Dynamic container placement

**We'll implement both.** Which do you want to deploy first?
