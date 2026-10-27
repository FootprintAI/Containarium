# Spot Instances & Scaling Strategies

This document covers production deployment strategies for Containarium, including using spot instances for cost savings and scaling beyond a single VM.

## Table of Contents

1. [Spot Instances with Persistent State](#spot-instances-with-persistent-state)
2. [Scaling Strategies](#scaling-strategies)
3. [High Availability](#high-availability)
4. [Cost Optimization](#cost-optimization)

---

## Spot Instances with Persistent State

### Overview

**Can we use spot instances?** ✅ **YES!**

Spot instances (GCE Preemptible VMs) are **60-91% cheaper** than regular VMs but can be terminated at any time. By storing container state on a persistent disk, containers survive VM restarts.

### Architecture

```
┌─────────────────────────────────────┐
│ Spot GCE VM (can be terminated)    │
│                                     │
│ ├─ Boot Disk (ephemeral)           │
│ │   └─ OS, binaries                │
│ │                                   │
│ └─ Persistent Disk (survives!)     │
│     └─ /var/lib/incus               │
│         ├─ Container filesystems    │
│         ├─ Container configs        │
│         └─ Container state          │
└─────────────────────────────────────┘
```

### How It Works

**Normal Operation**:
1. Spot VM runs with attached persistent disk
2. All containers run from `/var/lib/incus` on persistent disk
3. Container data is always on persistent disk

**When Spot VM is Terminated**:
1. GCE stops the spot VM
2. Persistent disk is automatically detached
3. Boot disk is deleted (ephemeral)
4. **Persistent disk remains intact with all container data**

**When Spot VM Restarts**:
1. New spot VM instance starts
2. Persistent disk automatically re-attaches
3. Incus reads container state from disk
4. Containers automatically restart (with systemd service)
5. **Everything resumes as if nothing happened**

### Cost Savings

| Instance Type | Regular Price | Spot Price | Savings |
|---------------|--------------|------------|---------|
| n2-standard-8 (32GB) | $242/mo | $58/mo | **76%** |
| n2-standard-16 (64GB) | $484/mo | $116/mo | **76%** |
| n2-standard-32 (128GB) | $968/mo | $232/mo | **76%** |

**Combined with container efficiency**: 90% total savings vs VM-per-user!

### Configuration

See `terraform/gce/spot-instance.tf` for Terraform configuration.

Key settings:
```hcl
resource "google_compute_instance" "jump_server_spot" {
  # Enable spot instance
  scheduling {
    preemptible                 = true
    automatic_restart           = false
    on_host_maintenance         = "TERMINATE"
    provisioning_model          = "SPOT"
    instance_termination_action = "STOP"  # Stop instead of delete
  }

  # Persistent disk for container state
  attached_disk {
    source      = google_compute_disk.incus_data.id
    device_name = "incus-data"
    mode        = "READ_WRITE"
  }
}
```

### Handling Spot Termination

> **With Sentinel HA**, recovery is automatic with ~85s downtime and a maintenance page for users. See [SENTINEL-DESIGN.md](SENTINEL-DESIGN.md).

**Without sentinel — automatic recovery**:
1. Systemd service auto-starts Incus on boot
2. Containers auto-restart (configured in startup script)
3. Network IPs preserved (Incus DHCP on persistent disk)
4. SSH access resumes automatically

**Downtime (without sentinel)**:
- Typical termination → restart: **2-5 minutes**
- Containers pause during VM restart
- SSH connections drop and must reconnect

**Best Practices**:
1. **Enable auto-restart for containers**:
   ```bash
   incus config set <container> boot.autostart true
   ```

2. **Use systemd to ensure Incus starts**:
   ```bash
   systemctl enable incus
   ```

3. **Monitor for terminations**:
   - Set up Cloud Monitoring alerts
   - Log termination events

4. **Graceful shutdown script**:
   - Save container state before termination
   - Flush disk caches

### Persistent Disk Strategy

**Option 1: Single Persistent Disk (Recommended for < 50 containers)**
```
/var/lib/incus → Persistent Disk 1 (500GB)
  ├─ Containers
  ├─ Images
  └─ Network state
```

**Option 2: Separate Disks for Performance (> 50 containers)**
```
/var/lib/incus/storage-pools → Persistent Disk 1 (1TB SSD)
/var/lib/incus/database      → Persistent Disk 2 (100GB SSD)
```

**Backup Strategy**:
```bash
# Snapshot persistent disk daily
gcloud compute disks snapshot incus-data-disk \
  --snapshot-names incus-backup-$(date +%Y%m%d) \
  --zone us-central1-a

# Retention: 30 days rolling
```

---

## Scaling Strategies

When one VM isn't enough (> 50-100 containers), you have three options:

### Strategy 1: Vertical Scaling (Simplest)

**Grow the VM size as you need more capacity.**

```
10 users  → n2-standard-4  (16GB RAM)  [$121/mo]
30 users  → n2-standard-8  (32GB RAM)  [$242/mo]
60 users  → n2-standard-16 (64GB RAM)  [$484/mo]
120 users → n2-standard-32 (128GB RAM) [$968/mo]
```

**Pros**:
- ✅ Simple (no architecture changes)
- ✅ Single jump server to manage
- ✅ No load balancing complexity

**Cons**:
- ❌ Limited by max VM size (~128GB RAM → ~150 containers)
- ❌ No redundancy (single point of failure)
- ❌ Downtime during resize

**How to scale up**:
```bash
# 1. Stop the VM
gcloud compute instances stop containarium-jump

# 2. Change machine type
gcloud compute instances set-machine-type containarium-jump \
  --machine-type n2-standard-16 \
  --zone us-central1-a

# 3. Start the VM
gcloud compute instances start containarium-jump

# Downtime: 2-3 minutes
```

**When to use**: 10-120 users, simplicity over redundancy

---

### Strategy 2: Horizontal Scaling - Multiple Jump Servers (Recommended)

**Run multiple independent jump servers, each hosting different users.**

```
                  ┌─────────────────┐
                  │ DNS / LB        │
                  │ jump.company.com│
                  └────────┬────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
   ┌──────────┐      ┌──────────┐      ┌──────────┐
   │ Jump-1   │      │ Jump-2   │      │ Jump-3   │
   │192.0.2.1 │      │192.0.2.2 │      │192.0.2.3 │
   ├──────────┤      ├──────────┤      ├──────────┤
   │ Team A   │      │ Team B   │      │ Team C   │
   │ 50 users │      │ 50 users │      │ 50 users │
   └──────────┘      └──────────┘      └──────────┘
```

**Pros**:
- ✅ Scales infinitely (add more jump servers)
- ✅ Fault isolation (Jump-1 failure doesn't affect Jump-2)
- ✅ Team/project separation
- ✅ Easy to add capacity

**Cons**:
- ❌ Users must know which jump server to use
- ❌ More infrastructure to manage
- ❌ Load balancing needed for seamless experience

**Implementation**:

**Option A: Manual Assignment (Simplest)**
- Team A → jump-1.company.com
- Team B → jump-2.company.com
- Team C → jump-3.company.com

Users configure SSH:
```ssh-config
# Team A members
Host containarium-jump
    HostName jump-1.company.com

# Team B members
Host containarium-jump
    HostName jump-2.company.com
```

**Option B: DNS Round-Robin**
```
jump.company.com → 192.0.2.1, 192.0.2.2, 192.0.2.3
```

**Option C: Load Balancer (Best)**
```
GCP Network Load Balancer
  ├─ jump-1 (health check: port 22)
  ├─ jump-2
  └─ jump-3
```

**Terraform for multiple jump servers**:
```hcl
# Deploy 3 jump servers
module "jump_server" {
  source = "./modules/jump-server"
  count  = 3

  instance_name = "containarium-jump-${count.index + 1}"
  machine_type  = "n2-standard-8"
  use_spot      = true
}
```

**When to use**: > 100 users, need fault tolerance

---

### Strategy 3: Incus Clustering (Advanced)

**Run Incus in cluster mode across multiple VMs with shared storage.**

```
                  ┌─────────────────┐
                  │ Jump/LB         │
                  └────────┬────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
   ┌──────────┐      ┌──────────┐      ┌──────────┐
   │ Incus-1  │      │ Incus-2  │      │ Incus-3  │
   │ (Member) │      │ (Member) │      │ (Member) │
   └────┬─────┘      └────┬─────┘      └────┬─────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          ▼
                  ┌──────────────┐
                  │ Shared Storage│
                  │ (Ceph/NFS)    │
                  └──────────────┘
```

**Pros**:
- ✅ True high availability
- ✅ Containers can migrate between nodes
- ✅ Automatic load balancing
- ✅ Shared storage for resilience

**Cons**:
- ❌ Complex setup (Incus cluster + storage cluster)
- ❌ Higher cost (need 3+ nodes + shared storage)
- ❌ Network overhead for shared storage
- ❌ Requires deep Incus expertise

**Setup**:
```bash
# Node 1
incus cluster enable node1

# Node 2
incus cluster join node1 --server-address 10.0.1.1

# Node 3
incus cluster join node1 --server-address 10.0.1.1

# Containers automatically distributed
incus launch ubuntu:24.04 alice-container
# Incus picks least-loaded node
```

**When to use**: > 500 users, need HA, have ops expertise

---

## Comparison: Which Scaling Strategy?

| Users | Strategy | Cost/Month | Complexity | Downtime | Best For |
|-------|----------|-----------|------------|----------|----------|
| 10-50 | Vertical (spot) | $58 | Low | 2-3 min | Startups |
| 50-100 | Vertical (regular) | $242-484 | Low | 2-3 min | Small teams |
| 100-300 | Horizontal (3x spot) | $174 | Medium | None* | Growing teams |
| 300-500 | Horizontal (5x spot) | $290 | Medium | None* | Medium teams |
| 500+ | Incus Cluster | $800+ | High | None | Enterprise |

*No downtime if one jump server fails (others take over)

---

## High Availability Setup

> **Recommended:** Use the **Sentinel HA** architecture for production spot instance deployments. The sentinel is a tiny always-on VM that monitors spot VMs, auto-restarts them on preemption (~85s recovery), and serves a maintenance page during outages. One sentinel can front multiple spot VMs. See [SENTINEL-DESIGN.md](SENTINEL-DESIGN.md) for the full design.

### Legacy: 2-Node HA with Persistent Disks

**Architecture**:
```
                ┌─────────────────────┐
                │ Cloud Load Balancer │
                │ jump.company.com    │
                └──────────┬──────────┘
                           │
                  ┌────────┴─────────┐
                  ▼                  ▼
           ┌─────────────┐    ┌─────────────┐
           │ Jump-1      │    │ Jump-2      │
           │ (Active)    │    │ (Standby)   │
           │ us-central1 │    │ us-west1    │
           └──────┬──────┘    └──────┬──────┘
                  │                  │
           ┌──────┴──────┐    ┌──────┴──────┐
           │ Disk-1      │    │ Disk-2      │
           │ (Primary)   │    │ (Replica)   │
           └─────────────┘    └─────────────┘
```

**Implementation**:
1. Run 2 jump servers in different zones/regions
2. Sync container state with `rsync` or snapshot replication
3. Load balancer health checks port 22
4. If Jump-1 fails, LB routes to Jump-2

**Drawback**: Container IPs may change if failover to Jump-2

---

## Cost Optimization Summary

### Single VM (Spot) - 50 users
- Instance: n2-standard-8 spot = **$58/mo**
- Persistent disk: 500GB = **$40/mo**
- **Total: $98/mo** ($1.96/user/mo)

### Horizontal (3x Spot) - 150 users
- 3x n2-standard-8 spot = **$174/mo**
- 3x 500GB disks = **$120/mo**
- Load balancer = **$18/mo**
- **Total: $312/mo** ($2.08/user/mo)

### Old Way (150 users, 1 VM each)
- 150x e2-small = **$3,750/mo** ($25/user/mo)

**Savings: 92%** 🎉

---

## Recommendations

| Your Situation | Recommendation |
|----------------|----------------|
| **< 30 users, tight budget** | Single spot VM + persistent disk |
| **30-80 users, production** | Sentinel + spot VM ([SENTINEL-DESIGN.md](SENTINEL-DESIGN.md)) |
| **80-200 users, need reliability** | Sentinel + multiple spot VMs (horizontal) |
| **200-500 users, need HA** | Sentinel + multiple spot VMs + load balancer |
| **500+ users, enterprise** | Incus cluster with Ceph storage |

---

## Next Steps

1. **Start small**: Deploy single spot VM with persistent disk
2. **Monitor usage**: Track CPU, memory, container count
3. **Scale when needed**:
   - Vertical: Resize VM when > 70% memory used
   - Horizontal: Add jump server when > 50 containers
4. **Add HA later**: When uptime becomes critical
5. **Consider Incus cluster**: Only if you need 500+ containers

See Terraform configurations:
- `terraform/gce/spot-instance.tf` - Spot VM setup
- `terraform/gce/horizontal-scaling.tf` - Multiple jump servers
- `terraform/gce/ha-setup.tf` - High availability configuration
