# Spot Instance Recovery

This document describes how Containarium recovers from GCE spot instance preemption, including measured recovery timelines and the sentinel HA architecture that reduces downtime from ~9 minutes to ~85 seconds.

> For the full sentinel architecture, modes, TLS cert sync, status page, CLI reference, and operational runbook, see [SENTINEL-DESIGN.md](SENTINEL-DESIGN.md).

## Architecture: Sentinel HA (Current)

```
                ┌──────────────────────┐
  Users ──────► │  Sentinel VM         │  e2-micro, us-west1 (free tier)
  (all traffic) │  containarium        │  Owns public static IP
                │    sentinel          │  Always-on, STANDARD provisioning
                └──────────┬───────────┘
                           │ GCP internal VPC (cross-region)
                ┌──────────▼───────────┐
                │  Spot VM             │  c3d-highmem-8, us-west1-a
                │  containarium        │  Ephemeral IP
                │    daemon            │  instance_termination_action: STOP
                │                      │
                │  Boot Disk (preserved on STOP)
                │  ├── Ubuntu 24.04, Incus, ZFS
                │  ├── Containarium binary
                │  └── JWT secret, SSH keys
                │                      │
                │  Persistent Disk (500GB)
                │  └── ZFS pool "incus-pool"
                │      └── containers  │
                └──────────────────────┘

Normal:      Sentinel forwards 22/80/443/50051 → spot VM via iptables DNAT
Preempted:   Sentinel serves maintenance page, restarts spot VM
```

**Key design principle:** The sentinel replaces the MIG. Since `instance_termination_action: STOP` preserves the VM (boot disk + persistent disk + network config), the sentinel simply calls `StartInstance()` to restart it. No delete/recreate cycle, no software reinstallation, no ZFS recovery. The VM boots with everything already in place.

### Why Not MIG?

The MIG's auto-healing **deletes** the stopped instance and creates a new one from a template. This destroys the boot disk, requiring a full software reinstall on every recovery (~5 minutes of overhead). The sentinel avoids this entirely by restarting the existing stopped VM.

| Aspect | MIG Auto-Healing | Sentinel |
|--------|-----------------|----------|
| Detection | ~91s (health check × threshold) | ~10s (GCP operations watcher) |
| Recovery action | Delete + recreate from template | Restart stopped VM |
| Boot disk | Destroyed, fresh install | Preserved, instant boot |
| Software install | Every recovery (~57s) | Never (already installed) |
| Binary download | Every recovery (~26s) | Never (already on disk) |
| ZFS recovery | Every recovery (~21s) | Not needed (Incus auto-starts) |
| User experience | Connection refused (blackout) | Maintenance page in ~10s |
| **Effective downtime** | **~8m 44s** | **~85s** |

## What Happens During Preemption (Sentinel)

1. GCE preempts the spot VM (`instance_termination_action: STOP`)
2. VM enters STOPPED state — boot disk and persistent disk preserved
3. Sentinel event watcher detects preemption via GCP operations API (~10s)
4. Sentinel immediately switches to maintenance mode (serves 503 page)
5. Sentinel calls `StartInstance()` on the stopped VM
6. VM boots with existing boot disk — all software already installed
7. systemd auto-starts Incus and containarium daemon
8. Sentinel TCP health check detects backend healthy, switches to proxy mode
9. Traffic flows again — users see the service resume

## What Happens During Preemption (Legacy MIG)

1. GCE terminates the spot VM (`instance_termination_action: STOP`)
2. Boot disk is destroyed (`auto_delete: true` triggers on MIG delete)
3. Persistent disk (ZFS/container data) is preserved (`auto_delete: false`)
4. Static external IP is preserved (stateful MIG config)
5. MIG health check detects the instance as unhealthy
6. MIG auto-healing deletes the stopped instance and creates a new one
7. New VM boots with fresh boot disk + same persistent disk + same IP
8. Startup script runs: installs packages, imports ZFS, recovers containers

## Sentinel Recovery Timeline (Expected)

Based on the measured MIG recovery data below, the sentinel eliminates the delete/recreate cycle and software installation phases.

```
Sentinel recovery breakdown:

  Detection (event watcher):  ~10s   (12%)  ██
  VM Boot (same boot disk):   ~60s   (71%)  ██████████████
  Services auto-start:        ~15s   (17%)  ███
  ──────────────────────────────
  Effective downtime:         ~85s   (100%)

  Users see maintenance page from ~10s (not connection refused)
```

| Metric | MIG (Legacy) | Sentinel |
|--------|-------------|----------|
| **Effective downtime** | **~8m 44s** | **~85s** |
| User-visible blackout | ~8m 44s | ~0s (maintenance page) |
| Software reinstall | Every recovery | Never |
| Data loss | None | None |
| Cost (sentinel VM) | $0 | $0 (free tier e2-micro) |

### Why Restarting Is Faster Than Recreating

With `instance_termination_action: STOP`, GCE stops the VM but preserves it:
- Boot disk intact (Ubuntu, Incus, ZFS, binary, config — all in place)
- Persistent disk still attached
- Network config preserved

The sentinel calls `StartInstance()` which boots the existing VM. systemd starts Incus and the containarium daemon automatically. No startup script reinstallation needed.

Spot VMs (provisioning_model: SPOT) have **no 24-hour time limit** — unlike old preemptible VMs. They run indefinitely until GCE needs capacity. Restarting a stopped spot VM does not affect preemption scheduling.

## Legacy MIG Recovery Timeline (Measured)

Measured on 2026-02-27 with 15 running containers on a `c3d-highmem-8` instance in `us-west1-a`.

### Phase 1: Shutdown & Detection (T+0s to T+91s)

| Elapsed | Event | Duration |
|---------|-------|----------|
| T+0s | GCE preempts instance (STOP action) | — |
| T+61s | Instance fully stopped | 61s |
| T+91s | MIG auto-heal triggered (recreating) | 30s |

The MIG detects the unhealthy instance quickly because the TCP health check on port 8080 fails immediately when the instance stops. With `check_interval_sec: 30` and `unhealthy_threshold: 3`, detection takes ~90s in the worst case. In practice, it was faster because the MIG also monitors instance status directly.

### Phase 2: Instance Recreation (T+91s to T+417s)

| Elapsed | Event | Duration |
|---------|-------|----------|
| T+91s | MIG starts recreating | — |
| T+361s | New VM boots | 270s |
| T+417s | Startup script begins | 56s |

This is the **largest bottleneck** (~5 minutes). It includes:
- Deleting the old stopped instance
- Detaching the persistent disk
- Creating a new instance from the template
- Attaching the persistent disk via per-instance config
- Assigning the static IP
- GCE VM boot sequence

### Phase 3: Software Installation (T+417s to T+474s)

| Elapsed | Event | Duration |
|---------|-------|----------|
| T+417s | `apt-get update && upgrade` | — |
| T+432s | Essential packages installed | 15s |
| T+435s | fail2ban configured | 3s |
| T+436s | Persistent disk found | 1s |
| T+460s | Incus 6.21 installed from Zabbly repo | 24s |
| T+474s | ZFS pool imported | 14s |

Package installation takes ~57s total. This could be reduced to near-zero by using a custom VM image with Incus and ZFS pre-installed (see Optimization section).

### Phase 4: Container Recovery (T+474s to T+495s)

| Elapsed | Event | Duration |
|---------|-------|----------|
| T+474s | ZFS pool imported, 15 containers detected | 0s |
| T+485s | `incus admin recover` completes (storage pool) | 11s |
| T+495s | All 15 containers RUNNING | 10s |

Container recovery is very fast — the ZFS pool has all container data intact, and `incus admin recover` restores the storage pool and container metadata. Starting 15 containers takes ~10 seconds.

### Phase 5: Daemon & Service Startup (T+495s to T+524s)

| Elapsed | Event | Duration |
|---------|-------|----------|
| T+521s | Containarium v0.7.0 binary downloaded | 26s |
| T+521s | JWT secret auto-generated | <1s |
| T+524s | Daemon active, serving on :8080 | 3s |

### Phase 6: Post-Recovery Tasks (T+524s to T+813s)

| Elapsed | Event | Duration |
|---------|-------|----------|
| T+524s | SSH account sync from containers | ~60s |
| T+813s | Startup script complete | ~230s |

Post-recovery tasks include syncing SSH jump server accounts, setting up logrotate, configuring SSH hardening, and other non-critical setup. These run after the daemon is already serving.

### Summary

```
Total downtime breakdown:

  Shutdown & Detection:    91s  (11%)  ██
  Instance Recreation:    270s  (33%)  ██████
  Software Installation:   57s   (7%)  █
  Container Recovery:      21s   (3%)  █
  Binary Download:         26s   (3%)  █
  Daemon Start:             3s  (<1%)
  Post-Recovery:          289s  (35%)  ██████
  ─────────────────────────────
  Script complete:        813s (100%)

  Effective downtime*:    524s  (~8m 44s)

  * Time until daemon is serving and all containers are running.
    Post-recovery tasks are non-critical (SSH account sync, etc).
```

| Metric | Value |
|--------|-------|
| **Effective downtime** | **~8 min 44s** |
| Total script time | ~13 min 33s |
| Containers recovered | 15/15 |
| Data loss | None (ZFS persistent disk) |
| IP change | None (stateful MIG preserves static IP) |

## Sentinel Infrastructure

### Terraform Configuration

Enable sentinel with two variables:

```hcl
# terraform.tfvars
use_spot_instance = true
enable_sentinel   = true
```

This creates:
- Sentinel VM (e2-micro, us-west1, free tier) — owns the public static IP
- Spot VM (c3d-highmem-8, us-west1-a) — ephemeral IP, `containarium-spot-backend` tag
- Firewall rules for sentinel ingress (22/80/443), management SSH (2222), and sentinel-to-spot forwarding
- Binary server on sentinel (port 8888) — spot VM downloads binary from sentinel on first boot
- Management SSH on port 2222 (port 22 is DNAT'd to spot VM in proxy mode)

### Sentinel Subcommand

The sentinel runs the same `containarium` binary:

```bash
# Production (on sentinel VM, installed via systemd)
containarium sentinel --spot-vm containarium-jump --zone us-west1-a --project my-project

# Local testing (no GCP, no iptables)
containarium sentinel --provider=none --backend-addr=127.0.0.1 --health-port 8080 --http-port 9090
```

Key flags:
- `--recovery-timeout=10m` — warn if recovery exceeds threshold
- `--binary-port=8888` — serve binary for spot VM downloads
- `--check-interval=15s` — TCP health check interval
- `--cert-sync-interval=6h` — interval for syncing TLS certs from spot VM

### How the Sentinel Works

1. **Normal mode (PROXY)**: iptables DNAT forwards ports 22/80/443/50051 to spot VM internal IP
2. **Preemption detected**: event watcher polls GCP `zoneOperations` every 10s
3. **Immediate switch**: clears iptables, starts HTTP/HTTPS maintenance server on :80/:443
4. **Auto-restart**: calls `StartInstance()` on the stopped spot VM
5. **Health check**: TCP check on spot VM's health port; after 2 consecutive passes, switches back to proxy
6. **Recovery tracking**: logs preemption count, recovery duration, warns if > recovery timeout

### TLS Certificate Sync

During maintenance mode, the sentinel serves HTTPS on port 443. To avoid browser TLS warnings, the sentinel syncs real Let's Encrypt certificates from the spot VM's Caddy server.

**How it works:**
1. The daemon on the spot VM exposes a `/certs` endpoint (on the HTTP gateway port) that returns all Caddy TLS certificates as JSON
2. The sentinel periodically fetches certificates from `http://<spot-internal-ip>:<http-port>/certs`
3. Certificates are stored in memory and served via SNI-based lookup during maintenance mode

**SNI certificate selection order:**
1. Exact domain match (e.g., `app.example.com`)
2. Wildcard match (e.g., `*.example.com`)
3. Self-signed fallback (generated at startup)

**Configuration:**
- `--cert-sync-interval=6h` — how often the sentinel syncs certs from the spot VM (default: 6h)
- `--caddy-cert-dir` — daemon flag to set the Caddy certificate directory (default: `/var/lib/caddy/.local/share/caddy`)

When the sentinel switches to proxy mode (spot VM recovered), it performs an immediate cert sync to ensure fresh certificates are available for the next maintenance window.

### Sentinel Status Page

The sentinel provides real-time status information accessible at `/sentinel` on both HTTP and HTTPS during maintenance mode.

**Status page shows:**
- Current mode (PROXY or MAINTENANCE)
- Spot VM internal IP
- Forwarded ports
- Preemption count
- Last preemption time
- Current outage duration
- Cert sync status (count, last sync time)

**JSON API:** A machine-readable status endpoint is always available at `http://<sentinel-ip>:8888/status` (on the binary server port), regardless of the sentinel's mode.

```bash
# Check sentinel status (always available)
curl http://<sentinel-ip>:8888/status

# During maintenance, the HTML status page is at:
curl http://<sentinel-ip>/sentinel
```

### Management SSH (Port 2222)

When the sentinel is in PROXY mode, port 22 is forwarded (DNAT) to the spot VM. To SSH into the sentinel itself for management, use port 2222:

```bash
# SSH to sentinel directly (management)
ssh -p 2222 admin@<sentinel-ip>

# SSH through sentinel to spot VM (forwarded via iptables)
ssh admin@<sentinel-ip>

# Via IAP (for VMs without external IP)
gcloud compute ssh <your-sentinel-vm> \
  --project <your-gcp-project> \
  --zone us-west1-b \
  --tunnel-through-iap \
  -- -p 2222
```

### fail2ban Whitelist

The sentinel's TCP health checks to the spot VM can trigger fail2ban on the spot VM if they come from a MASQUERADE'd source IP. To prevent this, whitelist the sentinel's internal IP on the spot VM:

```bash
# On the spot VM, add to /etc/fail2ban/jail.local:
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 10.130.0.0/24

# Then restart fail2ban
sudo systemctl restart fail2ban
```

The sentinel's startup script should ideally be paired with a spot VM startup script that pre-configures this whitelist.

### Sentinel Observability

```bash
# View sentinel logs
sudo journalctl -u containarium-sentinel -f

# Example log output during preemption:
# [sentinel] EVENT: PREEMPTION detected at 2026-02-27T15:30:00Z (total: 3) — spot VM preempted
# [sentinel] mode: MAINTENANCE → serving maintenance page
# [sentinel] backend VM status: stopped
# [sentinel] attempting to start backend VM...
# [sentinel] start command sent, waiting for VM to boot...
# [sentinel] backend healthy (2 consecutive checks), switching to proxy (recovery took 1m25s)
```

## Legacy: MIG Architecture

<details>
<summary>Click to expand legacy MIG configuration (replaced by sentinel)</summary>

### MIG (Managed Instance Group)

```hcl
resource "google_compute_instance_group_manager" "containarium_spot" {
  target_size        = 1
  base_instance_name = "<your-primary-vm>"

  stateful_disk {
    device_name = "incus-data"
    delete_rule = "NEVER"
  }
  stateful_external_ip {
    interface_name = "nic0"
    delete_rule    = "NEVER"
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.containarium.id
    initial_delay_sec = 600
  }

  update_policy {
    type               = "OPPORTUNISTIC"
    replacement_method = "RECREATE"
  }
}
```

### Health Check

```hcl
resource "google_compute_health_check" "containarium" {
  check_interval_sec  = 30
  timeout_sec         = 10
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = 8080
  }
}
```

### Startup Script Recovery Flow

The startup script (`scripts/startup-spot.sh`) handles two scenarios because the MIG destroys the boot disk on every recovery:

**Fresh Install:** `apt install → incus admin init → create ZFS pool → done`

**Recovery:** `apt install → zpool import → incus admin recover → start containers → download binary → start daemon`

</details>

## Testing Recovery

### Simulate Preemption (with Sentinel)

```bash
# Stop the instance (simulates STOP preemption action)
gcloud compute instances stop containarium-jump \
  --project <your-gcp-project> \
  --zone us-west1-a

# Sentinel detects in ~10s, serves maintenance page, restarts VM
# Monitor from sentinel (use port 2222 for management SSH):
ssh -p 2222 admin@<sentinel-ip> 'sudo journalctl -u containarium-sentinel -f'

# Verify maintenance page:
curl -s http://<sentinel-ip>  # → 503 + maintenance HTML

# Verify status page:
curl -s http://<sentinel-ip>/sentinel  # → status page with recovery info

# Check JSON status (always available on binary server port):
curl -s http://<sentinel-ip>:8888/status | jq .

# VM recovers in ~60-90s, sentinel switches back to proxy
```

### Verify Recovery

```bash
# Via sentinel (proxied through)
ssh admin@<sentinel-ip> '
  containarium version
  systemctl is-active containarium
  sudo incus list --format=csv -c ns
'

# Or direct to spot VM (if you know its ephemeral IP)
gcloud compute ssh containarium-jump \
  --project <your-gcp-project> \
  --zone us-west1-a \
  --tunnel-through-iap \
  --command "systemctl is-active containarium && sudo incus list -c ns"
```

### Edge Cases

**Repeated preemption** (capacity crunch): The sentinel tracks preemption count and logs warnings. If the spot VM enters a preempt-restart-preempt loop, `--recovery-timeout=10m` triggers a warning. Consider switching zones.

**Sentinel VM down**: The sentinel runs on a STANDARD (non-spot) e2-micro with `automatic_restart: true` and `on_host_maintenance: MIGRATE`. GCE live-migrates it during maintenance windows. If it somehow goes down, the spot VM continues running — users just lose the HA safety net until the sentinel restarts.
