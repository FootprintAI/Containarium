# Sentinel Design

The sentinel is a tiny always-on VM (e2-micro, GCP free tier) that sits in front of one or more spot VMs. It owns the static public IP, forwards traffic transparently during normal operation, and provides automatic recovery when spot VMs are preempted.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Users (SSH / HTTP / gRPC)                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│               Sentinel VM (e2-micro, always-on)                  │
│               • Owns static public IP                            │
│               • iptables DNAT → spot VMs (PROXY mode)            │
│               • Maintenance page + status page (MAINTENANCE)     │
│               • Auto-restarts spot VMs on preemption             │
│               • Syncs TLS certs for valid HTTPS                  │
│               • Management SSH on port 2222                      │
│               • Binary server on port 8888                       │
└────────────────────────────┬────────────────────────────────────┘
                             │ VPC internal
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ Spot VM 1        │ │ Spot VM 2        │ │ Spot VM N        │
│ • Incus + ZFS    │ │ • Incus + ZFS    │ │ • Incus + ZFS    │
│ • Caddy (TLS)    │ │ • Caddy (TLS)    │ │ • Caddy (TLS)    │
│ • Containarium   │ │ • Containarium   │ │ • Containarium   │
│ • No external IP │ │ • No external IP │ │ • No external IP │
└────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
         ▼                    ▼                    ▼
  Persistent Disk      Persistent Disk      Persistent Disk
  (ZFS pool)           (ZFS pool)           (ZFS pool)
    50 containers        50 containers        50 containers
```

### Why Sentinel (Not MIG)

GCE Managed Instance Groups (MIG) auto-heal by **deleting** the stopped instance and creating a new one. This destroys the boot disk, requiring full software reinstallation on every recovery (~5 minutes overhead).

The sentinel avoids this by using `instance_termination_action: STOP`, which preserves the VM. The sentinel simply calls `StartInstance()` to restart it — no reinstallation needed.

| Aspect | MIG Auto-Healing | Sentinel |
|--------|-----------------|----------|
| Detection | ~91s (health check x threshold) | ~10s (GCP operations watcher) |
| Recovery action | Delete + recreate from template | Restart stopped VM |
| Boot disk | Destroyed, fresh install | Preserved, instant boot |
| User experience | Connection refused (blackout) | Maintenance page in ~10s |
| **Effective downtime** | **~8m 44s** | **~85s** |

### Why One Sentinel for Multiple Spot VMs

A single sentinel can monitor and route traffic to multiple spot VMs:

- **Cost**: One e2-micro (free tier) serves the entire cluster, no need for a sentinel per VM
- **Simplicity**: Single static IP entry point, single management point
- **Independent recovery**: Each spot VM is monitored independently — if one is preempted, only its users see the maintenance page while other VMs continue serving
- **Scaling**: Add more spot VMs behind the same sentinel as your user count grows

## Modes

The sentinel operates in two modes:

### PROXY Mode (normal)

Traffic flows transparently through iptables DNAT:

```
User → sentinel:22  → [DNAT] → spot-vm:22   (SSH)
User → sentinel:80  → [DNAT] → spot-vm:80   (HTTP)
User → sentinel:443 → [DNAT] → spot-vm:443  (HTTPS/Caddy)
User → sentinel:50051 → [DNAT] → spot-vm:50051 (gRPC)
```

The sentinel is invisible to users — they connect to the static IP and traffic is forwarded to the spot VM's internal VPC address.

### MAINTENANCE Mode (spot VM down)

When the spot VM is unhealthy or preempted:

```
User → sentinel:80  → Maintenance HTML page (503)
User → sentinel:443 → Maintenance HTML page (503, with synced TLS cert)
User → sentinel:80/sentinel  → Status page (recovery info)
User → sentinel:443/sentinel → Status page (recovery info)
```

The sentinel clears all iptables DNAT rules and starts its own HTTP/HTTPS servers.

## Recovery Flow

1. GCE preempts the spot VM (`instance_termination_action: STOP`)
2. VM enters STOPPED state — boot disk and persistent disk preserved
3. Sentinel event watcher detects preemption via GCP operations API (~10s)
4. Sentinel switches to MAINTENANCE mode (serves 503 maintenance page)
5. Sentinel calls `StartInstance()` on the stopped VM
6. VM boots with existing boot disk — all software already in place
7. systemd auto-starts Incus and containarium daemon
8. Sentinel TCP health check detects backend healthy (2 consecutive passes)
9. Sentinel switches back to PROXY mode — traffic flows again

```
Recovery timeline:

  Detection (event watcher):  ~10s   (12%)  ██
  VM Boot (same boot disk):   ~60s   (71%)  ██████████████
  Services auto-start:        ~15s   (17%)  ███
  ──────────────────────────────
  Effective downtime:         ~85s   (100%)

  Users see maintenance page from ~10s (not connection refused)
```

## TLS Certificate Sync

During MAINTENANCE mode, the sentinel serves HTTPS on port 443. To avoid browser TLS warnings, it syncs real Let's Encrypt certificates from the spot VM's Caddy server.

### How It Works

1. The daemon on the spot VM exposes a `/certs` endpoint on its HTTP gateway port
2. The endpoint walks Caddy's certificate directory and returns all cert/key pairs as JSON
3. The sentinel periodically fetches from `http://<spot-internal-ip>:<http-port>/certs`
4. Certificates are stored in memory and served via SNI-based lookup

### SNI Certificate Selection

When a TLS handshake arrives, the sentinel's `CertStore.GetCertificate()` selects:

1. **Exact match** — e.g., `app.example.com`
2. **Wildcard match** — e.g., `*.example.com`
3. **Self-signed fallback** — generated at startup (last resort)

### Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--cert-sync-interval` | `6h` | How often sentinel syncs certs from spot VM |
| `--caddy-cert-dir` (daemon) | `/var/lib/caddy/.local/share/caddy` | Caddy certificate directory on spot VM |

When the sentinel switches to PROXY mode (spot VM recovered), it performs an immediate cert sync to ensure fresh certificates are available for the next maintenance window.

## Status Page

The sentinel provides real-time status information via two endpoints:

### HTML Status Page (`/sentinel`)

Available during MAINTENANCE mode on ports 80 and 443. Dark-themed page showing:
- Current mode (PROXY or MAINTENANCE badge)
- Spot VM internal IP
- Forwarded ports
- Preemption count
- Last preemption time
- Current outage duration
- Cert sync status (count, last sync time)

Auto-refreshes every 10 seconds.

### JSON Status API (`:8888/status`)

Always available on the binary server port, regardless of mode:

```bash
curl http://<sentinel-ip>:8888/status
```

```json
{
  "state": "proxy",
  "spot_ip": "10.130.0.14",
  "preempt_count": 3,
  "outage_duration": "",
  "last_preemption": "2026-02-27T15:30:00Z",
  "cert_sync_count": 5,
  "cert_sync_last": "2026-02-27T21:30:00Z"
}
```

## Management SSH (Port 2222)

When the sentinel is in PROXY mode, port 22 is DNAT'd to the spot VM. To SSH into the sentinel itself for management, use port 2222:

```bash
# SSH to sentinel directly (management)
ssh -p 2222 admin@<sentinel-ip>

# SSH through sentinel to spot VM (forwarded via iptables DNAT)
ssh admin@<sentinel-ip>

# Via IAP tunnel
gcloud compute ssh <sentinel-vm-name> \
  --project <project-id> \
  --zone <zone> \
  --tunnel-through-iap \
  -- -p 2222
```

The startup script configures sshd to listen on both port 22 and port 2222. A dedicated firewall rule (`sentinel-mgmt-ssh`) allows TCP/2222 traffic to sentinel-tagged VMs.

## Binary Server (Port 8888)

The sentinel serves the `containarium` binary on port 8888 so newly created spot VMs (without external IPs) can download it over the internal VPC network:

```bash
# Spot VM startup script downloads binary from sentinel
curl -fsSL http://<sentinel-internal-ip>:8888/binary -o /usr/local/bin/containarium
```

This avoids requiring Cloud NAT or external IP on the spot VM just to download the binary.

## CLI Reference

```bash
containarium sentinel [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | `gcp` | Cloud provider: `gcp`, `none` (local testing), or `tunnel` (reverse tunnel) |
| `--tunnel-token` | | Pre-shared token for tunnel auth (`tunnel` provider only) |
| `--spot-vm` | | Name of backend VM instance (required for GCP) |
| `--zone` | | GCP zone (required for GCP) |
| `--project` | | GCP project ID (required for GCP) |
| `--backend-addr` | | Direct backend IP (for `--provider=none`) |
| `--health-port` | `8080` | TCP port to health-check on backend |
| `--check-interval` | `15s` | Health check interval |
| `--healthy-threshold` | `2` | Consecutive healthy checks before PROXY |
| `--unhealthy-threshold` | `2` | Consecutive unhealthy checks before MAINTENANCE |
| `--http-port` | `80` | Maintenance page HTTP port |
| `--https-port` | `443` | Maintenance page HTTPS port |
| `--forwarded-ports` | `22,80,443,50051` | Comma-separated ports to DNAT forward |
| `--binary-port` | `8888` | Port to serve binary (0 to disable) |
| `--recovery-timeout` | `10m` | Warn if recovery exceeds this duration |
| `--cert-sync-interval` | `6h` | TLS cert sync interval |

### Service Management

```bash
# Install as systemd service
sudo containarium sentinel service install \
  --spot-vm <vm-name> \
  --zone <zone> \
  --project <project-id>

# View logs
sudo journalctl -u containarium-sentinel -f

# Restart
sudo systemctl restart containarium-sentinel
```

### Tunnel Mode (Firewalled Spots)

```bash
# Sentinel accepts reverse tunnel connections on port 443
containarium sentinel --provider=tunnel --tunnel-token SECRET

# Firewalled spot connects outbound to sentinel
containarium tunnel \
  --sentinel-addr sentinel.example.com:443 \
  --token SECRET \
  --spot-id my-spot \
  --ports 22,80,443,8080
```

See [TUNNEL-REVERSE-PROXY.md](TUNNEL-REVERSE-PROXY.md) for full details.

### Local Testing

```bash
# No GCP, no iptables — just health check and maintenance page
containarium sentinel \
  --provider=none \
  --backend-addr=127.0.0.1 \
  --health-port 8080 \
  --http-port 9090 \
  --https-port 9443
```

## Terraform Configuration

Enable sentinel with two variables:

```hcl
# terraform.tfvars
use_spot_instance = true
enable_sentinel   = true
```

This creates:

| Resource | Description |
|----------|-------------|
| `google_compute_instance.sentinel` | e2-micro, always-on, owns static IP |
| `google_compute_firewall.sentinel_ingress` | Allow 22/80/443 from internet |
| `google_compute_firewall.sentinel_mgmt_ssh` | Allow 2222 for management SSH |
| `google_compute_firewall.sentinel_to_spot` | Allow forwarded ports to spot VM |
| `google_compute_firewall.spot_to_sentinel_binary` | Allow spot VM to download binary (8888) |

### Key Terraform Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `enable_sentinel` | `false` | Enable sentinel HA proxy |
| `sentinel_region` | `us-west1` | Region (free tier: us-west1/us-central1/us-east1) |
| `sentinel_zone` | `us-west1-b` | Zone for sentinel VM |
| `sentinel_machine_type` | `e2-micro` | Machine type (e2-micro for free tier) |
| `sentinel_boot_disk_size` | `20` | Boot disk size in GB (up to 30 free) |

## Operational Runbook

### fail2ban Whitelist

The sentinel's TCP health checks can trigger fail2ban on the spot VM. Whitelist the sentinel's VPC subnet on the spot VM:

```bash
# On the spot VM
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 10.130.0.0/24
EOF
sudo systemctl restart fail2ban
```

### Observability

```bash
# Sentinel logs
sudo journalctl -u containarium-sentinel -f

# JSON status (always available)
curl -s http://<sentinel-ip>:8888/status | jq .

# Example log during preemption:
# [sentinel] EVENT: PREEMPTION detected (total: 3)
# [sentinel] mode: MAINTENANCE — serving maintenance page
# [sentinel] attempting to start backend VM...
# [sentinel] backend healthy (2 checks), switching to proxy (recovery: 1m25s)
```

### Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Can't SSH to sentinel in PROXY mode | Port 22 is DNAT'd to spot VM | Use `ssh -p 2222` for sentinel management |
| Browser TLS warning during maintenance | Cert sync hasn't run or certs inside Incus container | Check `/certs` endpoint on daemon; verify `--caddy-cert-dir` |
| Spot VM port 22 "connection refused" | fail2ban banned sentinel IP | `sudo fail2ban-client set sshd unbanip <sentinel-ip>` + add whitelist |
| Spot VM has leftover iptables rules | Previous sentinel run on spot VM | `sudo iptables -t nat -F SENTINEL_PREROUTING && sudo iptables -t nat -X SENTINEL_PREROUTING` |
| Recovery takes >10 minutes | GCP capacity issue or spot VM won't start | Check `gcloud compute instances describe <vm>` status; consider switching zones |

### Simulate Preemption

```bash
# Stop the spot VM (simulates preemption)
gcloud compute instances stop <spot-vm-name> \
  --project <project-id> \
  --zone <zone>

# Monitor sentinel recovery
ssh -p 2222 admin@<sentinel-ip> 'sudo journalctl -u containarium-sentinel -f'

# Verify maintenance page
curl -s http://<sentinel-ip>         # → 503 maintenance HTML
curl -s http://<sentinel-ip>/sentinel  # → status page

# VM recovers in ~60-90s, sentinel switches back to PROXY
```

## Scaling

### Single Server (20-50 users)

```
Sentinel (e2-micro) → Spot VM → 50 containers
```

### Horizontal (100-250 users)

```
Sentinel (e2-micro) → Spot VM 1 → 50 containers
                    → Spot VM 2 → 50 containers
                    → Spot VM 3 → 50 containers
```

One sentinel monitors all spot VMs. Each is independently recovered — one preemption doesn't affect the others. Add more spot VMs as needed.

### Cost

| Component | Cost |
|-----------|------|
| Sentinel VM (e2-micro, free tier) | $0 |
| Spot VM (c3d-highmem-8) | ~$98/mo |
| Persistent Disk (500GB) | ~$40/mo |
| **Total (single server)** | **~$138/mo** |

## Source Code

| File | Description |
|------|-------------|
| `internal/sentinel/manager.go` | Core orchestrator — mode switching, health checks, recovery |
| `internal/sentinel/certsync.go` | TLS certificate store and sync from backend |
| `internal/sentinel/maintenance.go` | HTTP/HTTPS maintenance servers |
| `internal/sentinel/status.go` | Status page handler |
| `internal/sentinel/status.html` | Status page HTML template |
| `internal/sentinel/maintenance.html` | Maintenance page HTML template |
| `internal/sentinel/binaryserver.go` | Binary download + JSON status server |
| `internal/sentinel/iptables.go` | iptables DNAT rule management |
| `internal/sentinel/provider_gcp.go` | GCP cloud provider (GetInstanceIP, StartInstance, event watcher) |
| `internal/sentinel/provider_none.go` | Local testing provider (no cloud, no iptables) |
| `internal/sentinel/tunnel_*.go` | Reverse tunnel: mux, server, client, registry, provider, auth |
| `internal/cmd/sentinel.go` | CLI flags and command wiring |
| `internal/cmd/tunnel.go` | `containarium tunnel` subcommand (spot-side client) |
| `internal/gateway/certs_handler.go` | Cert export endpoint on daemon side |
| `terraform/gce/sentinel.tf` | Terraform resources |
| `terraform/gce/scripts/startup-sentinel.sh` | Startup script template |

## Related Documents

- [TUNNEL-REVERSE-PROXY.md](TUNNEL-REVERSE-PROXY.md) — Reverse tunnel for firewalled spot instances
- [SPOT-RECOVERY.md](SPOT-RECOVERY.md) — Recovery timelines and MIG vs sentinel comparison
- [SPOT-INSTANCES-AND-SCALING.md](SPOT-INSTANCES-AND-SCALING.md) — Spot instance cost savings and scaling strategies
- [HORIZONTAL-SCALING-ARCHITECTURE.md](HORIZONTAL-SCALING-ARCHITECTURE.md) — Multi-server architectures
