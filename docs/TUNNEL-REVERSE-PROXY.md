# Reverse Tunnel for Firewalled Spot Instances

The reverse tunnel allows a spot VM behind a firewall (no inbound connectivity) to join the Containarium sentinel architecture. The spot VM initiates an **outbound** TCP connection to the sentinel's public IP on port 443, multiplexed alongside regular HTTPS traffic — no extra firewall port needed.

## Problem

The standard sentinel architecture assumes the spot VM is in the same VPC as the sentinel, reachable via its private IP. This doesn't work when:

- The spot VM is behind a corporate firewall that blocks inbound connections
- The spot VM is on a different network or cloud provider (e.g., bare metal)
- The spot VM is behind NAT with no port forwarding

## Solution

The spot VM connects **outbound** to the sentinel on port 443. The sentinel multiplexes tunnel and HTTPS traffic on the same port using first-byte protocol detection.

```
┌──────────────────────────────────────────────────────────────────┐
│                    Users (SSH / HTTP / HTTPS)                     │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│              Sentinel VM (always-on, public IP)                   │
│              Port 443: ConnMux                                    │
│                ├─ first byte '{' → TunnelServer (yamux)           │
│                └─ first byte 0x16 → HTTPS (raw TCP proxy to spot) │
│              Port 22: sshpiper → per-user routing to backends     │
│              Port 80: iptables DNAT → spot VM                     │
└──────────────────────────────────────────────────────────────────┘
                  ▲                               ▲
                  │ VPC internal                   │ outbound TCP:443
                  │                                │ (yamux-multiplexed)
┌─────────────────┴──────┐          ┌──────────────┴───────────────┐
│ GCP Spot VM (primary)   │          │ Bare Metal (secondary)       │
│ • Same VPC as sentinel  │          │ • Behind firewall            │
│ • Auto-restart on       │          │ • Runs tunnel client         │
│   preemption            │          │ • Connects outbound to 443   │
│ • Priority 0 (HTTP)     │          │ • Priority 10 (HTTP failover)│
└─────────────────────────┘          └──────────────────────────────┘
```

## How It Works

### 1. Port Multiplexing (ConnMux)

The sentinel's ConnMux listens on port 443 and peeks the first byte of each incoming connection:

| First byte | Protocol | Routing |
|-----------|----------|---------|
| `{` (0x7B) | Tunnel handshake (JSON) | → TunnelServer |
| `0x16` | TLS ClientHello | → Raw TCP proxy to spot VM's Caddy (SNI preserved) |

This works because the tunnel handshake is a JSON object (`{"token":...}`), while TLS always starts with byte `0x16`. No extra port is needed — tunnel and HTTPS share port 443.

In PROXY mode, HTTPS connections are forwarded as **raw TCP** to the spot VM (e.g., `10.130.0.15:443`). The TLS handshake (including SNI) is preserved end-to-end, so Caddy on the spot VM handles certificate selection and TLS termination as normal.

In MAINTENANCE mode, the sentinel itself terminates TLS and serves a 503 maintenance page.

The ConnMux uses a **dispatch listener** pattern: a single goroutine pulls connections from the channel and dispatches them to whichever handler is currently registered (proxy or maintenance). Swapping handlers is instant with no listener lifecycle issues.

### 2. Tunnel Handshake

When the spot connects to the sentinel on port 443:

```
Spot → Sentinel:  {"token":"SECRET","spot_id":"my-spot","ports":[22,80,443,8080]}
Sentinel → Spot:  {"ok":true,"assigned_ip":"127.0.0.2"}
```

After the handshake, the TCP connection is upgraded to a [yamux](https://github.com/hashicorp/yamux) multiplexed session.

### 3. Yamux Session

The yamux library multiplexes many logical streams over the single TCP connection:

- **Sentinel is the yamux client** (opens streams to "dial into" the spot)
- **Spot is the yamux server** (accepts streams and proxies to local ports)

When the sentinel needs to forward a connection to the spot (e.g., an SSH session), it opens a yamux stream, writes a 2-byte port header, then does bidirectional copy:

```
[2-byte port (big-endian)] [TCP data stream...]
```

The spot reads the port number, connects to `127.0.0.1:<port>` locally, and proxies the data.

#### Overriding the local dial target (`--forward`)

`127.0.0.1:<port>` is right when the advertised service listens on the spot's
own loopback (an LXC node's sshd, a local Caddy). A **K8s node** is different:
its box gateway is an in-cluster sshpiper reached through a Kubernetes
Service, and NodePorts are *not* reliably reachable on `127.0.0.1` (kube-proxy
`iptablesLocalhostNodePorts` is off by default). So the tunnel client accepts
a per-port dial override:

```bash
containarium tunnel --ports 32022 --forward 32022=<gateway-addr>
```

`<gateway-addr>` is the Service's reachable address — a LoadBalancer ingress
(`<lb>:22`) or `<nodeIP>:<NodePort>`. The daemon resolves and logs the
recommended value (`k8s.Backend.ResolveGatewayDialTarget`: LB ingress first,
else a node InternalIP + the NodePort). The port advertised to the sentinel
(via `/authorized-keys` `ssh_port`) and the tunnel listener stay on the same
number; only the *local* dial target changes. See
[MULTI-BACKEND-PEERS.md](MULTI-BACKEND-PEERS.md#k8s-runtime-backends-a-second-gateway-hop).

### 4. Loopback Aliases

Each connected tunnel spot gets a loopback alias on the sentinel (e.g., `127.0.0.2`). The tunnel server opens TCP proxy listeners on `127.0.0.2:<port>` for each advertised port. This makes the tunneled spot look like a directly reachable IP to the existing sentinel code:

- Health checks dial `127.0.0.2:8080` → tunneled to spot's daemon
- sshpiper connects to `127.0.0.2:22` → tunneled to spot's sshd
- Key sync calls `http://127.0.0.2:8080/authorized-keys` → tunneled to spot

### 5. Multi-Backend Routing

In hybrid mode (GCP + tunnel), the sentinel tracks multiple backends:

**HTTP/HTTPS**: the ConnMux's dispatch handler proxies to the primary backend's IP. GCP has priority 0 (preferred), tunnel has priority 10 (failover). When GCP is preempted, HTTPS automatically switches to the tunnel backend.

**SSH**: sshpiper generates per-user routing. Each user's config points to the backend they were synced from:

```yaml
pipes:
  - from:
      - username: "alice"    # synced from GCP
    to:
      host: 10.130.0.15:22  # routes to GCP spot VM
  - from:
      - username: "bob"      # synced from tunnel
    to:
      host: 127.0.0.2:22    # routes to bare metal via tunnel
```

### 6. Authentication

Phase 1 uses a pre-shared token. The spot includes the token in its JSON handshake. The sentinel validates it before accepting the connection.

The token is configured via `--tunnel-token` flag or `CONTAINARIUM_TUNNEL_TOKEN` environment variable.

## Usage

### Hybrid Mode (GCP + Tunnel) — Recommended for Production

Add `--tunnel-token` to your existing GCP sentinel command:

```bash
# Generate a strong token
TOKEN=$(openssl rand -hex 32)

# Sentinel (add --tunnel-token to existing command)
containarium sentinel \
  --spot-vm my-spot-vm --zone us-west1-a --project my-project \
  --tunnel-token "$TOKEN" \
  --forwarded-ports 80,443
```

This gives you:
- **GCP spot VM** as the primary backend (auto-restart on preemption)
- **Bare metal** as a secondary backend (connects via tunnel)
- **Automatic failover**: if GCP is preempted, HTTPS switches to the tunnel backend
- **Per-user SSH routing**: sshpiper routes each user to whichever backend they belong to
- **Independent health checks**: each backend is monitored separately

### Bare Metal Side

```bash
containarium tunnel \
  --sentinel-addr sentinel.example.com:443 \
  --token "$TOKEN" \
  --spot-id baremetal-1 \
  --ports 22,80,443,8080
```

The tunnel client:
1. Connects outbound to the sentinel's port 443
2. Authenticates with the pre-shared token
3. Establishes a yamux session
4. Accepts stream requests and proxies to local ports
5. Reconnects automatically with exponential backoff on disconnect

### Pure Tunnel Mode (no GCP)

```bash
containarium sentinel \
  --provider=tunnel \
  --tunnel-token SECRET \
  --forwarded-ports 80,443
```

### Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `CONTAINARIUM_TUNNEL_TOKEN` | Both | Pre-shared token (alternative to `--tunnel-token`/`--token`) |

## Hybrid Mode Failover

In hybrid mode, the sentinel manages multiple backends with automatic failover:

```
GCP healthy + Tunnel healthy    → PROXY via GCP (primary), SSH routes to both
GCP preempted + Tunnel healthy  → PROXY via Tunnel (failover), sentinel restarts GCP VM
GCP healthy + Tunnel disconnects → PROXY via GCP (no interruption)
Both down                       → MAINTENANCE page served
GCP recovers                    → PROXY via GCP (failback to primary)
```

**HTTP/HTTPS routing**: always goes to the highest-priority healthy backend (GCP=0 > Tunnel=10).

**SSH routing**: per-user — each user is routed to the backend they were synced from. GCP users keep SSHing to GCP, and bare metal users SSH to the tunnel backend, regardless of which backend is primary for HTTP.

## Data Flow Examples

### HTTPS Request (hybrid mode, GCP primary)

```
User browser
  → sentinel:443 (TCP)
  → ConnMux peeks first byte: 0x16 (TLS) → dispatch to HTTPS proxy
  → raw TCP proxy to 10.130.0.15:443 (GCP spot VM)
  → Caddy handles TLS (SNI preserved), serves response
```

### HTTPS Request (pure tunnel mode)

```
User browser
  → sentinel:443 (TCP)
  → ConnMux peeks first byte: 0x16 (TLS) → dispatch to HTTPS proxy
  → raw TCP proxy to 127.0.0.2:443 (loopback alias)
  → TCP proxy listener → yamux stream (port 443)
  → spot's tunnel client → 127.0.0.1:443 on spot (Caddy)
```

### SSH Connection (per-user routing)

```
User SSH (alice@sentinel)
  → sentinel:22 → sshpiper
  → config says alice → 10.130.0.15:22 (GCP)
  → SSH to GCP spot VM

User SSH (bob@sentinel)
  → sentinel:22 → sshpiper
  → config says bob → 127.0.0.2:22 (tunnel)
  → yamux stream → 127.0.0.1:22 on bare metal
```

### Tunnel Handshake (bare metal connecting)

```
Bare metal
  → outbound TCP to sentinel:443
  → ConnMux peeks first byte: '{' → tunnel server
  → JSON handshake: {"token":"...", "spot_id":"baremetal-1", "ports":[22,80,443,8080]}
  → sentinel validates token, assigns 127.0.0.2
  → yamux session established
  → sentinel starts proxy listeners on 127.0.0.2:*
  → sentinel registers backend, starts health checks + key sync
```

## Requirements

### Sentinel

- Linux (for iptables DNAT and loopback aliases)
- Port 443 open for inbound (already required for HTTPS)
- `net.ipv4.conf.all.route_localnet=1` sysctl (set automatically when DNAT targets loopback)

### Firewalled Spot VM / Bare Metal

- **Outbound TCP to port 443** on the sentinel's public IP (most firewalls allow this)
- No inbound ports needed
- Running containarium daemon and services locally (sshd, Caddy, etc.)
- The `containarium` binary installed
- Go toolchain (to build from source) or pre-built binary

## Comparison with Standard Sentinel

| Aspect | Standard (same VPC) | Hybrid (GCP + Tunnel) |
|--------|--------------------|-----------------------|
| Backends | Single GCP spot VM | GCP spot + bare metal |
| Spot → Sentinel | VPC internal IP | GCP: VPC IP, Bare metal: outbound TCP:443 |
| Extra ports | None | None (shares 443 via ConnMux) |
| Latency | Sub-millisecond | GCP: same, Tunnel: ~1-10ms (internet + yamux) |
| Auto-recovery | Sentinel restarts VM | GCP: auto-restart, Bare metal: must reconnect |
| HTTP failover | N/A (single backend) | GCP → Tunnel if GCP down |
| SSH routing | All users → one backend | Per-user routing to correct backend |
| Health check | TCP to VPC IP | Per-backend independent checks |

## Testing

### Run all tunnel tests locally

```bash
go test ./internal/sentinel/ -run "TestTunnel|TestConnMux" -v
```

### Integration test

The `TestTunnelIntegration` test verifies the full flow on localhost:

```bash
go test ./internal/sentinel/ -run TestTunnelIntegration -v
```

### What requires Linux to test

- iptables DNAT to loopback aliases (127.0.0.2)
- sshpiper integration
- Full proxy mode port forwarding

## Security Considerations

- The tunnel token should be a strong random secret (e.g., `openssl rand -hex 32`)
- The tunnel rides on port 443 alongside HTTPS — anyone can attempt a handshake
- Invalid tokens are rejected before yamux session creation
- Future: upgrade to mutual TLS for stronger authentication
- The yamux session carries all traffic unencrypted between sentinel and spot — consider wrapping with TLS for internet transit

## Source Code

| File | Description |
|------|-------------|
| `internal/sentinel/backend.go` | Backend type, BackendPool with health tracking and primary selection |
| `internal/sentinel/tunnel_mux.go` | ConnMux: first-byte protocol detection, dispatchListener, chanListener |
| `internal/sentinel/tunnel_server.go` | TunnelServer: accepts connections, yamux client, local TCP proxies |
| `internal/sentinel/tunnel_client.go` | TunnelClient: outbound connection, yamux server, port forwarding |
| `internal/sentinel/tunnel_registry.go` | TunnelRegistry: spot tracking, loopback alias management |
| `internal/sentinel/tunnel_provider.go` | TunnelProvider: CloudProvider impl using tunnel state |
| `internal/sentinel/tunnel_auth.go` | Handshake types, JSON encode/decode, token validation |
| `internal/sentinel/tunnel_test.go` | Unit tests: handshake, registry, E2E, wrong token, ConnMux |
| `internal/sentinel/tunnel_integration_test.go` | Full integration test with mock spot services |
| `internal/sentinel/manager.go` | Multi-backend Manager with failover, dispatch-based HTTPS routing |
| `internal/sentinel/keysync.go` | Multi-backend KeyStore with per-user sshpiper routing |
| `internal/cmd/tunnel.go` | `containarium tunnel` CLI subcommand |
| `internal/cmd/sentinel.go` | `--provider=tunnel` and hybrid mode wiring |

## Related Documents

- [SENTINEL-DESIGN.md](SENTINEL-DESIGN.md) — Standard sentinel architecture
- [SPOT-RECOVERY.md](SPOT-RECOVERY.md) — Recovery timelines
- [SSH-JUMP-SERVER-SETUP.md](SSH-JUMP-SERVER-SETUP.md) — sshpiper configuration
