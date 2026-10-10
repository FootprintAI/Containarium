# Reverse Tunnel for Firewalled Spot Instances

The reverse tunnel allows a spot VM behind a firewall (no inbound connectivity) to join the Containarium sentinel architecture. The spot VM initiates an **outbound** TCP connection to the sentinel's public IP on port 443, multiplexed alongside regular HTTPS traffic — no extra firewall port needed.

## Problem

The standard sentinel architecture assumes the spot VM is in the same VPC as the sentinel, reachable via its private IP. This doesn't work when:

- The spot VM is behind a corporate firewall that blocks inbound connections
- The spot VM is on a different network or cloud provider (e.g., bare metal)
- The spot VM is behind NAT with no port forwarding

## Solution

The spot VM connects **outbound** to the sentinel on port 443. The sentinel multiplexes tunnel and HTTPS traffic on the same port: tunnel sessions are TLS connections that offer the `containarium-tunnel/1` ALPN protocol, so they are told apart from ordinary HTTPS by the ClientHello alone.

```
┌──────────────────────────────────────────────────────────────────┐
│                    Users (SSH / HTTP / HTTPS)                     │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│              Sentinel VM (always-on, public IP)                   │
│              Port 443: ConnMux                                    │
│                ├─ TLS + ALPN containarium-tunnel/1 → TunnelServer │
│                ├─ first byte '{' → TunnelServer (legacy handshake)│
│                └─ other TLS → HTTPS (raw TCP proxy to spot)       │
│              Port 22: sshpiper → per-user routing to backends     │
│              Port 80: iptables DNAT → spot VM                     │
└──────────────────────────────────────────────────────────────────┘
                  ▲                               ▲
                  │ VPC internal                   │ outbound TLS:443
                  │                                │ (yamux inside TLS)
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

The sentinel's ConnMux listens on port 443 and peeks the start of each incoming connection. For a TLS ClientHello it reads the SNI and ALPN extensions without consuming any bytes:

| First bytes | ALPN | Routing |
|-------------|------|---------|
| `0x16` (TLS ClientHello) | offers `containarium-tunnel/1` | → TunnelServer (TLS terminated with the tunnel identity) |
| `0x16` (TLS ClientHello) | anything else, or none | → Raw TCP proxy to spot VM's Caddy (SNI preserved) |
| `{` (0x7B) | — | → TunnelServer, legacy cleartext handshake (see [Upgrading](#upgrading-to-the-tls-transport)) |

ALPN is used rather than a reserved SNI name because it cannot collide with browser or HTTP traffic. No extra port is needed — tunnel and HTTPS share port 443.

In PROXY mode, HTTPS connections are forwarded as **raw TCP** to the spot VM (e.g., `10.130.0.15:443`). The TLS handshake (including SNI) is preserved end-to-end, so Caddy on the spot VM handles certificate selection and TLS termination as normal.

In MAINTENANCE mode, the sentinel itself terminates TLS and serves a 503 maintenance page.

The ConnMux uses a **dispatch listener** pattern: a single goroutine pulls connections from the channel and dispatches them to whichever handler is currently registered (proxy or maintenance). Swapping handlers is instant with no listener lifecycle issues.

### 2. Transport and Tunnel Handshake

The spot opens a TLS 1.3 connection to the sentinel's port 443:

- **ALPN** `containarium-tunnel/1`; **SNI** is the host part of `--sentinel-addr`.
- The sentinel presents its **tunnel identity**: a long-lived ECDSA P-256 key with a self-signed certificate, kept in the file named by `--tunnel-tls-identity` (default `/etc/containarium/sentinel-tunnel-identity.pem`).
- The client accepts the sentinel only if the SHA-256 of the certificate's SubjectPublicKeyInfo matches one of its configured pins (`--sentinel-pin sha256:<hex>`). Certificate dates, subject and issuer are not checked: the pin authenticates a key. If no pin matches, the client closes the connection before sending any handshake bytes and retries with backoff. The client never falls back to a cleartext connection.

Inside the TLS session the spot sends **handshake v2**, one JSON line:

```
Spot → Sentinel:  {"v":2,"token_id":"<16 hex>","proof":"<base64>","spot_id":"my-spot","ports":[22,80,443,8080]}
Sentinel → Spot:  {"ok":true,"assigned_ip":"127.0.0.2"}
```

- `token_id` is the first 16 hex characters of SHA-256(token); it lets the sentinel look up the token without receiving it.
- `proof` is `base64(HMAC-SHA256(key = token, msg = EKM))`, where EKM is 32 bytes of TLS exported keying material (label `containarium-tunnel-token-proof/1`, RFC 8446 §7.5). The EKM is unique to the TLS session, so a proof is valid for that session only.
- The sentinel recomputes the proof on its side of the session, compares in constant time, then applies the token's pool policy as before. A handshake inside TLS that carries a raw `token` field is rejected.

After the handshake, the TLS connection carries a [yamux](https://github.com/hashicorp/yamux) multiplexed session.

### 3. Yamux Session

The yamux library multiplexes many logical streams over the single TLS connection:

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

- **Sentinel → spot**: the spot authenticates the sentinel by its tunnel identity pin (TLS, see above).
- **Spot → sentinel**: the spot proves possession of a pre-shared token, bound to the TLS session (handshake v2). The sentinel validates the proof and the token's pool policy before creating the yamux session.

The token is configured via `--tunnel-token` / `--tunnel-token-policy` (or `CONTAINARIUM_TUNNEL_TOKEN`) on the sentinel and `--token` (or `CONTAINARIUM_TUNNEL_TOKEN`) on the spot. The pin is configured via `--sentinel-pin` (or `CONTAINARIUM_TUNNEL_SENTINEL_PIN`) on the spot.

#### Tunnel identity and pin

The sentinel creates its tunnel identity on first start if the file does not exist (mode `0600`, parent directory `0700`), and reuses it on every later start. Each start logs the pin:

```
[sentinel] generated tunnel identity at /etc/containarium/sentinel-tunnel-identity.pem; pin sha256:…
```

Print it at any time on the sentinel host:

```bash
containarium sentinel tunnel-identity
# sha256:<64 hex>
```

`tunnel-identity` only reads the file; it fails if the sentinel has not created it yet. The pin is public and can be distributed freely; the identity file is not, and must be kept across sentinel redeploys, since every tunnel client pins it. A file that exists but cannot be read stops the sentinel instead of being replaced.

**Rotation**: prepare a new identity file (for example by starting a throwaway sentinel with a different `--tunnel-tls-identity` path) and read its pin with `tunnel-identity --tunnel-tls-identity <path>`; add that pin to every client's comma-separated `--sentinel-pin` list; swap the identity file on the sentinel and restart it; then remove the old pin from the clients.

## Usage

### Hybrid Mode (GCP + Tunnel) — Recommended for Production

Add `--tunnel-token` to your existing GCP sentinel command, then read the sentinel's pin:

```bash
# Generate a strong token
TOKEN=$(openssl rand -hex 32)

# Sentinel (add --tunnel-token to existing command)
containariumd sentinel \
  --spot-vm my-spot-vm --zone us-west1-a --project my-project \
  --tunnel-token "$TOKEN" \
  --backend-base-domain example.com \
  --forwarded-ports 80,443

# On the sentinel host, after the first start
PIN=$(containarium sentinel tunnel-identity)
```

`--backend-base-domain` (with `--backend-hostname` / `--backend-alias` as needed) declares the domains the GCP spot VM serves. The sentinel serves a backend's synced certificates only for that backend's own domains, so set these **before** upgrading an existing hybrid sentinel; without them the GCP backend's certificates are not served and the maintenance page falls back to a self-signed certificate. Tunnel backends are scoped by their `--public-hostname` / `--public-aliases` / `--public-base-domain`. See [Per-Backend Certificate Scoping](SENTINEL-DESIGN.md#per-backend-certificate-scoping).

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
  --sentinel-pin "$PIN" \
  --spot-id baremetal-1 \
  --ports 22,80,443,8080
```

The tunnel client:
1. Connects outbound to the sentinel's port 443 over TLS and verifies the sentinel's pin
2. Proves possession of the pre-shared token (handshake v2)
3. Establishes a yamux session
4. Accepts stream requests and proxies to local ports
5. Reconnects automatically with exponential backoff on disconnect

### Pure Tunnel Mode (no GCP)

```bash
containariumd sentinel \
  --provider=tunnel \
  --tunnel-token SECRET \
  --forwarded-ports 80,443
```

### Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `CONTAINARIUM_TUNNEL_TOKEN` | Both | Pre-shared token (alternative to `--tunnel-token`/`--token`) |
| `CONTAINARIUM_TUNNEL_SENTINEL_PIN` | Tunnel client | Sentinel pin list (alternative to `--sentinel-pin`) |

### Sentinel Tunnel Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--tunnel-tls-identity` | `/etc/containarium/sentinel-tunnel-identity.pem` | Tunnel identity file; created on first start if absent |
| `--tunnel-allow-cleartext` | `true` | Also accept the legacy cleartext handshake from older clients; set `false` once every client uses TLS |

### Upgrading to the TLS Transport

Upgrade in this order:

1. **Sentinels first.** A new sentinel accepts both TLS sessions and the legacy cleartext handshake while `--tunnel-allow-cleartext=true` (the default). Existing tunnel clients keep working. Each cleartext registration logs a `DEPRECATED` line naming the spot.
2. **Distribute pins.** Run `containarium sentinel tunnel-identity` on each sentinel and add the pin to every tunnel client's configuration (`--sentinel-pin` or `CONTAINARIUM_TUNNEL_SENTINEL_PIN`).
3. **Then tunnel clients.** An upgraded client requires a pin and only speaks TLS. Against a sentinel that has not been upgraded it fails the pin check, sends nothing, and keeps retrying, so upgrade the sentinel before its clients.
4. **Refuse cleartext.** When `sentinel_tunnel_sessions_cleartext` on the sentinel's `/metrics` stays at zero, restart the sentinel with `--tunnel-allow-cleartext=false`. A cleartext peer then receives `{"ok":false,"error":"tls required; …"}` without its handshake being read, and `sentinel_tunnel_cleartext_refused_total` counts it.

The sentinel's `/metrics` exposes `sentinel_tunnel_sessions_tls`, `sentinel_tunnel_sessions_cleartext` and `sentinel_tunnel_cleartext_refused_total`; the status page shows the session counts by transport.

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
  → outbound TCP to sentinel:443, TLS ClientHello with ALPN containarium-tunnel/1
  → ConnMux sees the tunnel ALPN → tunnel server terminates TLS with the tunnel identity
  → client verifies the sentinel's pin
  → handshake v2: {"v":2, "token_id":"...", "proof":"...", "spot_id":"baremetal-1", "ports":[22,80,443,8080]}
  → sentinel verifies the proof against this TLS session, assigns 127.0.0.2
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
- The sentinel's tunnel identity pin
- No inbound ports needed
- Running containariumd daemon and services locally (sshd, Caddy, etc.)
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

- Tunnel sessions are carried over TLS 1.3; the yamux session and every stream inside it are encrypted between spot and sentinel.
- The spot authenticates the sentinel by a pinned public key, never by trust on first use. Pins come from `containarium sentinel tunnel-identity` (or the sentinel's startup log) and are configured explicitly on each client.
- The token is not sent over the network: the spot sends a token id and an HMAC proof bound to the TLS session's exported keying material, so a proof cannot be reused in another session.
- The tunnel token should be a strong random secret (e.g., `openssl rand -hex 32`).
- The tunnel rides on port 443 alongside HTTPS — anyone can attempt a handshake. Invalid proofs and tokens are rejected before yamux session creation.
- Keep the identity file (`0600`) private and persistent: whoever holds it can present the sentinel's identity, and replacing it means distributing a new pin to every client.
- While `--tunnel-allow-cleartext=true`, the legacy cleartext handshake is still accepted for older clients. Set it to `false` once the cleartext session gauge stays at zero (see [Upgrading](#upgrading-to-the-tls-transport)).
- Client certificates (mutual TLS) for the spot side are a possible future addition; today the spot is authenticated by its token proof.

## Source Code

| File | Description |
|------|-------------|
| `internal/sentinel/backend.go` | Backend type, BackendPool with health tracking and primary selection |
| `internal/sentinel/tunnel_mux.go` | ConnMux: ClientHello ALPN / first-byte routing, dispatchListener, chanListener |
| `internal/sentinel/tunnel_identity.go` | Tunnel identity (key + self-signed cert), pin format, pin verifier |
| `internal/sentinel/tunnel_server.go` | TunnelServer: accepts connections, yamux client, local TCP proxies |
| `internal/sentinel/tunnel_client.go` | TunnelClient: outbound connection, yamux server, port forwarding |
| `internal/sentinel/tunnel_registry.go` | TunnelRegistry: spot tracking, loopback alias management |
| `internal/sentinel/tunnel_provider.go` | TunnelProvider: CloudProvider impl using tunnel state |
| `internal/sentinel/tunnel_auth.go` | Handshake types (v1 and v2), JSON encode/decode, token and proof validation |
| `internal/sentinel/tunnel_test.go` | Unit tests: handshake, registry, E2E, wrong token, ConnMux |
| `internal/sentinel/tunnel_integration_test.go` | Full integration test with mock spot services |
| `internal/sentinel/manager.go` | Multi-backend Manager with failover, dispatch-based HTTPS routing |
| `internal/sentinel/keysync.go` | Multi-backend KeyStore with per-user sshpiper routing |
| `internal/cmd/tunnel.go` | `containarium tunnel` CLI subcommand |
| `internal/cmd/sentinel.go` | `--provider=tunnel` and hybrid mode wiring, tunnel transport flags |
| `internal/cmd/sentinel_tunnel_identity.go` | Identity bootstrap at startup, `containarium sentinel tunnel-identity` |

## Related Documents

- [SENTINEL-DESIGN.md](SENTINEL-DESIGN.md) — Standard sentinel architecture
- [SPOT-RECOVERY.md](SPOT-RECOVERY.md) — Recovery timelines
- [SSH-JUMP-SERVER-SETUP.md](SSH-JUMP-SERVER-SETUP.md) — sshpiper configuration
