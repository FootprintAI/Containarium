# Multi-Backend Peer Architecture

The peer system allows a single Containarium deployment to manage containers across multiple backend hosts. The primary daemon (on the GCP spot VM) aggregates containers from all backends, forwarding operations to the correct host transparently.

## Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    Users (SSH / HTTP / WebSocket)                  │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│              Sentinel VM (always-on, public IP)                    │
│              Port 22: sshpiper (routes by username)                │
│              Port 443: ConnMux (HTTPS + tunnel multiplexing)      │
│              Port 8888: binary server + peer API proxy            │
│                                                                    │
│              Loopback aliases per tunnel backend:                  │
│                127.0.0.x:20022 → tunnel → backend SSH             │
│                127.0.0.x:8080  → tunnel → backend API             │
└───────────┬──────────────────────────────┬───────────────────────┘
            │ VPC internal                 │ yamux tunnel (outbound)
            ▼                              ▼
┌────────────────────────┐    ┌──────────────────────────────────┐
│ GCP Spot VM (primary)  │    │ Bare Metal / Remote Host          │
│ • Same VPC as sentinel │    │ • Behind firewall / NAT           │
│ • Runs primary daemon  │    │ • Runs daemon (--standalone)      │
│ • Aggregates all peers │    │ • Runs tunnel client              │
│ • Hosts WebUI + API    │    │ • Connects outbound to :443       │
│ • Direct IP reachable  │    │ • IP not reachable from sentinel  │
│                        │    │                                    │
│  Incus containers:     │    │  Incus containers:                │
│  ├─ hsin-container     │    │  ├─ test-4090-container (GPU)     │
│  ├─ api-container      │    │  └─ ml-training-container         │
│  └─ devbox-container   │    │                                    │
└────────────────────────┘    └──────────────────────────────────┘
```

## Peer Discovery

The primary daemon discovers peers via the sentinel's `/sentinel/peers` endpoint (polled every 30 seconds). Each tunnel-connected backend appears as a peer with a proxy path through the sentinel.

```go
// PeerPool auto-discovers tunnel backends from sentinel
pool := NewPeerPool("spot-vm-id", "http://sentinel:8888", nil)
pool.StartDiscovery(ctx)
```

Peer addresses follow the format: `sentinel-host:8888/peer/{backend-id}`

## Operation Routing

All container operations follow the same pattern:

1. Try the operation locally
2. On failure (container not found), search all healthy peers
3. Forward the request to the peer that owns the container

### Supported Peer Operations

| Operation | Method | Peer Path |
|---|---|---|
| List Containers | Fan-out GET | `/v1/containers` (all peers) |
| Create Container | POST | `/v1/containers` (target peer by `backend_id`) |
| Get Container | GET | `/v1/containers/{username}` |
| Delete Container | DELETE | `/v1/containers/{username}` |
| Start/Stop | POST | `/v1/containers/{username}/start\|stop` |
| Resize | PUT | `/v1/containers/{username}/resize` |
| Cleanup Disk | POST | `/v1/containers/{username}/cleanup-disk` |
| Add Collaborator | POST | `/v1/containers/{owner}/collaborators` |
| Remove Collaborator | DELETE | `/v1/containers/{owner}/collaborators/{collab}` |
| List Collaborators | GET | `/v1/containers/{owner}/collaborators` |
| Terminal (WebSocket) | WS | `/v1/containers/{username}/terminal` |
| System Info | GET | `/v1/backends/{id}/system-info` |

### List Containers (fan-out)

The primary daemon merges local containers with results from all healthy peers. Each container is tagged with `backend_id` so the UI can display which host it runs on.

```
Primary daemon                    Peer (tunnel backend)
     │                                  │
     ├─ List local containers           │
     ├─ GET /v1/containers ────────────►│
     │◄──── [{name, state, ...}] ──────┤
     ├─ Tag each with backend_id        │
     └─ Merge and return all            │
```

### Terminal WebSocket Proxy

Terminal sessions for peer containers are proxied at the WebSocket level:

```
Browser  ─ws─►  Gateway  ─ws─►  Peer (via sentinel tunnel)
                   │
                   ├─ PeerTerminalProxy.PeerTerminalURL(username)
                   │  → "ws://sentinel:8888/peer/{id}/v1/containers/{user}/terminal"
                   │
                   └─ Bidirectional WebSocket bridge (client ↔ peer)
```

## SSH Access

SSH access works through sshpiper on the sentinel, which routes connections by username to the correct backend host.

### Connection Flow

```
Client                  Sentinel (sshpiper)           Backend Host
  │                          │                            │
  ├─ ssh user@sentinel ─────►│                            │
  │                          ├─ Match username in config   │
  │                          ├─ Route to backend:          │
  │                          │   Same VPC: host:22         │
  │                          │   Tunnel:   127.0.0.x:20022 │
  │                          │   K8s node: host:<ssh_port> │
  │                          ├─ Auth with upstream key ───►│
  │                          │                            ├─ sshd accepts key
  │                          │                            ├─ containarium-shell
  │                          │                            ├─ incus exec {user}-container
  │◄─── interactive shell ───┤◄───────────────────────────┤
```

### K8s-runtime backends: a second gateway hop

An LXC backend runs its own sshd on the routed port (22, or 20022 through a
tunnel). A **K8s-runtime node** has no per-box sshd on the host — boxes are
pods, reached through an *in-cluster* sshpiper. So the sentinel forwards to
that node's gateway ingress rather than to :22, and the chain grows a hop:

```
agent ──agent key──▶ sentinel sshpiper ──sentinel upstream key──▶
    node in-cluster sshpiper (NodePort/LB) ──node upstream key──▶ box pod → agent-box MCP
```

Each key is scoped to one hop (a leak reaches one hop, not the cluster). The
mechanism reuses the existing sentinel plumbing:

- The node's daemon advertises its gateway SSH ingress in the
  `/authorized-keys` response (`ssh_port`); keysync routes `username →
  <backend>:<ssh_port>` instead of assuming :22. Absent/0 keeps the legacy
  22/20022 convention, so LXC backends and old daemons are unchanged.
- The node serves `/authorized-keys` from box metadata (the agent keys the
  K8s backend records per tenant) — there is no `/home` on a K8s node.
- When the sentinel pushes its upstream key, the node authorizes it at its
  in-cluster gateway (appended to every box's sshpiper Pipe), not in box home
  dirs. Requires gateway-upstream mode.

For a **tunnel-attached** K8s node, the tunnel must forward the advertised
gateway port to the in-cluster sshpiper Service's *reachable* address — a
LoadBalancer ingress, or `<nodeIP>:<NodePort>` (NodePorts aren't reliably
reachable on 127.0.0.1). Use `containarium tunnel --forward
<port>=<addr>`; the daemon logs the resolved target
(`ResolveGatewayDialTarget`: LB ingress first, else node InternalIP +
NodePort). See [TUNNEL-REVERSE-PROXY.md](TUNNEL-REVERSE-PROXY.md).

> **Username collisions** are resolved first-backend-wins (by backend-ID
> sort) — the same exposure the LXC multi-backend fleet has today. Box names
> are globally unique in practice, so this is a note, not a guard.

### containarium-shell

A login shell (`/usr/local/bin/containarium-shell`) installed on backend hosts that proxies SSH sessions into containers:

```bash
#!/bin/bash
USERNAME="$(whoami)"
CONTAINER="${USERNAME}-container"
# For command execution (ssh host "cmd"):
#   sudo incus exec $CONTAINER --mode non-interactive -- su - $USERNAME -c "$SSH_ORIGINAL_COMMAND"
# For interactive sessions:
#   sudo incus exec $CONTAINER -t -- su -l $USERNAME
```

Install with: `sudo bash scripts/setup-ssh-container-proxy.sh`

This replaces `/usr/sbin/nologin` for containarium users. The daemon auto-detects the wrapper at startup — if present, new users get `containarium-shell`; otherwise they get `nologin` (for legacy ProxyJump setups).

### SSH Config (Client)

```ssh-config
# All backends (recommended)
Host my-container
    HostName containarium.example.com
    User my-username
    IdentityFile ~/.ssh/my-key

# Legacy: ProxyJump with container IP (same-VPC backends only)
Host my-container
    HostName 10.0.3.100
    User my-username
    IdentityFile ~/.ssh/my-key
    ProxyJump jump-host
```

### Tunnel SSH Port (20022)

sshpiper binds `*:22` on the sentinel for user-facing SSH. The tunnel server cannot also bind port 22 on loopback aliases. Instead, it uses port 20022:

- Tunnel proxy: `127.0.0.x:20022` → yamux → remote backend port 22
- sshpiper config for tunnel users: `host: 127.0.0.x:20022`
- sshpiper config for VPC users: `host: 10.x.x.x:22` (direct)

## GPU Passthrough

Containers can request GPU passthrough via the `gpu` field in `CreateContainerRequest`. The GPU device is passed through to the Incus container using the Incus GPU device type.

### System Info GPU Detection

The `/v1/system/info` endpoint (and per-backend `/v1/backends/{id}/system-info`) reports GPU devices using proto enums:

```protobuf
enum GPUVendor {
  GPU_VENDOR_UNSPECIFIED = 0;
  GPU_VENDOR_NVIDIA = 1;
  GPU_VENDOR_AMD = 2;
  GPU_VENDOR_INTEL = 3;
}

enum GPUModel {
  GPU_MODEL_UNSPECIFIED = 0;
  GPU_MODEL_NVIDIA_RTX_4090 = 100;
  GPU_MODEL_NVIDIA_A100 = 200;
  GPU_MODEL_NVIDIA_H100 = 203;
  // ... (see proto/containarium/v1/config.proto for full list)
}

message GPUInfo {
  GPUVendor vendor = 1;
  GPUModel model = 2;
  string model_name = 3;    // raw driver string for unknown models
  string pci_address = 4;
  string driver_version = 5;
  string cuda_version = 6;
  int64 vram_bytes = 7;
}
```

GPU info is populated from Incus `GetServerResources().GPU.Cards`, with NVIDIA-specific enrichment from the `Nvidia` sub-struct (driver version, CUDA version, model name).

## Web UI

### Node Filter

When containers span multiple backends, the UI shows:
- **Search box**: Filter by container name, username, or IP
- **Node dropdown**: Filter by backend (only appears with 2+ backends)
- **Backend chip**: Each container card shows its `backendId`

### System Resources Card

A toggle button group lets users switch between backends to view per-host CPU, memory, disk, and GPU stats. Data is fetched from `/v1/backends/{id}/system-info`.

## Adding a New Backend

1. **Install Containarium** on the new host
2. **Run in standalone mode**: `containarium daemon --standalone --rest --jwt-secret-file /etc/containarium/jwt.secret`
3. **Run tunnel client**: `containarium tunnel --sentinel-addr sentinel:443 --token <token> --spot-id <id> --ports 22,8080`
4. **Install containarium-shell**: `sudo bash scripts/setup-ssh-container-proxy.sh`
5. The sentinel auto-discovers the new backend within 30 seconds
6. Containers created with `backend_id: "<id>"` will be placed on the new host
