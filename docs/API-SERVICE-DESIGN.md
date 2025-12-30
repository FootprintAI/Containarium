# Containarium API + Service Design (Phase 7)

This document outlines the design for exposing Containarium as an API service with a daemon.

## Current State (Phase 6)

**How it works now**:
```
You → SSH to jump server → Run: sudo containarium create alice
```

**Problems**:
- ❌ Must SSH to each jump server manually
- ❌ No remote management
- ❌ No central view of all containers across servers
- ❌ No API for automation
- ❌ Can't build Web UI on top

---

## Proposed Architecture (Phase 7)

### Overview

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  Web UI      │────────▶│  API Gateway │────────▶│  Jump-1      │
│  (Future)    │         │  (Optional)  │    │    │  + Daemon    │
└──────────────┘         └──────────────┘    │    └──────────────┘
                                              │
┌──────────────┐                             │    ┌──────────────┐
│  CLI Client  │─────────────────────────────┼───▶│  Jump-2      │
│  (Enhanced)  │                             │    │  + Daemon    │
└──────────────┘                             │    └──────────────┘
                                              │
┌──────────────┐                             │    ┌──────────────┐
│  Automation  │                             └───▶│  Jump-3      │
│  Scripts     │                                  │  + Daemon    │
└──────────────┘                                  └──────────────┘
```

### Daemon Deployment: Host vs Container

**DECISION: Daemon runs on HOST, not in container**

```
GCE VM (Host OS - Ubuntu 24.04)
├─ systemd service: containarium daemon (port 50051)  ← Runs HERE
│  └─ Connects to: /var/lib/incus/unix.socket
│
└─ LXC Containers (managed by daemon):
   ├─ alice-container
   ├─ bob-container
   └─ charlie-container
```

**Why host-based?**
- ✅ Direct access to Incus socket (no mounting required)
- ✅ Simpler security model (no socket exposure to container)
- ✅ Better performance (no container overhead)
- ✅ Easier deployment (Terraform handles it automatically)
- ✅ Industry standard (Docker daemon, Kubernetes also run on host)

**Why NOT in container?**
- ❌ Security risk: Container would need full Incus control
- ❌ Complexity: Requires mounting `/var/lib/incus/unix.socket`
- ❌ Container could create/delete itself and other containers
- ❌ No real benefit (daemon needs root anyway)

### Components

1. **Containarium Daemon** - Runs on HOST as systemd service
   - gRPC API server listening on 0.0.0.0:50051
   - Exposes container operations via gRPC
   - Connects to Incus via Unix socket
   - Authenticates requests
   - Auto-starts on boot
   - Automatically deployed by Terraform

2. **Containarium CLI** - Enhanced client mode
   - Can run locally (not just on jump server)
   - Talks to daemon via gRPC
   - Manages multiple jump servers
   - Remote commands: `containarium remote create jump-1:50051 alice`

3. **API Gateway** (Optional, Phase 8)
   - Central entry point
   - Routes requests to correct jump server
   - Aggregates data from all servers

4. **Web UI** (Phase 8)
   - Browser-based management
   - Real-time container status
   - Create/delete/manage containers
   - Multi-server dashboard

---

## Phase 7: API + Daemon Service

### Step 1: gRPC Service Definition

We already have protobuf! Just add service definitions:

**File**: `proto/containarium/v1/service.proto`

```protobuf
syntax = "proto3";

package containarium.v1;

import "containarium/v1/container.proto";
import "containarium/v1/config.proto";

// ContainerService provides container management operations
service ContainerService {
  // Create a new container
  rpc CreateContainer(CreateContainerRequest) returns (CreateContainerResponse);

  // List containers
  rpc ListContainers(ListContainersRequest) returns (ListContainersResponse);

  // Get container information
  rpc GetContainer(GetContainerRequest) returns (GetContainerResponse);

  // Delete a container
  rpc DeleteContainer(DeleteContainerRequest) returns (DeleteContainerResponse);

  // Start a container
  rpc StartContainer(StartContainerRequest) returns (StartContainerResponse);

  // Stop a container
  rpc StopContainer(StopContainerRequest) returns (StopContainerResponse);

  // Add SSH key to container
  rpc AddSSHKey(AddSSHKeyRequest) returns (AddSSHKeyResponse);

  // Remove SSH key from container
  rpc RemoveSSHKey(RemoveSSHKeyRequest) returns (RemoveSSHKeyResponse);

  // Get metrics for containers
  rpc GetMetrics(GetMetricsRequest) returns (GetMetricsResponse);

  // Get system information
  rpc GetSystemInfo(GetSystemInfoRequest) returns (GetSystemInfoResponse);
}

// Authentication service
service AuthService {
  // Authenticate and get token
  rpc Login(LoginRequest) returns (LoginResponse);

  // Validate token
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
}

message LoginRequest {
  string username = 1;
  string password = 2; // Or API key
}

message LoginResponse {
  string token = 1;
  int64 expires_at = 2;
}

message ValidateTokenRequest {
  string token = 1;
}

message ValidateTokenResponse {
  bool valid = 1;
  string username = 2;
}
```

### Step 2: Daemon Implementation

**File**: `cmd/containarium-daemon/main.go`

```go
package main

import (
    "fmt"
    "log"
    "net"

    "github.com/footprintai/containarium/internal/server"
    "google.golang.org/grpc"
)

func main() {
    // Create gRPC server
    lis, err := net.Listen("tcp", ":50051")
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }

    grpcServer := grpc.NewServer()

    // Register services
    containerServer := server.NewContainerServer()
    pb.RegisterContainerServiceServer(grpcServer, containerServer)

    log.Println("Containarium daemon listening on :50051")
    if err := grpcServer.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
```

**File**: `internal/server/container_server.go`

```go
package server

import (
    "context"

    "github.com/footprintai/containarium/internal/container"
    pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type ContainerServer struct {
    pb.UnimplementedContainerServiceServer
    manager *container.Manager
}

func NewContainerServer() *ContainerServer {
    mgr, _ := container.New()
    return &ContainerServer{manager: mgr}
}

func (s *ContainerServer) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
    // Use existing manager
    opts := container.CreateOptions{
        Username:     req.Username,
        Image:        req.Image,
        CPU:          req.Resources.Cpu,
        Memory:       req.Resources.Memory,
        Disk:         req.Resources.Disk,
        SSHKeys:      req.SshKeys,
        EnableDocker: req.EnableDocker,
        AutoStart:    true,
    }

    info, err := s.manager.Create(opts)
    if err != nil {
        return nil, err
    }

    // Convert to protobuf response
    return &pb.CreateContainerResponse{
        Container: toProtoContainer(info),
        Message:   "Container created successfully",
    }, nil
}

func (s *ContainerServer) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
    containers, err := s.manager.List()
    if err != nil {
        return nil, err
    }

    // Convert to protobuf
    var protoContainers []*pb.Container
    for _, c := range containers {
        protoContainers = append(protoContainers, toProtoContainer(&c))
    }

    return &pb.ListContainersResponse{
        Containers: protoContainers,
        TotalCount: int32(len(protoContainers)),
    }, nil
}

// ... other methods
```

### Step 3: Systemd Service

**File**: `scripts/containarium.service`

```ini
[Unit]
Description=Containarium Container Management Daemon
After=network.target incus.service
Requires=incus.service

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium daemon --config /etc/containarium/config.yaml
Restart=on-failure
RestartSec=5s
User=root
Group=root

# Security
NoNewPrivileges=true
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=containarium

[Install]
WantedBy=multi-user.target
```

### Step 4: Enhanced CLI (Client Mode)

**File**: `internal/cmd/daemon.go`

```go
package cmd

var daemonCmd = &cobra.Command{
    Use:   "daemon",
    Short: "Run Containarium as a daemon service",
    Long:  `Start the Containarium gRPC API server for remote management.`,
    RunE:  runDaemon,
}

func runDaemon(cmd *cobra.Command, args []string) error {
    // Start gRPC server
    // ... (same as daemon main.go)
}
```

**File**: `internal/cmd/remote.go`

```go
package cmd

var remoteCreateCmd = &cobra.Command{
    Use:   "remote-create <jump-server> <username>",
    Short: "Create container on a remote jump server",
    RunE:  runRemoteCreate,
}

func runRemoteCreate(cmd *cobra.Command, args []string) error {
    server := args[0]  // jump-1.example.com:50051
    username := args[1]

    // Connect to remote daemon
    conn, err := grpc.Dial(server, grpc.WithInsecure())
    if err != nil {
        return err
    }
    defer conn.Close()

    client := pb.NewContainerServiceClient(conn)

    // Call CreateContainer via gRPC
    req := &pb.CreateContainerRequest{
        Username: username,
        Resources: &pb.ResourceLimits{
            Cpu:    "4",
            Memory: "4GB",
            Disk:   "50GB",
        },
        EnableDocker: true,
    }

    resp, err := client.CreateContainer(context.Background(), req)
    if err != nil {
        return err
    }

    fmt.Printf("✓ Container created on %s\n", server)
    fmt.Printf("IP: %s\n", resp.Container.Network.IpAddress)
    return nil
}
```

### Step 5: Configuration File

**File**: `/etc/containarium/config.yaml`

```yaml
# Containarium daemon configuration

server:
  # gRPC server address
  address: "0.0.0.0:50051"

  # TLS configuration (optional)
  tls:
    enabled: false
    cert_file: /etc/containarium/tls/server.crt
    key_file: /etc/containarium/tls/server.key

auth:
  # Authentication method: none, token, mtls
  method: token

  # Token configuration
  token:
    secret: "your-secret-key-change-this"
    expiry: 24h

incus:
  # Incus socket path
  socket: /var/lib/incus/unix.socket

  # Default project
  project: default

containers:
  # Default container settings
  defaults:
    image: ubuntu:24.04
    cpu: "4"
    memory: "4GB"
    disk: "50GB"
    enable_docker: true
    auto_start: true

logging:
  level: info
  format: json
  output: /var/log/containarium/daemon.log
```

---

## Usage Examples

### Deployment

**Option 1: Automatic Deployment via Terraform (Recommended)**

Terraform automatically installs and starts the daemon when creating the VM:

```bash
# 1. Build the binary locally
make build-linux

# 2. Deploy infrastructure (daemon auto-installs)
cd terraform/gce
terraform apply

# That's it! The daemon is now running on all jump servers
```

Terraform startup script handles:
- Downloading containarium binary (or you can embed it)
- Installing systemd service
- Creating config file
- Enabling and starting daemon
- Configuring firewall for port 50051

**Option 2: Manual Deployment**

If you need to update the daemon on existing servers:

```bash
# 1. Build daemon + CLI
make build-linux

# 2. Copy to jump servers
scp bin/containarium-linux-amd64 admin@jump-1:/tmp/
ssh admin@jump-1

# 3. Install binary
sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium
sudo chmod +x /usr/local/bin/containarium

# 4. Install systemd service (if not exists)
sudo cp scripts/containarium.service /etc/systemd/system/
sudo mkdir -p /etc/containarium
sudo cp config.example.yaml /etc/containarium/config.yaml

# 5. Restart daemon
sudo systemctl daemon-reload
sudo systemctl restart containarium
sudo systemctl status containarium
```

### Local CLI to Remote Daemon

```bash
# On your laptop (not jump server!)

# Create container on jump-1
containarium remote create jump-1.example.com:50051 alice \
  --ssh-key ~/.ssh/alice.pub

# List containers on jump-2
containarium remote list jump-2.example.com:50051

# Get info from jump-3
containarium remote info jump-3.example.com:50051 alice

# Manage multiple servers
containarium remote list-all \
  --servers jump-1:50051,jump-2:50051,jump-3:50051
```

### API Clients (HTTP/REST Gateway)

Add gRPC-Gateway for REST API:

```bash
# REST API (if you add grpc-gateway)
curl -X POST https://jump-1.example.com/v1/containers \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "username": "alice",
    "resources": {"cpu": "4", "memory": "4GB"},
    "enable_docker": true
  }'

# List containers
curl https://jump-1.example.com/v1/containers \
  -H "Authorization: Bearer $TOKEN"
```

### Python Client Example

```python
import grpc
from containarium.v1 import container_pb2, container_pb2_grpc

# Connect to daemon
channel = grpc.insecure_channel('jump-1.example.com:50051')
stub = container_pb2_grpc.ContainerServiceStub(channel)

# Create container
request = container_pb2.CreateContainerRequest(
    username='alice',
    resources=container_pb2.ResourceLimits(
        cpu='4',
        memory='4GB',
        disk='50GB'
    ),
    enable_docker=True
)

response = stub.CreateContainer(request)
print(f"Container created: {response.container.network.ip_address}")
```

---

## Security Considerations

### Authentication Options

**Option 1: API Tokens (Simplest)**
```yaml
auth:
  method: token
  token:
    secret: "secret-key"
```

**Option 2: mTLS (Most Secure)**
```yaml
auth:
  method: mtls
  tls:
    ca_cert: /etc/containarium/ca.crt
    server_cert: /etc/containarium/server.crt
    server_key: /etc/containarium/server.key
```

**Option 3: OAuth/OIDC (Enterprise)**
```yaml
auth:
  method: oidc
  oidc:
    issuer: https://auth.company.com
    client_id: containarium
```

### Network Security

```bash
# Firewall: Only allow gRPC from specific IPs
sudo ufw allow from 203.0.113.0/24 to any port 50051

# Or use Tailscale/Wireguard for private network
# Daemon only listens on private network interface
```

---

## Benefits of API + Daemon

### Current (Phase 6)
```bash
# Must SSH to each server
ssh admin@jump-1 "sudo containarium create alice"
ssh admin@jump-2 "sudo containarium create bob"
ssh admin@jump-3 "sudo containarium create charlie"

# Can't see all containers at once
# No automation possible
# No Web UI possible
```

### With API + Daemon (Phase 7)
```bash
# From your laptop - manage all servers
containarium remote create jump-1:50051 alice
containarium remote create jump-2:50051 bob
containarium remote create jump-3:50051 charlie

# View all containers across all servers
containarium remote list-all

# Automate with scripts
for user in alice bob charlie; do
  containarium remote create jump-1:50051 $user
done

# Foundation for Web UI (Phase 8)
# Web UI → API Gateway → Daemons on each jump server
```

---

## Implementation Plan

### Phase 7.1: Basic gRPC Service (1-2 days)
- ✅ Add service.proto definitions
- ✅ Implement gRPC server
- ✅ Add daemon command to CLI
- ✅ Test locally

### Phase 7.2: Client/Server Mode (1 day)
- ✅ Implement remote CLI commands
- ✅ Add authentication (token-based)
- ✅ Configuration file support

### Phase 7.3: Systemd Service (1 day)
- ✅ Create systemd unit file
- ✅ Add to Terraform startup script
- ✅ Auto-start daemon on boot
- ✅ Health checks

### Phase 7.4: Multi-Server Support (1 day)
- ✅ Manage multiple jump servers from one CLI
- ✅ Aggregate views
- ✅ Server discovery/registration

### Phase 7.5: REST Gateway (Optional, 1 day)
- ✅ Add grpc-gateway
- ✅ HTTP/JSON API alongside gRPC
- ✅ Swagger/OpenAPI docs

**Total**: ~5-7 days of development

---

## Phase 8: Web UI (Future)

With the API in place, building a Web UI becomes straightforward:

```
┌─────────────────────────────────────────┐
│           Web UI (React/Vue)            │
│                                         │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐│
│  │Dashboard│ │Containers│ │ Users    ││
│  └─────────┘ └──────────┘ └──────────┘│
└────────────────┬────────────────────────┘
                 │ (gRPC/REST)
                 ↓
┌─────────────────────────────────────────┐
│         API Gateway / Backend           │
└────────────────┬────────────────────────┘
                 │
      ┌──────────┼──────────┐
      ↓          ↓          ↓
   Jump-1     Jump-2     Jump-3
   Daemon     Daemon     Daemon
```

**Features**:
- Dashboard: View all containers across all servers
- Create Container: Form → API → Container created
- Monitoring: Real-time stats from all servers
- User Management: Assign users to containers
- SSH Config Generator: Auto-generate ~/.ssh/config

---

## Next Steps

**Do you want to implement Phase 7 (API + Daemon) next?**

This would give you:
1. Remote management capability
2. API for automation
3. Foundation for Web UI
4. Much better user experience

We can start with Phase 7.1 (basic gRPC service) and build from there.
