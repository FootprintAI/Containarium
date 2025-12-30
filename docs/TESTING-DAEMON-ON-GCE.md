# Testing Containarium Daemon on GCE

This guide walks you through deploying a test instance on GCE to verify the gRPC daemon works end-to-end.

## Prerequisites

1. **GCP Project** with billing enabled
2. **gcloud CLI** installed and authenticated: `gcloud auth application-default login`
3. **Terraform** installed (>= 1.0)
4. **SSH key pair** at `~/.ssh/id_rsa` (or adjust path in terraform)
5. **Your IP address** for security (optional but recommended)

## Cost Estimate

Test instance (e2-standard-2 spot):
- **~$0.02/hour** or **~$14/month** (spot pricing)
- Stop when not testing to avoid charges

## Step-by-Step Deployment

### 1. Build the Binary

```bash
cd /Users/hsinhoyeh/Workspaces/github/footprintai/Containarium
make build-linux

# Verify binary exists
ls -lh bin/containarium-linux-amd64
```

### 2. Configure Terraform

```bash
cd terraform/gce

# Copy test configuration
cp examples/test-daemon-spot.tfvars terraform.tfvars

# Edit with your details
vim terraform.tfvars
```

**Required changes in `terraform.tfvars`:**

```hcl
# 1. Set your GCP project ID
project_id = "my-gcp-project-id"  # CHANGE THIS

# 2. Add your SSH public key
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3Nza... your-actual-key"  # CHANGE THIS
}

# 3. (Optional) Restrict to your IP for security
# Get your IP: curl ifconfig.me
allowed_ssh_sources = ["YOUR.IP.ADDRESS/32"]
```

### 3. Deploy to GCE

```bash
# Initialize Terraform
terraform init

# Review what will be created
terraform plan

# Deploy (takes 3-5 minutes)
terraform apply

# Type 'yes' when prompted
```

**What gets created:**
- ✅ Small spot VM (e2-standard-2: 2 vCPU, 8GB RAM)
- ✅ Static external IP
- ✅ Firewall rules (SSH port 22, gRPC port 50051)
- ✅ Persistent disk for container data
- ✅ Incus installed and initialized
- ✅ Containarium daemon installed and running

### 4. Save the Outputs

After `terraform apply` completes:

```
Outputs:

jump_server_ip = "34.123.45.67"
ssh_command = "ssh admin@34.123.45.67"
daemon_endpoint = "34.123.45.67:50051"
```

**Save these values!** You'll need them for testing.

### 5. Verify Deployment

```bash
# SSH to the server
ssh admin@34.123.45.67

# Check daemon status
sudo systemctl status containarium

# Should show:
# ● containarium.service - Containarium Container Management Daemon
#    Active: active (running)

# Check daemon logs
sudo journalctl -u containarium -f

# Check Incus is running
sudo incus list

# Exit
exit
```

## Testing the gRPC Daemon

### Option 1: Test with grpcurl (Easiest)

```bash
# Install grpcurl (if not installed)
# macOS:
brew install grpcurl

# Linux:
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Test connection
DAEMON_IP="34.123.45.67"  # Use your actual IP

# List available services
grpcurl -plaintext $DAEMON_IP:50051 list

# Should show:
# containarium.v1.ContainerService
# grpc.reflection.v1.ServerReflection
# grpc.reflection.v1alpha.ServerReflection

# List methods
grpcurl -plaintext $DAEMON_IP:50051 list containarium.v1.ContainerService

# Get system info
grpcurl -plaintext $DAEMON_IP:50051 \
  containarium.v1.ContainerService/GetSystemInfo

# Should return JSON with Incus version, OS, etc.

# List containers (should be empty initially)
grpcurl -plaintext $DAEMON_IP:50051 \
  containarium.v1.ContainerService/ListContainers
```

### Option 2: Create Container via gRPC

```bash
# Create a container for user "alice"
grpcurl -plaintext -d '{
  "username": "alice",
  "resources": {
    "cpu": "2",
    "memory": "2GB",
    "disk": "20GB"
  },
  "enable_docker": true
}' $DAEMON_IP:50051 \
  containarium.v1.ContainerService/CreateContainer

# This will:
# 1. Create LXC container
# 2. Install Docker, SSH, sudo
# 3. Create user "alice"
# 4. Return IP address

# Wait ~60 seconds for container creation

# List containers again
grpcurl -plaintext $DAEMON_IP:50051 \
  containarium.v1.ContainerService/ListContainers

# Should show alice-container
```

### Option 3: Test from Go Client

Create `test-client.go`:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func main() {
	// Connect to daemon
	conn, err := grpc.Dial("34.123.45.67:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewContainerServiceClient(conn)

	// Get system info
	info, err := client.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{})
	if err != nil {
		log.Fatalf("GetSystemInfo failed: %v", err)
	}

	fmt.Printf("Connected to Containarium!\n")
	fmt.Printf("Incus Version: %s\n", info.Info.IncusVersion)
	fmt.Printf("OS: %s\n", info.Info.Os)
	fmt.Printf("Containers: %d total, %d running\n",
		info.Info.ContainersTotal,
		info.Info.ContainersRunning)
}
```

Run:
```bash
go run test-client.go
```

## Troubleshooting

### Daemon not running

```bash
ssh admin@<jump-server-ip>

# Check daemon status
sudo systemctl status containarium

# View logs
sudo journalctl -u containarium -n 50

# Restart daemon
sudo systemctl restart containarium

# Check if binary exists
ls -lh /usr/local/bin/containarium
/usr/local/bin/containarium version
```

### Connection refused

```bash
# Check firewall rule exists
gcloud compute firewall-rules list | grep grpc

# Test if port is open
nc -zv <jump-server-ip> 50051

# Check daemon is listening
ssh admin@<jump-server-ip> "sudo ss -tlnp | grep 50051"
```

### Binary not copied

```bash
# Check if file provisioner ran
terraform state show 'null_resource.copy_containarium_binary[0]'

# Manually copy if needed
scp bin/containarium-linux-amd64 admin@<jump-server-ip>:/tmp/
ssh admin@<jump-server-ip>
sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium
sudo chmod +x /usr/local/bin/containarium
sudo systemctl restart containarium
```

## Cleanup

When done testing:

```bash
cd terraform/gce

# Destroy all resources
terraform destroy

# Type 'yes' when prompted

# This will:
# - Stop and delete the VM
# - Delete the static IP
# - Remove firewall rules
# - Delete persistent disk (if not backed up)
```

**Estimated savings**: Stopping immediately saves ~$0.02/hour.

## Next Steps

After successful testing:

1. **Phase 7.2**: Implement remote CLI commands (`containarium remote create`)
2. **Add Authentication**: Token-based or mTLS
3. **Production Deployment**: Use regular instances (not spot) for stability
4. **Scale Horizontally**: Deploy multiple jump servers
5. **Build Web UI**: Phase 8

## Verification Checklist

```
✓ Binary builds successfully
✓ Terraform apply completes without errors
✓ Can SSH to jump server
✓ Daemon is running (systemctl status)
✓ Port 50051 is accessible
✓ grpcurl can list services
✓ grpcurl can call GetSystemInfo
✓ Can create container via gRPC
✓ Container appears in incus list
✓ Daemon survives restart
```

## Support

If you encounter issues:
1. Check logs: `sudo journalctl -u containarium -f`
2. Verify Incus: `sudo incus list`
3. Test manually: `sudo /usr/local/bin/containarium daemon`
4. Review startup script execution: `sudo journalctl -t containarium-startup`

---

**Ready to test!** Start with Step 1 and deploy your first gRPC-enabled Containarium instance. 🚀
