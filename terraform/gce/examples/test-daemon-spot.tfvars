# Test Configuration for Containarium Daemon on Small Spot Instance
# This is a minimal setup for testing the gRPC daemon

# REQUIRED: Set your GCP project ID
project_id = "your-gcp-project-id"  # CHANGE THIS

# REQUIRED: Add your SSH public key for admin access
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3Nza... your-key-here"  # CHANGE THIS
}

# Use small spot instance for testing (cheap!)
machine_type       = "e2-standard-2"  # 2 vCPU, 8GB RAM - $14/month spot
use_spot_instance  = true
use_persistent_disk = true

# Small disks for testing
boot_disk_size = 100  # GB
data_disk_size = 100  # GB

# Security: Restrict to your IP (recommended)
# allowed_ssh_sources = ["YOUR.IP.ADDRESS/32"]  # Uncomment and set your IP
allowed_ssh_sources = ["0.0.0.0/0"]  # WARNING: Open to all - OK for testing only

# Containarium daemon configuration
enable_containarium_daemon = true
containarium_version       = "dev"

# Option 1: Use file provisioner (copy local binary) - DEFAULT
containarium_binary_url = ""

# Option 2: Download from URL (uncomment if you uploaded binary somewhere)
# containarium_binary_url = "https://storage.googleapis.com/your-bucket/containarium-linux-amd64"
# containarium_binary_url = "https://github.com/footprintai/Containarium/releases/download/v0.1.0/containarium-linux-amd64"

# Single server (not scaling)
enable_horizontal_scaling = false
jump_server_count        = 1
enable_load_balancer     = false

# Enable monitoring
enable_monitoring = true

# Instance naming
instance_name = "containarium-test"

# Enable disk snapshots (backup)
enable_disk_snapshots = true

# Labels for organization
labels = {
  environment = "test"
  managed_by  = "terraform"
  project     = "containarium"
  purpose     = "daemon-testing"
}
