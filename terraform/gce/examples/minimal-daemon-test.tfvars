# Minimal Test Configuration - Just Test the Daemon
# Smallest possible instance to test gRPC daemon works
# Cost: ~$7-12/month spot

# REQUIRED: Set your GCP project ID
project_id = "your-gcp-project-id"  # CHANGE THIS

# REQUIRED: Add your SSH public key
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3Nza... your-key-here"  # CHANGE THIS
}

# Minimal instance - just to test daemon
machine_type       = "e2-small"  # 2 vCPU, 2GB RAM
use_spot_instance  = true        # 70% cheaper
use_persistent_disk = false      # Not needed for testing

# Minimal disks
boot_disk_size = 20   # GB - just OS + Incus + daemon
data_disk_size = 20   # GB - minimal

# Security: Open for testing (change in production)
allowed_ssh_sources = ["0.0.0.0/0"]

# Enable daemon
enable_containarium_daemon = true
containarium_version       = "dev"
containarium_binary_url    = ""  # Use local binary

# No scaling - single server
enable_horizontal_scaling = false
enable_load_balancer     = false

# No monitoring for minimal cost
enable_monitoring = false

# No snapshots for testing
enable_disk_snapshots = false

# Instance name
instance_name = "containarium-minimal-test"

# Labels
labels = {
  environment = "test"
  purpose     = "daemon-only"
  cost        = "minimal"
}
