# Single Server Example: Spot Instance with Persistent Disk
# Use case: 20-50 users, tight budget, can tolerate 2-5 min downtime

# GCP Project
project_id = "your-gcp-project-id"
region     = "us-central1"
zone       = "us-central1-a"

# Single Server Configuration
enable_horizontal_scaling = false    # Single jump server
instance_name = "containarium-jump"
machine_type  = "n2-standard-8"      # 8 vCPU, 32GB RAM

# Cost Optimization - Maximum Savings!
use_spot_instance   = true           # 76% cheaper than regular VM
use_persistent_disk = true           # Containers survive spot termination

# Storage
boot_disk_size = 100                 # GB
data_disk_size = 500                 # GB - all container data here
data_disk_type = "pd-balanced"

# Backup
enable_disk_snapshots = true         # Daily snapshots

# SSH Access
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@example.com"
}

# Security
allowed_ssh_sources = [
  "0.0.0.0/0"  # WARNING: Restrict in production!
]

# Labels
labels = {
  environment = "development"
  managed_by  = "terraform"
}

# === Deployment Summary ===
#
# This configuration deploys:
# - 1 spot instance jump server
# - 500GB persistent disk (containers survive spot termination)
# - Daily backups with 30-day retention
#
# Capacity:
# - ~50 users maximum
# - Each container: 4GB RAM, 4 CPU default
#
# Cost (approximate):
# - Spot VM (n2-standard-8): $58/month
# - Persistent disk (500GB): $40/month
# - TOTAL: ~$98/month ($1.96/user for 50 users)
#
# vs Traditional (50 VMs): $1,250/month
# Savings: $1,152/month (92%)
#
# Downtime:
# - When spot instance is terminated: 2-5 minutes
# - Containers automatically restart from persistent disk
# - Frequency: Typically every few days to weeks
