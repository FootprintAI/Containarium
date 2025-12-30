# Horizontal Scaling Example: 5 Jump Servers
# Use case: 200-250 users, large team, need fault tolerance

# GCP Project
project_id = "your-gcp-project-id"
region     = "us-central1"
zone       = "us-central1-a"

# Horizontal Scaling Configuration
enable_horizontal_scaling = true
jump_server_count         = 5        # 5 independent jump servers
enable_load_balancer      = true

# Instance Configuration
instance_name = "containarium-jump"
machine_type  = "n2-standard-8"      # 8 vCPU, 32GB RAM per server

# Cost Optimization
use_spot_instance   = true
use_persistent_disk = true

# Storage
boot_disk_size = 100
data_disk_size = 500
data_disk_type = "pd-balanced"

# Backup
enable_disk_snapshots = true

# SSH Access
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3... admin@example.com"
}

# Security - Restrict to your IPs in production!
allowed_ssh_sources = [
  "203.0.113.0/24",    # Example: Office network
  "198.51.100.5/32",   # Example: VPN server
]

# Optional: DNS
# dns_zone_name   = "your-dns-zone"
# dns_zone_domain = "example.com"

# Labels
labels = {
  environment = "production"
  team        = "platform"
  scale       = "large"
  managed_by  = "terraform"
}

# === Deployment Summary ===
#
# This configuration deploys:
# - 5 independent jump servers
# - Each with 32GB RAM, 500GB persistent disk
# - Network load balancer
# - Daily snapshots
#
# Capacity:
# - ~50 users per jump server = 250 total users
# - High availability: If 1 server fails, others continue
#
# Cost (approximate):
# - 5x spot VMs: $290/month
# - 5x persistent disks: $200/month
# - Load balancer: $18/month
# - TOTAL: ~$508/month ($2.03/user for 250 users)
#
# vs Traditional (250 VMs): $6,250/month
# Savings: $5,742/month (92%)
#
# Fault Tolerance:
# - Load balancer distributes users across servers
# - If jump-1 fails, only affects ~50 users
# - Other 200 users unaffected
# - Failed server can be replaced quickly
