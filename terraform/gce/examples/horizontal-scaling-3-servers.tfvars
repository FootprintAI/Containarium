# Horizontal Scaling Example: 3 Jump Servers
# Use case: 100-150 users across 3 teams or projects

# GCP Project
project_id = "your-gcp-project-id"
region     = "us-central1"
zone       = "us-central1-a"

# Horizontal Scaling Configuration
enable_horizontal_scaling = true
jump_server_count         = 3        # Deploy 3 independent jump servers
enable_load_balancer      = true     # Load balancer in front

# Instance Configuration
instance_name = "containarium-jump"
machine_type  = "n2-standard-8"      # 8 vCPU, 32GB RAM per server

# Cost Optimization - Use Spot Instances!
use_spot_instance   = true           # 76% cheaper!
use_persistent_disk = true           # Containers survive spot termination

# Storage
boot_disk_size = 100                 # GB - OS and binaries
data_disk_size = 500                 # GB per jump server - container storage
data_disk_type = "pd-balanced"       # Good price/performance ratio

# Backup Strategy
enable_disk_snapshots = true         # Daily snapshots, 30-day retention

# SSH Access - Add your admin keys
admin_ssh_keys = {
  admin = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@example.com"
  # alice = "ssh-ed25519 AAAAC3... alice@example.com"
}

# Security - IMPORTANT: Restrict in production!
allowed_ssh_sources = [
  "0.0.0.0/0"  # WARNING: Open to internet. Change to your office/VPN IPs!
  # Production example:
  # "203.0.113.0/24",   # Office IP range
  # "198.51.100.5/32",  # VPN server
]

# Optional: DNS Configuration
# dns_zone_name   = "your-dns-zone"
# dns_zone_domain = "example.com"
# Creates: jump.example.com (load balancer)
#          jump-1.example.com, jump-2.example.com, jump-3.example.com

# Labels
labels = {
  environment = "production"
  team        = "platform"
  project     = "containarium"
  managed_by  = "terraform"
}

# === Deployment Summary ===
#
# This configuration deploys:
# - 3 independent jump servers (n2-standard-8, spot instances)
# - Each with 500GB persistent disk
# - Network load balancer for SSH traffic
# - Daily disk snapshots for backups
#
# Capacity:
# - ~50 users per jump server = 150 total users
# - Each container gets 4GB RAM, 4 CPU by default
#
# Cost (approximate):
# - 3x spot VMs: $174/month
# - 3x persistent disks (500GB): $120/month
# - Load balancer: $18/month
# - TOTAL: ~$312/month ($2.08/user/month)
#
# vs Traditional (150 VMs): $3,750/month
# Savings: $3,438/month (92%)
