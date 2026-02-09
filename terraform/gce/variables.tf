variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "instance_name" {
  description = "Name of the GCE instance"
  type        = string
  default     = "containarium-jump"
}

variable "machine_type" {
  description = "GCE machine type"
  type        = string
  default     = "n2-standard-8" # 8 vCPU, 32GB RAM - can host 50+ containers

  validation {
    condition     = can(regex("^(n2|n2d|e2|n1|c4)-(standard|highmem|highcpu)-[0-9]+$", var.machine_type))
    error_message = "Must be a valid GCE machine type"
  }
}

variable "os_image" {
  description = "OS image for the instance"
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
}

variable "boot_disk_size" {
  description = "Boot disk size in GB"
  type        = number
  default     = 500

  validation {
    condition     = var.boot_disk_size >= 100 && var.boot_disk_size <= 2000
    error_message = "Boot disk size must be between 100 and 2000 GB"
  }
}

variable "boot_disk_type" {
  description = "Boot disk type"
  type        = string
  default     = "pd-balanced" # Good balance of price/performance

  validation {
    condition     = contains(["pd-standard", "pd-balanced", "pd-ssd", "hyperdisk-balanced", "hyperdisk-throughput"], var.boot_disk_type)
    error_message = "Boot disk type must be pd-standard, pd-balanced, pd-ssd, hyperdisk-balanced, or hyperdisk-throughput"
  }
}

variable "admin_ssh_keys" {
  description = "Map of admin users to their SSH public keys"
  type        = map(string)
  default     = {}

  # Example:
  # admin_ssh_keys = {
  #   admin = "ssh-ed25519 AAAAC3... admin@example.com"
  #   alice = "ssh-ed25519 AAAAC3... alice@example.com"
  # }
}

variable "allowed_ssh_sources" {
  description = "List of CIDR blocks allowed to SSH to the jump server"
  type        = list(string)
  default     = ["0.0.0.0/0"] # WARNING: Open to internet. Restrict in production!

  # Example for production:
  # allowed_ssh_sources = [
  #   "203.0.113.0/24",  # Office IP range
  #   "198.51.100.5/32", # VPN server
  # ]
}

variable "incus_version" {
  description = "Incus version to install (latest stable if empty)"
  type        = string
  default     = ""
}

variable "enable_monitoring" {
  description = "Enable GCP monitoring and logging"
  type        = bool
  default     = true
}

variable "service_account_email" {
  description = "Service account email for the instance (uses default if empty)"
  type        = string
  default     = null
}

variable "labels" {
  description = "Labels to apply to resources"
  type        = map(string)
  default = {
    managed_by = "terraform"
    project    = "containarium"
  }
}

variable "dns_zone_name" {
  description = "Cloud DNS zone name for jump server DNS record (optional)"
  type        = string
  default     = ""
}

variable "dns_zone_domain" {
  description = "Cloud DNS zone domain (e.g., example.com)"
  type        = string
  default     = ""
}

# Spot Instance and Persistent Disk Configuration

variable "use_spot_instance" {
  description = "Use spot (preemptible) instance for cost savings (60-91% cheaper)"
  type        = bool
  default     = false
}

variable "use_persistent_disk" {
  description = "Use separate persistent disk for Incus data (survives spot termination)"
  type        = bool
  default     = true
}

variable "data_disk_size" {
  description = "Size of persistent data disk for containers (GB)"
  type        = number
  default     = 500

  validation {
    condition     = var.data_disk_size >= 100 && var.data_disk_size <= 10000
    error_message = "Data disk size must be between 100 and 10000 GB"
  }
}

variable "data_disk_type" {
  description = "Type of persistent data disk"
  type        = string
  default     = "pd-balanced"

  validation {
    condition     = contains(["pd-standard", "pd-balanced", "pd-ssd", "hyperdisk-balanced", "hyperdisk-throughput"], var.data_disk_type)
    error_message = "Data disk type must be pd-standard, pd-balanced, pd-ssd, hyperdisk-balanced, or hyperdisk-throughput"
  }
}

variable "enable_disk_snapshots" {
  description = "Enable automated daily snapshots of persistent disk"
  type        = bool
  default     = true
}

# Horizontal Scaling Configuration

variable "enable_horizontal_scaling" {
  description = "Enable horizontal scaling with multiple jump servers"
  type        = bool
  default     = false
}

variable "jump_server_count" {
  description = "Number of jump servers for horizontal scaling"
  type        = number
  default     = 1

  validation {
    condition     = var.jump_server_count >= 1 && var.jump_server_count <= 10
    error_message = "Jump server count must be between 1 and 10"
  }
}

variable "enable_load_balancer" {
  description = "Enable load balancer for horizontal scaling (recommended for 3+ servers)"
  type        = bool
  default     = true
}

variable "load_balancer_ip" {
  description = "Reserved IP address for load balancer (optional, creates new if empty)"
  type        = string
  default     = ""
}

# Containarium Daemon Configuration

variable "containarium_version" {
  description = "Containarium version to install"
  type        = string
  default     = "dev"
}

variable "containarium_binary_url" {
  description = "URL to download containarium binary (empty = use file provisioner)"
  type        = string
  default     = ""

  # Examples:
  # - GitHub releases: "https://github.com/footprintai/Containarium/releases/download/v0.1.0/containarium-linux-amd64"
  # - GCS bucket: "https://storage.googleapis.com/my-bucket/containarium-linux-amd64"
  # - Empty string: Use Terraform file provisioner to copy local binary
}

variable "enable_containarium_daemon" {
  description = "Enable Containarium gRPC daemon service"
  type        = bool
  default     = true
}

variable "ssh_private_key_path" {
  description = "Path to SSH private key for provisioner connections (required if containarium_binary_url is empty)"
  type        = string
  default     = ""

  # Example:
  # ssh_private_key_path = "~/.ssh/id_ed25519"
  #
  # SECURITY NOTE: Never commit private keys to version control.
  # Set this via terraform.tfvars or environment variable:
  # export TF_VAR_ssh_private_key_path="~/.ssh/id_ed25519"
}
