# =============================================================================
# Dev Consumer Variables — pass-through to containarium module
# =============================================================================

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
  default     = "n2-standard-8"

  validation {
    condition     = can(regex("^(n1|n2|n2d|n4|e2|c3|c3d|c4|c4a)-(standard|highmem|highcpu)-[0-9]+$", var.machine_type))
    error_message = "Must be a valid GCE machine type (e.g., c3d-highmem-8, n2-standard-4)"
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
    condition     = var.boot_disk_size >= 10 && var.boot_disk_size <= 2000
    error_message = "Boot disk size must be between 10 and 2000 GB"
  }
}

variable "boot_disk_type" {
  description = "Boot disk type"
  type        = string
  default     = "pd-balanced"

  validation {
    condition     = contains(["pd-standard", "pd-balanced", "pd-ssd", "hyperdisk-balanced", "hyperdisk-throughput"], var.boot_disk_type)
    error_message = "Boot disk type must be pd-standard, pd-balanced, pd-ssd, hyperdisk-balanced, or hyperdisk-throughput"
  }
}

variable "boot_disk_auto_delete" {
  description = "Whether the spot jump-server's boot disk is deleted when the instance is deleted. Set false to protect a disk that predates or is managed outside this module's lifecycle."
  type        = bool
  default     = true
}

variable "admin_ssh_keys" {
  description = "Map of admin users to their SSH public keys"
  type        = map(string)
  default     = {}
}

variable "allowed_ssh_sources" {
  description = "List of CIDR blocks allowed to SSH to the jump server"
  type        = list(string)
  default     = ["0.0.0.0/0"]
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
}

variable "enable_containarium_daemon" {
  description = "Enable Containarium gRPC daemon service"
  type        = bool
  default     = true
}

# Sentinel HA Configuration

variable "enable_sentinel" {
  description = "Enable sentinel HA proxy for spot instance recovery (requires use_spot_instance=true)"
  type        = bool
  default     = false
}

variable "sentinel_machine_type" {
  description = "Machine type for the sentinel VM (e2-micro for free tier)"
  type        = string
  default     = "e2-micro"
}

variable "sentinel_boot_disk_size" {
  description = "Boot disk size for sentinel VM in GB (up to 30GB for free tier)"
  type        = number
  default     = 20

  validation {
    condition     = var.sentinel_boot_disk_size >= 10 && var.sentinel_boot_disk_size <= 100
    error_message = "Sentinel boot disk size must be between 10 and 100 GB"
  }
}
