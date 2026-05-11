# =============================================================================
# Containarium Terraform Module — Variables
# =============================================================================
# Unified variable definitions for both dev and production consumers.

# -----------------------------------------------------------------------------
# Project & Region
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# Instance Configuration
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# Encryption (CMEK)
# -----------------------------------------------------------------------------

variable "kms_key_self_link" {
  description = <<-EOT
    Optional customer-managed KMS key for encrypting the backend and sentinel
    disks (boot + attached data disk). Provide a full self_link, e.g.
    "projects/<project>/locations/<region>/keyRings/<ring>/cryptoKeys/<key>".

    Default empty string keeps Google-managed encryption (the GCE default).
    Set this for compliance-bound deployments that need customer-managed keys.

    The compute service account on the project must have
    roles/cloudkms.cryptoKeyEncrypterDecrypter on the named key before apply
    succeeds, otherwise disk creation fails with a permission error.
  EOT
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------

variable "network_self_link" {
  description = "VPC network self_link. If empty, uses default network."
  type        = string
  default     = ""
}

variable "subnetwork_self_link" {
  description = "Subnetwork self_link. If empty, uses default."
  type        = string
  default     = ""
}

variable "instance_tags" {
  description = "Network tags for the jump server instance"
  type        = list(string)
  default     = ["containarium-jump-server"]
}

# -----------------------------------------------------------------------------
# SSH & Security
# -----------------------------------------------------------------------------

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

variable "fail2ban_whitelist_cidr" {
  description = "CIDR to whitelist in fail2ban (e.g., 10.128.0.0/9 for GCE default, 10.0.0.0/8 for VPC)"
  type        = string
  default     = "10.0.0.0/8"
}

variable "jwt_secret" {
  description = "JWT secret for REST API authentication. If empty, auto-generated at boot."
  type        = string
  sensitive   = true
  default     = ""
}

# -----------------------------------------------------------------------------
# Conditional Features (production vs dev)
# -----------------------------------------------------------------------------

variable "enable_iap_firewall" {
  description = "Create IAP SSH firewall rule (needed in VPC environments)"
  type        = bool
  default     = false
}

variable "spot_vm_external_ip" {
  description = "Give spot VM an ephemeral external IP (false = Cloud NAT only)"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Incus & Software
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# Service Account & Labels
# -----------------------------------------------------------------------------

variable "service_account_email" {
  description = "Service account email for the instance (uses default if null)"
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

# -----------------------------------------------------------------------------
# DNS (optional)
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# Spot Instance & Persistent Disk
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# Containarium Daemon
# -----------------------------------------------------------------------------

variable "containarium_version" {
  description = "Containarium version to install"
  type        = string
  default     = "dev"
}

variable "containarium_binary_url" {
  description = "URL to download containarium binary (empty = not installed via URL)"
  type        = string
  default     = ""
}

variable "enable_containarium_daemon" {
  description = "Enable Containarium gRPC daemon service"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Sentinel HA
# -----------------------------------------------------------------------------

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

variable "spot_vm_name_suffix" {
  description = "Suffix appended to instance_name for the spot VM when sentinel is enabled (e.g., '-spot' gives 'instance-name-spot'). Empty string uses instance_name as-is."
  type        = string
  default     = ""
}
