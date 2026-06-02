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
  description = <<-EOT
    CIDR blocks allowed to reach user-facing services on the
    sentinel: sshpiper on :22 (the per-tenant SSH proxy), plus
    HTTP :80 and HTTPS :443. Defaults to 0.0.0.0/0 because the
    whole point of these services is to accept user traffic
    from anywhere; sshpiper has fail2ban in front, and 80/443
    front Caddy which handles its own TLS termination.

    For operator-only ports (jump-server SSH :22, gRPC :50051,
    sentinel management SSH :2222) use `allowed_management_sources`
    instead — that defaults to VPC-only so operator surfaces
    aren't world-reachable by accident. Audit C-HIGH-3.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "allowed_management_sources" {
  description = <<-EOT
    CIDR blocks allowed to reach operator-only surfaces: jump-
    server SSH :22, gRPC :50051, and sentinel management SSH
    :2222. Defaults to RFC-1918 (10/8, 172.16/12, 192.168/16) so
    operators reach them via VPN / IAP / bastion rather than via
    open internet. Set to a narrower CIDR if your operator
    network is more specific, or to ["0.0.0.0/0"] only when you
    have a documented reason and other compensating controls.

    Tracks audit finding C-HIGH-3.
  EOT
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
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
# Phase 0.4 / 0.5 — sentinel↔daemon authentication and peer-CA
# -----------------------------------------------------------------------------
#
# `sentinel_auth_secret` is the shared HMAC secret used by the daemon
# to sign calls to the sentinel's /authorized-keys, /certs,
# /sentinel/ca, and /sentinel/peer-cert endpoints (Phase 0.4) and by
# the sentinel to sign the /sentinel/peers response (Phase 0.6).
# When this is empty, the sentinel falls back to pre-Phase-0
# behavior — unauthenticated endpoints + unsigned discovery — which
# matches the audit-vulnerable baseline (findings A-CRIT-4, C-CRIT-2).
# In production you want this set.
#
# Generate with:
#   openssl rand -base64 48
#
# Must be at least 32 bytes after any encoding. Both the sentinel
# and the spot/daemon VM see the same value via metadata.
variable "sentinel_auth_secret" {
  description = "Shared HMAC secret between sentinel and daemons (Phase 0.4/0.5/0.6). 32+ bytes. Empty = falls back to pre-Phase-0 behavior with the audit-known vulnerabilities."
  type        = string
  sensitive   = true
  default     = ""
}

# `enable_peer_mtls` turns on the Phase 0.5 peer-CA path. When true,
# the sentinel auto-generates an RSA-4096 CA private key at
# `/etc/containarium/ca.key` on first boot, mints itself a server
# cert, and exposes the HTTPS binary-server listener on port 8889
# (in addition to the existing HTTP listener on 8888). Daemons
# fetch a leaf cert from /sentinel/peer-cert at startup and use it
# for HTTPS peer-to-peer. Defaults to false during rollout — flip
# to true once the daemon binaries on every peer support the flow.
variable "enable_peer_mtls" {
  description = "Enable Phase 0.5 peer-to-peer mTLS via the sentinel-managed CA. Requires sentinel_auth_secret to also be set."
  type        = bool
  default     = false
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
  description = <<-EOT
    Containarium version to install. The startup script reconciles the
    installed binary to this version on every boot (substring match against
    `containarium version`), so bumping it upgrades the daemon — but note a
    metadata-only `terraform apply` does NOT restart the instance, so the new
    version takes effect on the next reboot/preemption-recovery (or force one
    with `terraform apply -replace=<instance>`). On a sentinel-HA deployment a
    recovered workhorse declines a sentinel-served binary whose version doesn't
    match this value (avoids silent downgrade); upgrade the sentinel too so its
    :8888 server hands out the matching version. See #385 and the module README.
  EOT
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

# -----------------------------------------------------------------------------
# App hosting + PROXY v2 (real-client-IP preservation)
#
# These four variables form one logical feature: serving customer apps on
# sentinel-fronted hostnames AND making sure the apps see real client IPs
# instead of the sentinel/bridge gateway. They're independent (you can
# enable app-hosting without PROXY v2 if you don't care about visitor IPs,
# or PROXY v2 alone if you have your own routing on top) but in practice
# the demo and prod clusters want both.
# -----------------------------------------------------------------------------

variable "enable_app_hosting" {
  description = "Enable Containarium's app-hosting subsystem (Caddy reverse proxy, ACME, route store). Required for `expose_port` to provision public hostnames automatically."
  type        = bool
  default     = false
}

variable "base_domain" {
  description = "Base domain for app-hosting. When set with enable_app_hosting=true, the daemon registers the management route at this hostname and Caddy ACMEs a cert for it; containers exposed via expose_port get subdomains of this base (e.g. blog.<base_domain>). Empty disables hostname-aware routing."
  type        = string
  default     = ""
}

variable "enable_proxy_protocol" {
  description = "Have the sentinel emit PROXY v2 headers to the backend and have the backend's Caddy parse them so the real client IP propagates as X-Forwarded-For. In simple-proxy mode (single-spot-VM deployments) this also switches the sentinel from kernel iptables DNAT to a userspace TCP forwarder — iptables can't inject the header. Requires Containarium v0.16.7+ on both sentinel and backend."
  type        = bool
  default     = false
}

variable "proxy_protocol_trusted_cidrs" {
  description = "CIDR blocks the backend's Caddy will trust as sources of PROXY v2 frames. Typically the sentinel's internal IP plus loopback. Required when enable_proxy_protocol=true. Wildcard 0.0.0.0/0 is rejected at startup to prevent IP spoofing."
  type        = list(string)
  default     = []
}

variable "zfs_encryption_keyfile" {
  description = "Absolute path on the backend VM for the ZFS native encryption keyfile (e.g. /etc/containarium/zfs.key). When non-empty, the data-disk ZFS pool is created with encryption=on and reads the 32-byte raw key from this path on every boot. The keyfile is generated automatically on first boot if missing. Operators MUST back this file up off-host — losing it makes the pool unrecoverable. Empty (default) = no ZFS-layer encryption, relies on PD/CMEK only. See docs/SECURITY-ENCRYPTION-AT-REST.md."
  type        = string
  default     = ""
}
