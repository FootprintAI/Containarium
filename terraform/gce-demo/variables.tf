// Identity ------------------------------------------------------------

variable "project_id" {
  description = "GCP project ID. The cluster, DNS records, and IAM resources all live here."
  type        = string
}

variable "region" {
  description = "GCP region for the spot VM and sentinel."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone (single-AZ for the demo)."
  type        = string
  default     = "us-central1-a"
}

variable "instance_name" {
  description = "Name prefix for the demo instances. The spot VM is <name>, the sentinel is <name>-sentinel."
  type        = string
  default     = "containarium-demo"
}

variable "machine_type" {
  description = "GCE machine type for the spot backend VM. e2-standard-2 (2 vCPU, 8 GB) is enough for the demo container plus Incus overhead. Note: the upstream module's regex rejects shared-core types (e2-medium / e2-small / e2-micro)."
  type        = string
  default     = "e2-standard-2"
}

// Versioning ----------------------------------------------------------

variable "containarium_version" {
  description = "Containarium version to install on the demo VM. Should match a tagged release at https://github.com/footprintai/Containarium/releases."
  type        = string
  default     = "0.16.4"
}

variable "containarium_binary_url" {
  description = "Override the binary download URL. Empty means derive from containarium_version (the standard release URL pattern)."
  type        = string
  default     = ""
}

// Access --------------------------------------------------------------

variable "admin_ssh_keys" {
  description = "Map of admin username → SSH public key string. The admin can SSH into the sentinel for token issuance."
  type        = map(string)
}

variable "allowed_ssh_sources" {
  description = "CIDR blocks allowed to SSH to the sentinel on port 22. Restrict to your egress IP for a real demo; broad for a quick test."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "jwt_secret" {
  description = "JWT signing secret used by the daemon. Anyone holding it can mint admin tokens, so generate a random one and don't commit it to public terraform.tfvars."
  type        = string
  sensitive   = true
}

// DNS -----------------------------------------------------------------

variable "dns_managed_zone_name" {
  description = "Cloud DNS managed-zone resource name (e.g. 'kafeido-app'). Empty disables DNS provisioning — set the *.<subdomain> A-record manually elsewhere in that case."
  type        = string
  default     = ""
}

variable "dns_zone_domain" {
  description = "DNS zone's domain (e.g. 'kafeido.app'). Required only when dns_managed_zone_name is set."
  type        = string
  default     = ""
}

variable "demo_subdomain" {
  description = "Subdomain for the demo deployment. The demo flow exposes apps at <whatever>.<demo_subdomain>.<dns_zone_domain>, e.g. blog.demo.kafeido.app."
  type        = string
  default     = "demo"
}

// Misc ----------------------------------------------------------------

variable "labels" {
  description = "Extra labels merged onto every resource."
  type        = map(string)
  default     = {}
}
