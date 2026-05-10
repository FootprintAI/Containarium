// Demo deployment for the agent-native sandbox walkthrough.
//
// Provisions a single-host Containarium cluster with:
//   - Sentinel (e2-micro, free-tier) running sshpiper + Caddy
//   - Spot VM (e2-medium) running the daemon + Incus
//   - Persistent disk for container data
//   - Optional wildcard DNS record (*.<demo_subdomain>.<zone>) → sentinel
//
// Designed to be the smallest realistic deployment that supports the
// full agent-native demo flow (create → ssh → install → expose).
// Costs ~$30/month while running; teardown via terraform destroy.
//
// State is local (terraform.tfstate in this directory). For a long-
// lived demo cluster you may want to wire a GCS backend like the
// production deployment does (see terraform/gce/backend-prod.tf.example
// for the pattern).

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

module "containarium" {
  source = "../modules/containarium"

  // Identity
  project_id    = var.project_id
  region        = var.region
  zone          = var.zone
  instance_name = var.instance_name

  // Sizing — small but real
  machine_type   = var.machine_type
  boot_disk_size = 30

  // Spot + persistent disk: containers survive preemption. Demo
  // viewers see real recovery if they hold the cluster for a few days.
  use_spot_instance     = true
  use_persistent_disk   = true
  data_disk_size        = 100
  data_disk_type        = "pd-balanced"
  enable_disk_snapshots = false // optional; turn on if you keep the cluster around

  // Sentinel — required for the agent-native demo (Caddy + sshpiper
  // hostname routing live here).
  enable_sentinel         = true
  sentinel_machine_type   = "e2-micro"
  sentinel_boot_disk_size = 10

  // Daemon
  enable_containarium_daemon = true
  containarium_version       = var.containarium_version
  containarium_binary_url    = var.containarium_binary_url

  // Access
  admin_ssh_keys      = var.admin_ssh_keys
  allowed_ssh_sources = var.allowed_ssh_sources
  jwt_secret          = var.jwt_secret

  // Networking — no external IP on the spot VM by default; Cloud NAT
  // handles outbound. The sentinel owns the external IP and DNS A-record.
  spot_vm_external_ip = false
  enable_iap_firewall = true

  labels = merge({
    environment = "demo"
    managed_by  = "terraform"
  }, var.labels)
}

// Wildcard DNS record (*.<demo_subdomain>.<zone>) → sentinel IP.
// Skipped when dns_managed_zone_name is empty — set DNS manually in
// that case.
resource "google_dns_record_set" "demo_wildcard" {
  count = var.dns_managed_zone_name == "" ? 0 : 1

  project      = var.project_id
  managed_zone = var.dns_managed_zone_name
  name         = "*.${var.demo_subdomain}.${var.dns_zone_domain}."
  type         = "A"
  ttl          = 300

  rrdatas = [module.containarium.jump_server_ip]
}

// Apex record for the demo subdomain itself (so demo.<zone> also
// works, not just *.demo.<zone>). Useful for hitting the platform
// API or web UI directly.
resource "google_dns_record_set" "demo_apex" {
  count = var.dns_managed_zone_name == "" ? 0 : 1

  project      = var.project_id
  managed_zone = var.dns_managed_zone_name
  name         = "${var.demo_subdomain}.${var.dns_zone_domain}."
  type         = "A"
  ttl          = 300

  rrdatas = [module.containarium.jump_server_ip]
}
