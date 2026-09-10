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

// Derive the GitHub release URL when an explicit override isn't given.
// The startup script otherwise has no source for the binary on a fresh
// install (no file provisioner, no sentinel binary server set up yet).
//
// #1781 (design doc, Rollout Phase 1): the release artifact is still
// published as containarium-* (renaming that is #1782) — only the
// startup script's on-host install path changes, to
// /usr/local/bin/containariumd, with the old name symlinked for compat.
locals {
  containarium_binary_url = var.containarium_binary_url != "" ? var.containarium_binary_url : (
    "https://github.com/footprintai/Containarium/releases/download/v${var.containarium_version}/containarium-linux-amd64"
  )
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
  containarium_binary_url    = local.containarium_binary_url

  // App-hosting: the demo serves customer apps at subdomains of
  // base_domain (e.g. blog.demo.containarium.dev). Caddy ACMEs each
  // hostname on demand. Wildcard DNS for *.<base_domain> must point
  // at the sentinel's IP — Cloudflare-managed today.
  enable_app_hosting = true
  base_domain        = var.base_domain

  // PROXY v2: have the sentinel emit a PROXY v2 header on each
  // forwarded connection so the backend's Caddy sees the real client
  // IP. Without this, the simple-proxy sentinel mode passes traffic
  // through kernel iptables DNAT + MASQUERADE — the backend sees
  // 10.0.3.1 (LXC bridge) as the source for every request. Trusted
  // CIDR covers the GCP internal VPC + loopback; tighten to the
  // sentinel's exact IP for prod-style deployments.
  enable_proxy_protocol        = true
  proxy_protocol_trusted_cidrs = ["10.0.0.0/8", "127.0.0.0/8"]

  // Access
  admin_ssh_keys      = var.admin_ssh_keys
  allowed_ssh_sources = var.allowed_ssh_sources
  jwt_secret          = var.jwt_secret

  // Shared HMAC secret for sentinel→daemon keysync/certsync. Mandatory
  // on v0.22.x: without it the backend 401s every sync and tenant SSH
  // never wires up. Both sentinel and backend get it via startup env.
  sentinel_auth_secret = var.sentinel_auth_secret

  // Networking — the backend has NO external IP. It isn't internet-
  // reachable; outbound (apt, container image pulls, container egress)
  // goes through the Cloud NAT provisioned below. The shared module
  // assumes a NAT already exists when spot_vm_external_ip=false but
  // doesn't create one, so this consumer provisions it. Inbound stays
  // intact: sentinel→backend is internal VPC, admin SSH is via IAP.
  spot_vm_external_ip = false
  enable_iap_firewall = true

  labels = merge({
    environment = "demo"
    managed_by  = "terraform"
  }, var.labels)
}

// Cloud NAT — outbound internet for the backend (and its containers)
// now that it has no external IP. Without this the backend can't apt,
// pull LXC/docker images, or let containers reach the network. The
// shared module expects a NAT to exist but doesn't create one, so the
// demo consumer provisions a minimal one on the default network.
// Cost: ~$1.40/month for the gateway + $0.045/GB processed.
resource "google_compute_router" "demo" {
  name    = "${var.instance_name}-router"
  project = var.project_id
  region  = var.region
  network = "default"
}

resource "google_compute_router_nat" "demo" {
  name                               = "${var.instance_name}-nat"
  project                            = var.project_id
  region                             = var.region
  router                             = google_compute_router.demo.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = false
    filter = "ERRORS_ONLY"
  }
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
