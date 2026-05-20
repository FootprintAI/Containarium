# =============================================================================
# Containarium Terraform Module — Sentinel VM
# =============================================================================
# Sentinel VM for HA spot instance recovery.
# Uses the same static IP as jump_server_ip (sentinel owns it, spot VM uses internal).
# All resources are conditional on enable_sentinel + use_spot_instance.

locals {
  use_sentinel = var.enable_sentinel && var.use_spot_instance
}

# -----------------------------------------------------------------------------
# Sentinel VM — tiny always-on instance that owns the public static IP
# Runs in the SAME region/zone as spot VM (matching production setup).
# -----------------------------------------------------------------------------

resource "google_compute_instance" "sentinel" {
  count = local.use_sentinel ? 1 : 0

  name         = "${var.instance_name}-sentinel"
  machine_type = var.sentinel_machine_type
  zone         = var.zone
  project      = var.project_id

  tags = concat(["containarium-sentinel"], var.instance_tags)

  # Always-on: standard provisioning, live-migrate on maintenance
  scheduling {
    preemptible         = false
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }

  boot_disk {
    auto_delete       = true
    kms_key_self_link = var.kms_key_self_link == "" ? null : var.kms_key_self_link
    initialize_params {
      image = var.os_image
      size  = var.sentinel_boot_disk_size
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = local.network
    subnetwork = local.subnetwork

    access_config {
      # Sentinel owns the public static IP
      nat_ip = google_compute_address.jump_server_ip.address
    }
  }

  metadata = {
    ssh-keys = join("\n", [
      for user, key in var.admin_ssh_keys :
      "${user}:${key}"
    ])
    startup-script = templatefile("${path.module}/scripts/startup-sentinel.sh", {
      admin_users             = keys(var.admin_ssh_keys)
      containarium_binary_url = var.containarium_binary_url
      spot_vm_name            = local.spot_vm_name
      zone                    = var.zone
      project_id              = var.project_id
      enable_proxy_protocol   = var.enable_proxy_protocol
      sentinel_auth_secret    = var.sentinel_auth_secret
      enable_peer_mtls        = var.enable_peer_mtls
    })
  }

  service_account {
    email  = var.service_account_email
    scopes = ["cloud-platform"]
  }

  labels = merge(
    var.labels,
    {
      component = "containarium"
      role      = "sentinel"
    }
  )

  allow_stopping_for_update = true

  lifecycle {
    ignore_changes = [
      metadata["ssh-keys"],
    ]
  }
}

# -----------------------------------------------------------------------------
# Sentinel Firewall Rules
# -----------------------------------------------------------------------------

# Allow SSH/HTTP/HTTPS from internet to sentinel
resource "google_compute_firewall" "sentinel_ingress" {
  count = local.use_sentinel ? 1 : 0

  name    = "${var.instance_name}-sentinel-ingress"
  network = local.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443"]
  }

  source_ranges = var.allowed_ssh_sources
  target_tags   = ["containarium-sentinel"]

  description = "Allow SSH (sshpiper on :22) / HTTP / HTTPS to Containarium sentinel"
}

# Allow sentinel to forward user traffic to the spot backend.
# Carries SSH (sshpiper → backend per-user shell), HTTP, and HTTPS.
# These are user-facing protocols proxied through the sentinel.
resource "google_compute_firewall" "sentinel_to_spot" {
  count = local.use_sentinel ? 1 : 0

  name    = "${var.instance_name}-sentinel-to-spot"
  network = local.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443"]
  }

  source_tags = ["containarium-sentinel"]
  target_tags = ["containarium-spot-backend"]

  description = "Allow sentinel to forward user traffic (SSH/HTTP/HTTPS) to spot backend"
}

# Phase 2.4 — REST daemon API explicit pinning.
# Port 8080 (the daemon's HTTP/REST gateway) is split out into its
# own firewall rule so the audit trail makes clear: the API is
# only reachable from the sentinel, not from any other source.
# Audit C-HIGH-4 noted that 8080 wasn't explicitly pinned —
# previously it shared a rule with user-facing 22/80/443 and
# inherited the same tag scope, which is correct but inseparable
# in `terraform plan` diffs. Splitting it out means an operator
# can't accidentally widen the API exposure by editing one rule
# without seeing the implication.
resource "google_compute_firewall" "sentinel_to_spot_rest_api" {
  count = local.use_sentinel ? 1 : 0

  name    = "${var.instance_name}-sentinel-to-spot-rest-api"
  network = local.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_tags = ["containarium-sentinel"]
  target_tags = ["containarium-spot-backend"]

  description = "Allow sentinel to reach daemon REST API on :8080 (sentinel-only, no other source)"
}

# Allow spot VM to reach the sentinel binary server: 8888 = legacy
# HTTP (binary download, peer discovery, key/cert sync, peers
# endpoint); 8889 = Phase 0.5 HTTPS variant of the same handlers
# (used once enable_peer_mtls=true). Both ports stay internal-only —
# the spot-backend tag is the only allowed source.
resource "google_compute_firewall" "spot_to_sentinel_binary" {
  count = local.use_sentinel ? 1 : 0

  name    = "${var.instance_name}-spot-to-sentinel-binary"
  network = local.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["8888", "8889"]
  }

  source_tags = ["containarium-spot-backend"]
  target_tags = ["containarium-sentinel"]

  description = "Allow spot VM to reach sentinel binary server (HTTP 8888 + Phase 0.5 HTTPS 8889)"
}

# Allow SSH management on port 2222 (port 22 is handled by sshpiper).
# Phase 2.3: now sourced from `allowed_management_sources` (VPC-only
# default) rather than `allowed_ssh_sources` — sentinel admin SSH is
# an operator surface, not a user surface, and shouldn't default to
# 0.0.0.0/0.
resource "google_compute_firewall" "sentinel_mgmt_ssh" {
  count = local.use_sentinel ? 1 : 0

  name    = "${var.instance_name}-sentinel-mgmt-ssh"
  network = local.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["2222"]
  }

  source_ranges = var.allowed_management_sources
  target_tags   = ["containarium-sentinel"]

  description = "Allow SSH management to sentinel on port 2222 (operator-only, VPC default)"
}

