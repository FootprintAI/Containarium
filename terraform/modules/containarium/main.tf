# =============================================================================
# Containarium Terraform Module — Main
# =============================================================================
# Static IP, firewall rules, regular (non-spot) VM instance.
# Network references are parameterized for both default and VPC networks.

terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Locals
# -----------------------------------------------------------------------------

locals {
  network    = var.network_self_link != "" ? var.network_self_link : "default"
  subnetwork = var.subnetwork_self_link != "" ? var.subnetwork_self_link : null
}

# -----------------------------------------------------------------------------
# Static External IP for the jump server
# -----------------------------------------------------------------------------

resource "google_compute_address" "jump_server_ip" {
  name    = "${var.instance_name}-ip"
  region  = var.region
  project = var.project_id
}

# -----------------------------------------------------------------------------
# Firewall Rules
# -----------------------------------------------------------------------------

# Allow SSH to jump server
resource "google_compute_firewall" "allow_ssh" {
  name    = "${var.instance_name}-allow-ssh"
  network = local.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.allowed_ssh_sources
  target_tags   = var.instance_tags

  description = "Allow SSH access to Containarium jump server"
}

# Allow gRPC daemon API
resource "google_compute_firewall" "allow_grpc" {
  count   = var.enable_containarium_daemon ? 1 : 0
  name    = "${var.instance_name}-allow-grpc"
  network = local.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["50051"]
  }

  source_ranges = var.allowed_ssh_sources
  target_tags   = var.instance_tags

  description = "Allow gRPC API access to Containarium daemon"
}

# IAP SSH firewall rule (needed in VPC environments for IAP tunneling)
resource "google_compute_firewall" "allow_iap_ssh" {
  count   = var.enable_iap_firewall ? 1 : 0
  name    = "${var.instance_name}-allow-iap-ssh"
  network = local.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22", "2222"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = var.instance_tags

  description = "Allow IAP SSH tunneling to Containarium instances"
}

# -----------------------------------------------------------------------------
# Regular (non-spot) VM Instance
# -----------------------------------------------------------------------------

resource "google_compute_instance" "jump_server" {
  count = var.use_spot_instance ? 0 : 1

  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone
  project      = var.project_id

  tags = var.instance_tags

  boot_disk {
    kms_key_self_link = var.kms_key_self_link == "" ? null : var.kms_key_self_link
    initialize_params {
      image = var.os_image
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network    = local.network
    subnetwork = local.subnetwork

    access_config {
      nat_ip = google_compute_address.jump_server_ip.address
    }
  }

  metadata = {
    ssh-keys = join("\n", [
      for user, key in var.admin_ssh_keys :
      "${user}:${key}"
    ])
    startup-script = templatefile("${path.module}/scripts/startup.sh", {
      incus_version           = var.incus_version
      admin_users             = keys(var.admin_ssh_keys)
      enable_monitoring       = var.enable_monitoring
      containarium_version    = var.containarium_version
      containarium_binary_url = var.containarium_binary_url
      jwt_secret              = var.jwt_secret
      sentinel_auth_secret    = var.sentinel_auth_secret
      fail2ban_whitelist_cidr = var.fail2ban_whitelist_cidr
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
      role      = "jump-server"
    }
  )

  allow_stopping_for_update = true

  lifecycle {
    ignore_changes = [
      metadata["ssh-keys"],
    ]
  }
}
