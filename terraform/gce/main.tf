terraform {
  required_version = ">= 1.0"

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

# Static external IP for the jump server
resource "google_compute_address" "jump_server_ip" {
  name   = "${var.instance_name}-ip"
  region = var.region
}

# Firewall rule - Allow SSH to jump server
resource "google_compute_firewall" "allow_ssh" {
  name    = "${var.instance_name}-allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.allowed_ssh_sources
  target_tags   = ["containarium-jump-server"]

  description = "Allow SSH access to Containarium jump server"
}

# Firewall rule - Allow gRPC daemon API
resource "google_compute_firewall" "allow_grpc" {
  count   = var.enable_containarium_daemon ? 1 : 0
  name    = "${var.instance_name}-allow-grpc"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["50051"]
  }

  source_ranges = var.allowed_ssh_sources
  target_tags   = ["containarium-jump-server"]

  description = "Allow gRPC API access to Containarium daemon"
}

# Optional: Firewall rule for port forwarding approach
# Uncomment if using port forwarding instead of ProxyJump
# resource "google_compute_firewall" "allow_container_ssh" {
#   name    = "${var.instance_name}-allow-container-ssh"
#   network = "default"
#
#   allow {
#     protocol = "tcp"
#     ports    = ["2200-2299"]  # Ports for container SSH access
#   }
#
#   source_ranges = var.allowed_ssh_sources
#   target_tags   = ["containarium-jump-server"]
#
#   description = "Allow direct SSH access to containers via port forwarding"
# }

# GCE VM Instance - Jump Server + LXC Host (regular instance)
resource "google_compute_instance" "jump_server" {
  count = var.use_spot_instance ? 0 : 1

  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["containarium-jump-server"]

  boot_disk {
    initialize_params {
      image = var.os_image
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network = "default"

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
      incus_version          = var.incus_version
      admin_users            = keys(var.admin_ssh_keys)
      enable_monitoring      = var.enable_monitoring
      containarium_version   = var.containarium_version
      containarium_binary_url = var.containarium_binary_url
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
      metadata["ssh-keys"], # Allow manual SSH key additions
    ]
  }
}

# Copy containarium binary to server (if binary_url is empty)
resource "null_resource" "copy_containarium_binary" {
  count = var.enable_containarium_daemon && var.containarium_binary_url == "" ? 1 : 0

  depends_on = [
    google_compute_instance.jump_server_spot,
    google_compute_instance.jump_server,
  ]

  connection {
    type        = "ssh"
    user        = keys(var.admin_ssh_keys)[0]
    host        = google_compute_address.jump_server_ip.address
    private_key = file("/Users/hsinhoyeh/.ssh/containerium_ed25519")
  }

  provisioner "file" {
    source      = "${path.module}/../../bin/containarium-linux-amd64"
    destination = "/tmp/containarium"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo mv /tmp/containarium /usr/local/bin/containarium",
      "sudo chmod +x /usr/local/bin/containarium",
      "sudo systemctl daemon-reload",
      "sudo systemctl restart containarium",
      "sleep 2",
      "sudo systemctl status containarium --no-pager || true"
    ]
  }

  triggers = {
    instance_id = var.use_spot_instance ? google_compute_instance.jump_server_spot[0].id : google_compute_instance.jump_server[0].id
    binary_hash = filemd5("${path.module}/../../bin/containarium-linux-amd64")
  }
}

# Optional: Cloud DNS for jump server
# resource "google_dns_record_set" "jump_server_dns" {
#   count = var.dns_zone_name != "" ? 1 : 0
#
#   name         = "jump.${var.dns_zone_domain}"
#   type         = "A"
#   ttl          = 300
#   managed_zone = var.dns_zone_name
#   rrdatas      = [google_compute_address.jump_server_ip.address]
# }
