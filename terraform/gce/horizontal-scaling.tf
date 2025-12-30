# Horizontal Scaling Configuration
# Deploy multiple jump servers for increased capacity and fault tolerance

locals {
  # Use horizontal scaling instances instead of single instance
  use_horizontal = var.enable_horizontal_scaling && var.jump_server_count > 1

  # Generate server names
  server_names = [
    for i in range(var.jump_server_count) :
    "${var.instance_name}-${i + 1}"
  ]
}

# Static external IPs for each jump server
resource "google_compute_address" "jump_servers_ips" {
  count = local.use_horizontal ? var.jump_server_count : 0

  name   = "${var.instance_name}-${count.index + 1}-ip"
  region = var.region
}

# Persistent disks for each jump server
resource "google_compute_disk" "jump_servers_data" {
  count = local.use_horizontal && var.use_persistent_disk ? var.jump_server_count : 0

  name = "${var.instance_name}-${count.index + 1}-data"
  type = var.data_disk_type
  zone = var.zone
  size = var.data_disk_size

  labels = merge(
    var.labels,
    {
      component = "containarium"
      role      = "storage"
      server_id = tostring(count.index + 1)
    }
  )

  lifecycle {
    prevent_destroy = true
  }
}

# Multiple jump server instances
resource "google_compute_instance" "jump_servers" {
  count = local.use_horizontal ? var.jump_server_count : 0

  name         = local.server_names[count.index]
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["containarium-jump-server", "jump-server-${count.index + 1}"]

  # Spot instance configuration (if enabled)
  scheduling {
    preemptible                 = var.use_spot_instance
    automatic_restart           = !var.use_spot_instance
    on_host_maintenance         = var.use_spot_instance ? "TERMINATE" : "MIGRATE"
    provisioning_model          = var.use_spot_instance ? "SPOT" : "STANDARD"
    instance_termination_action = var.use_spot_instance ? "STOP" : null
  }

  boot_disk {
    auto_delete = true
    initialize_params {
      image = var.os_image
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  # Attach persistent disk if enabled
  dynamic "attached_disk" {
    for_each = var.use_persistent_disk ? [1] : []
    content {
      source      = google_compute_disk.jump_servers_data[count.index].id
      device_name = "incus-data"
      mode        = "READ_WRITE"
    }
  }

  network_interface {
    network = "default"

    access_config {
      nat_ip = google_compute_address.jump_servers_ips[count.index].address
    }
  }

  metadata = {
    ssh-keys = join("\n", [
      for user, key in var.admin_ssh_keys :
      "${user}:${key}"
    ])

    # Server ID for identification
    server-id = count.index + 1

    startup-script = templatefile(
      "${path.module}/scripts/${var.use_spot_instance ? "startup-spot.sh" : "startup.sh"}",
      {
        incus_version      = var.incus_version
        admin_users        = keys(var.admin_ssh_keys)
        enable_monitoring  = var.enable_monitoring
        use_persistent_disk = var.use_persistent_disk
      }
    )
  }

  service_account {
    email  = var.service_account_email
    scopes = ["cloud-platform"]
  }

  labels = merge(
    var.labels,
    {
      component     = "containarium"
      role          = "jump-server"
      server_id     = tostring(count.index + 1)
      instance_type = var.use_spot_instance ? "spot" : "regular"
    }
  )

  allow_stopping_for_update = true

  lifecycle {
    ignore_changes = [
      metadata["ssh-keys"],
    ]
  }
}

# Unmanaged instance group for load balancer backend
resource "google_compute_instance_group" "jump_servers" {
  count = local.use_horizontal && var.enable_load_balancer ? 1 : 0

  name = "${var.instance_name}-group"
  zone = var.zone

  instances = [
    for instance in google_compute_instance.jump_servers :
    instance.id
  ]

  named_port {
    name = "ssh"
    port = 22
  }
}

# Health check for jump servers (SSH connectivity)
resource "google_compute_health_check" "jump_servers_ssh" {
  count = local.use_horizontal && var.enable_load_balancer ? 1 : 0

  name                = "${var.instance_name}-ssh-health"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = 22
  }
}

# Network load balancer backend service
resource "google_compute_region_backend_service" "jump_servers" {
  count = local.use_horizontal && var.enable_load_balancer ? 1 : 0

  name                  = "${var.instance_name}-backend"
  region                = var.region
  protocol              = "TCP"
  load_balancing_scheme = "EXTERNAL"
  timeout_sec           = 60

  backend {
    group = google_compute_instance_group.jump_servers[0].id
  }

  health_checks = [google_compute_health_check.jump_servers_ssh[0].id]

  session_affinity = "CLIENT_IP"  # Keep user connected to same server
}

# Forwarding rule for SSH traffic
resource "google_compute_forwarding_rule" "jump_servers_ssh" {
  count = local.use_horizontal && var.enable_load_balancer ? 1 : 0

  name                  = "${var.instance_name}-ssh-lb"
  region                = var.region
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "22"
  backend_service       = google_compute_region_backend_service.jump_servers[0].id

  # Optional: use reserved IP for load balancer
  ip_address = var.load_balancer_ip != "" ? var.load_balancer_ip : null
}

# DNS record for load balancer (if DNS zone provided)
resource "google_dns_record_set" "jump_servers_lb" {
  count = local.use_horizontal && var.enable_load_balancer && var.dns_zone_name != "" ? 1 : 0

  name         = "jump.${var.dns_zone_domain}."
  type         = "A"
  ttl          = 300
  managed_zone = var.dns_zone_name
  rrdatas      = [google_compute_forwarding_rule.jump_servers_ssh[0].ip_address]
}

# DNS records for individual servers (for direct access)
resource "google_dns_record_set" "jump_servers_individual" {
  count = local.use_horizontal && var.dns_zone_name != "" ? var.jump_server_count : 0

  name         = "jump-${count.index + 1}.${var.dns_zone_domain}."
  type         = "A"
  ttl          = 300
  managed_zone = var.dns_zone_name
  rrdatas      = [google_compute_address.jump_servers_ips[count.index].address]
}
