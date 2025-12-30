# Spot Instance Configuration with Persistent Disk
# This file defines resources for running Containarium on spot instances with persistent storage

# Persistent disk for Incus data (survives spot termination)
resource "google_compute_disk" "incus_data" {
  count = var.use_persistent_disk ? 1 : 0

  name  = "${var.instance_name}-incus-data"
  type  = var.data_disk_type
  zone  = var.zone
  size  = var.data_disk_size

  labels = merge(
    var.labels,
    {
      component = "containarium"
      role      = "storage"
      data_type = "incus-containers"
    }
  )

  lifecycle {
    prevent_destroy = true  # Protect container data from accidental deletion
  }
}

# Snapshot schedule for daily backups
resource "google_compute_resource_policy" "incus_data_snapshot_policy" {
  count = var.enable_disk_snapshots ? 1 : 0

  name   = "${var.instance_name}-snapshot-policy"
  region = var.region

  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "03:00"  # 3 AM daily
      }
    }

    retention_policy {
      max_retention_days    = 30
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }

    snapshot_properties {
      labels = {
        snapshot_type = "automated"
        resource      = "containarium"
      }
      storage_locations = [var.region]
      guest_flush       = true
    }
  }
}

# Modified GCE instance for spot/preemptible usage
resource "google_compute_instance" "jump_server_spot" {
  count = var.use_spot_instance ? 1 : 0

  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["containarium-jump-server"]

  # Spot instance configuration
  scheduling {
    preemptible                 = true
    automatic_restart           = false
    on_host_maintenance         = "TERMINATE"
    provisioning_model          = "SPOT"
    instance_termination_action = "STOP"  # STOP preserves disk, DELETE removes it
  }

  boot_disk {
    auto_delete = true
    initialize_params {
      image = var.os_image
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  # Attach persistent disk for Incus data
  dynamic "attached_disk" {
    for_each = var.use_persistent_disk ? [1] : []
    content {
      source      = google_compute_disk.incus_data[0].id
      device_name = "incus-data"
      mode        = "READ_WRITE"
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
    startup-script = templatefile("${path.module}/scripts/startup-spot.sh", {
      incus_version          = var.incus_version
      admin_users            = keys(var.admin_ssh_keys)
      enable_monitoring      = var.enable_monitoring
      use_persistent_disk    = var.use_persistent_disk
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
      component     = "containarium"
      role          = "jump-server"
      instance_type = "spot"
    }
  )

  allow_stopping_for_update = true

  lifecycle {
    ignore_changes = [
      metadata["ssh-keys"],
    ]
  }
}
