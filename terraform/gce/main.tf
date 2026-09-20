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

module "containarium" {
  source = "../modules/containarium"

  # Project & region
  project_id    = var.project_id
  region        = var.region
  zone          = var.zone
  instance_name = var.instance_name
  machine_type  = var.machine_type

  # Instance config
  os_image              = var.os_image
  boot_disk_size        = var.boot_disk_size
  boot_disk_type        = var.boot_disk_type
  boot_disk_auto_delete = var.boot_disk_auto_delete

  # Dev defaults: default network, ephemeral IPs
  # network_self_link and subnetwork_self_link default to ""
  spot_vm_external_ip = true

  # SSH & Security
  admin_ssh_keys      = var.admin_ssh_keys
  allowed_ssh_sources = var.allowed_ssh_sources

  # Incus & Software
  incus_version     = var.incus_version
  enable_monitoring = var.enable_monitoring

  # Service account & labels
  service_account_email = var.service_account_email
  labels                = var.labels

  # DNS
  dns_zone_name   = var.dns_zone_name
  dns_zone_domain = var.dns_zone_domain

  # Spot instance & persistent disk
  use_spot_instance     = var.use_spot_instance
  use_persistent_disk   = var.use_persistent_disk
  data_disk_size        = var.data_disk_size
  data_disk_type        = var.data_disk_type
  enable_disk_snapshots = var.enable_disk_snapshots

  # Containarium daemon
  containarium_version       = var.containarium_version
  containarium_binary_url    = var.containarium_binary_url
  enable_containarium_daemon = var.enable_containarium_daemon

  # Sentinel HA
  enable_sentinel         = var.enable_sentinel
  sentinel_machine_type   = var.sentinel_machine_type
  sentinel_boot_disk_size = var.sentinel_boot_disk_size
}
