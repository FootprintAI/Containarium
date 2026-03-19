# =============================================================================
# Containarium Terraform Module — Outputs
# =============================================================================

output "jump_server_ip" {
  description = "Public IP address of the jump server (sentinel owns it when sentinel is enabled)"
  value       = google_compute_address.jump_server_ip.address
}

output "jump_server_name" {
  description = "Name of the jump server instance"
  value       = var.use_spot_instance ? google_compute_instance.jump_server_spot[0].name : google_compute_instance.jump_server[0].name
}

output "jump_server_zone" {
  description = "Zone where the jump server is deployed"
  value       = var.use_spot_instance ? google_compute_instance.jump_server_spot[0].zone : google_compute_instance.jump_server[0].zone
}

output "ssh_command" {
  description = "SSH command to connect to the jump server"
  value       = "ssh admin@${google_compute_address.jump_server_ip.address}"
}

output "sentinel_enabled" {
  description = "Whether sentinel HA is enabled"
  value       = local.use_sentinel
}

output "sentinel_vm_name" {
  description = "Name of the sentinel VM instance"
  value       = local.use_sentinel ? google_compute_instance.sentinel[0].name : null
}

output "sentinel_instance_self_link" {
  description = "Self link of the sentinel VM instance"
  value       = local.use_sentinel ? google_compute_instance.sentinel[0].self_link : null
}

output "spot_vm_name" {
  description = "Name of the spot VM"
  value       = var.use_spot_instance ? google_compute_instance.jump_server_spot[0].name : null
}

output "spot_vm_internal_ip" {
  description = "Internal IP of the spot VM (used by sentinel for forwarding)"
  value       = local.use_sentinel && var.use_spot_instance ? google_compute_instance.jump_server_spot[0].network_interface[0].network_ip : null
}

output "daemon_enabled" {
  description = "Whether Containarium gRPC daemon is enabled"
  value       = var.enable_containarium_daemon
}

output "daemon_endpoint" {
  description = "gRPC daemon endpoint (host:port)"
  value       = var.enable_containarium_daemon ? "${google_compute_address.jump_server_ip.address}:50051" : "Not enabled"
}

# Aliases for E2E testing
output "instance_name" {
  description = "Alias for jump_server_name (for E2E tests)"
  value       = var.use_spot_instance ? google_compute_instance.jump_server_spot[0].name : google_compute_instance.jump_server[0].name
}

output "zone" {
  description = "Alias for jump_server_zone (for E2E tests)"
  value       = var.use_spot_instance ? google_compute_instance.jump_server_spot[0].zone : google_compute_instance.jump_server[0].zone
}
