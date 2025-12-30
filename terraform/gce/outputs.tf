output "jump_server_ip" {
  description = "Public IP address of the jump server"
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

output "ssh_config_snippet" {
  description = "SSH config snippet for ~/.ssh/config"
  value       = <<-EOT
    # Containarium Jump Server
    Host containarium-jump
        HostName ${google_compute_address.jump_server_ip.address}
        User admin
        IdentityFile ~/.ssh/id_rsa

    # Example container access (add more as containers are created)
    # Host alice-dev
    #     HostName 10.0.3.100
    #     User alice
    #     ProxyJump containarium-jump
  EOT
}

output "setup_commands" {
  description = "Commands to run after deployment"
  value       = <<-EOT
    1. SSH to jump server:
       ssh admin@${google_compute_address.jump_server_ip.address}

    2. Verify Incus installation:
       incus --version
       incus list

    3. Copy containarium CLI to server:
       scp bin/containarium-linux-amd64 admin@${google_compute_address.jump_server_ip.address}:/tmp/
       ssh admin@${google_compute_address.jump_server_ip.address} 'sudo mv /tmp/containarium-linux-amd64 /usr/local/bin/containarium && sudo chmod +x /usr/local/bin/containarium'

    4. Create your first container:
       containarium create alice --ssh-key ~/.ssh/alice.pub

    5. Add SSH config to your local machine - see ssh_config_snippet output
  EOT
}

output "gcp_console_url" {
  description = "URL to view the instance in GCP Console"
  value       = var.enable_horizontal_scaling && var.jump_server_count > 1 ? "https://console.cloud.google.com/compute/instances?project=${var.project_id}" : (var.use_spot_instance ? "https://console.cloud.google.com/compute/instancesDetail/zones/${google_compute_instance.jump_server_spot[0].zone}/instances/${google_compute_instance.jump_server_spot[0].name}?project=${var.project_id}" : "https://console.cloud.google.com/compute/instancesDetail/zones/${google_compute_instance.jump_server[0].zone}/instances/${google_compute_instance.jump_server[0].name}?project=${var.project_id}")
}

# Horizontal Scaling Outputs

output "horizontal_scaling_enabled" {
  description = "Whether horizontal scaling is enabled"
  value       = var.enable_horizontal_scaling && var.jump_server_count > 1
}

output "jump_servers_count" {
  description = "Number of jump servers deployed"
  value       = var.enable_horizontal_scaling && var.jump_server_count > 1 ? var.jump_server_count : 1
}

output "jump_servers_ips" {
  description = "IP addresses of all jump servers"
  value = var.enable_horizontal_scaling && var.jump_server_count > 1 ? {
    for i, ip in google_compute_address.jump_servers_ips :
    "jump-${i + 1}" => ip.address
  } : {
    "jump-1" = google_compute_address.jump_server_ip.address
  }
}

output "load_balancer_ip" {
  description = "IP address of the load balancer (if enabled)"
  value       = var.enable_horizontal_scaling && var.enable_load_balancer && var.jump_server_count > 1 ? google_compute_forwarding_rule.jump_servers_ssh[0].ip_address : null
}

output "load_balancer_enabled" {
  description = "Whether load balancer is enabled"
  value       = var.enable_horizontal_scaling && var.enable_load_balancer && var.jump_server_count > 1
}

output "ssh_connection_methods" {
  description = "Methods to connect to the jump servers"
  value = var.enable_horizontal_scaling && var.jump_server_count > 1 ? (
    var.enable_load_balancer ? <<-EOT
      === Connection Methods ===

      1. Via Load Balancer (Recommended):
         ssh admin@${google_compute_forwarding_rule.jump_servers_ssh[0].ip_address}

      2. Direct to Specific Server:
         ${join("\n         ", [for i, ip in google_compute_address.jump_servers_ips : "ssh admin@${ip.address}  # jump-${i + 1}"])}

      3. With DNS (if configured):
         ssh admin@jump.${var.dns_zone_domain}

      The load balancer automatically distributes connections across healthy servers.
    EOT
    : <<-EOT
      === Connection Methods ===

      Connect to any jump server directly:
      ${join("\n      ", [for i, ip in google_compute_address.jump_servers_ips : "ssh admin@${ip.address}  # jump-${i + 1}"])}

      Note: Load balancer is disabled. Users must choose which server to connect to.
    EOT
  ) : "ssh admin@${google_compute_address.jump_server_ip.address}"
}

output "horizontal_scaling_ssh_config" {
  description = "SSH config snippet for horizontal scaling"
  value = var.enable_horizontal_scaling && var.jump_server_count > 1 ? (
    var.enable_load_balancer ? <<-EOT
      # Containarium Jump Servers (Load Balanced)
      Host containarium-jump
          HostName ${google_compute_forwarding_rule.jump_servers_ssh[0].ip_address}
          User admin
          IdentityFile ~/.ssh/id_rsa

      # Individual servers (for maintenance/debugging)
      ${join("\n      ", [for i, ip in google_compute_address.jump_servers_ips : "# Host jump-${i + 1}\n      #     HostName ${ip.address}\n      #     User admin"])}
    EOT
    : <<-EOT
      # Containarium Jump Servers (Manual Selection)
      ${join("\n      ", [for i, ip in google_compute_address.jump_servers_ips : "Host jump-${i + 1}\n      HostName ${ip.address}\n      User admin\n      IdentityFile ~/.ssh/id_rsa\n"])}

      # Use any server (round-robin manually)
      Host containarium-jump
          HostName ${google_compute_address.jump_servers_ips[0].address}
          User admin
    EOT
  ) : null
}

output "capacity_info" {
  description = "Capacity information for the deployment"
  value = {
    servers          = var.enable_horizontal_scaling && var.jump_server_count > 1 ? var.jump_server_count : 1
    machine_type     = var.machine_type
    estimated_users  = var.enable_horizontal_scaling && var.jump_server_count > 1 ? var.jump_server_count * 50 : 50
    using_spot       = var.use_spot_instance
    persistent_disk  = var.use_persistent_disk
    load_balanced    = var.enable_horizontal_scaling && var.enable_load_balancer && var.jump_server_count > 1
  }
}

# Containarium Daemon Outputs

output "daemon_enabled" {
  description = "Whether Containarium gRPC daemon is enabled"
  value       = var.enable_containarium_daemon
}

output "daemon_endpoint" {
  description = "gRPC daemon endpoint (host:port)"
  value       = var.enable_containarium_daemon ? "${google_compute_address.jump_server_ip.address}:50051" : "Not enabled"
}

output "daemon_test_commands" {
  description = "Commands to test the gRPC daemon"
  value = var.enable_containarium_daemon ? "grpcurl -plaintext ${google_compute_address.jump_server_ip.address}:50051 list" : "Daemon not enabled"
}

# Simplified aliases for E2E testing

output "instance_name" {
  description = "Alias for jump_server_name (for E2E tests)"
  value       = var.use_spot_instance ? google_compute_instance.jump_server_spot[0].name : google_compute_instance.jump_server[0].name
}

output "zone" {
  description = "Alias for jump_server_zone (for E2E tests)"
  value       = var.use_spot_instance ? google_compute_instance.jump_server_spot[0].zone : google_compute_instance.jump_server[0].zone
}
