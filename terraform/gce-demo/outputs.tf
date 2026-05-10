output "sentinel_ip" {
  description = "External IP of the sentinel VM. Wildcard DNS records point here."
  value       = module.containarium.jump_server_ip
}

output "sentinel_vm_name" {
  description = "GCE instance name of the sentinel."
  value       = module.containarium.sentinel_vm_name
}

output "spot_vm_name" {
  description = "GCE instance name of the backend VM where the daemon + Incus run."
  value       = module.containarium.spot_vm_name
}

output "demo_base_domain" {
  description = "Base hostname for the demo. Apps deployed during the demo land at <name>.<this>."
  value       = var.dns_managed_zone_name == "" ? "(set DNS manually)" : "${var.demo_subdomain}.${var.dns_zone_domain}"
}

output "ssh_command" {
  description = "SSH command for the sentinel (admin shell access)."
  value       = module.containarium.ssh_command
}

output "next_steps" {
  description = "Copy-paste guide to issue a JWT and wire Claude Code's MCP server."
  value       = <<-EOT

    ─────────────────────────────────────────────────────────────────
    Demo cluster ready. Next steps:
    ─────────────────────────────────────────────────────────────────

    1. Issue a 24h admin JWT (run on the sentinel via gcloud SSH):

       gcloud compute ssh ${module.containarium.sentinel_vm_name} \
           --project=${var.project_id} --zone=${var.zone} \
           --command='sudo /usr/local/bin/containarium token generate \
                       --username demo --roles admin --expiry 24h \
                       --secret-file /etc/containarium/jwt.secret \
                       2>/dev/null | grep "^eyJ"' \
           > ~/.containarium-demo-token.txt && \
       chmod 600 ~/.containarium-demo-token.txt

    2. Build the platform MCP binary and wire Claude Code:

       make build-mcp
       claude mcp add containarium-demo --scope user \
         --env CONTAINARIUM_SERVER_URL=http://${module.containarium.jump_server_ip}:8080 \
         --env CONTAINARIUM_JWT_TOKEN="$(cat ~/.containarium-demo-token.txt)" \
         -- $(pwd)/bin/mcp-server

    3. Restart Claude Code so it picks up the new server.

    4. Drive the demo with one prompt:

       "Spin up a sandbox called 'demo-blog', install nginx, serve a
        hello-world page, and expose it at demo-blog.${var.dns_managed_zone_name == "" ? "<your-domain>" : "${var.demo_subdomain}.${var.dns_zone_domain}"}."

    5. When the recording is done:

       terraform destroy

    ─────────────────────────────────────────────────────────────────
  EOT
}
