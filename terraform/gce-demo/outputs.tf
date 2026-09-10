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

// Echo the GCP coordinates so scripts can `terraform output -raw zone`
// instead of parsing them out of other outputs.
output "project_id" {
  description = "GCP project ID for this deployment."
  value       = var.project_id
}

output "zone" {
  description = "GCP zone for this deployment."
  value       = var.zone
}

output "demo_base_domain" {
  description = "Base hostname the daemon serves apps under (and where the platform API is reachable at https://<this>). Apps deployed during the demo land at <name>.<this>. Wildcard DNS for *.<this> must point at sentinel_ip."
  value       = var.base_domain != "" ? var.base_domain : "(app-hosting disabled)"
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

    1. Issue a 24h admin JWT. The daemon + jwt.secret live on the BACKEND,
       which has no public IP — reach it over IAP (the sentinel's port 22 is
       sshpiper, not a host shell, so issue the token on the backend):

       gcloud compute ssh ${module.containarium.spot_vm_name} \
           --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap \
           --command='sudo /usr/local/bin/containariumd token generate \
                       --username demo --roles admin --expiry 24h \
                       --secret-file /etc/containarium/jwt.secret \
                       2>/dev/null | grep "^eyJ"' \
           > ~/.containarium-demo-token.txt && \
       chmod 600 ~/.containarium-demo-token.txt

    2. Build the platform MCP binary and wire Claude Code. The API is reached
       through the sentinel's Caddy over HTTPS (port 8080 is not exposed
       publicly), so point the MCP server at https://${var.base_domain}:

       make build-mcp
       claude mcp add containarium-demo --scope user \
         --env CONTAINARIUM_SERVER_URL=https://${var.base_domain} \
         --env CONTAINARIUM_JWT_TOKEN="$(cat ~/.containarium-demo-token.txt)" \
         -- $(pwd)/bin/mcp-server

    3. Restart Claude Code so it picks up the new server.

    4. Drive the demo with one prompt:

       "Spin up a sandbox called 'demo-blog', install nginx, serve a
        hello-world page, and expose it at demo-blog.${var.base_domain}."

    5. When the recording is done:

       terraform destroy

    ─────────────────────────────────────────────────────────────────
  EOT
}
