# Rendered independently of VM resources so policy can be tested without GCP.
locals {
  ssh_upstream_policy_json = jsonencode({
    initialDelay  = "1s", maxDelay = "30s", window = "${var.ssh_upstream_window_seconds}s", setupTimeout = "30s",
    failureBudget = var.ssh_upstream_failure_budget, riskPerAttempt = var.ssh_upstream_risk_per_attempt,
    maxBackends   = 1024, maxPending = 32, maxConnections = 4096, jitter = 0.25, egressGroup = "sentinel"
  })
  ssh_ban_policy = {
    ssh_ban_max_failures     = var.ssh_ban_max_failures
    ssh_ban_duration_seconds = var.ssh_ban_duration_seconds
    ssh_ban_ignore_cidrs     = var.ssh_ban_ignore_cidrs
    ssh_ban_audit_records    = var.ssh_ban_audit_records
  }
  sshpiper_service_unit = templatefile("${path.module}/scripts/sshpiper.service.tmpl", merge(local.ssh_ban_policy, {
    ssh_authz_enforce = var.ssh_authz_enforce
  }))
  sshpiper_anon_service_unit = var.anon_door_addr == "" ? null : templatefile("${path.module}/scripts/sshpiper-anon.service.tmpl", merge(local.ssh_ban_policy, {
    anon_listen_host = split(":", var.anon_door_addr)[0]
    anon_listen_port = split(":", var.anon_door_addr)[1]
    anon_daemon_url  = var.anon_daemon_url
  }))
}
