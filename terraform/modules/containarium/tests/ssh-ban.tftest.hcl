variables {
  project_id      = "ssh-ban-test"
  anon_door_addr  = "127.0.0.1:2223"
  anon_daemon_url = "https://daemon.example.test"
}

run "defaults" {
  command = plan
  assert {
    condition     = alltrue([for unit in [local.sshpiper_service_unit, local.sshpiper_anon_service_unit] : strcontains(unit, "ssh-ban-plugin") && strcontains(unit, "--max-failures 100") && strcontains(unit, "--ban-duration 300s")])
    error_message = "Both listeners must invoke the inspectable plugin at the existing policy defaults."
  }
}

run "custom_policy" {
  command = plan
  variables {
    ssh_ban_max_failures     = 240
    ssh_ban_duration_seconds = 45
    ssh_ban_ignore_cidrs     = ["192.0.2.4/32", "2001:db8::/48"]
  }
  assert {
    condition     = alltrue([for unit in [local.sshpiper_service_unit, local.sshpiper_anon_service_unit] : strcontains(unit, "--max-failures 240") && strcontains(unit, "--ban-duration 45s") && strcontains(unit, "--ignore-ip 192.0.2.4/32") && strcontains(unit, "--ignore-ip 2001:db8::/48")])
    error_message = "Both listeners must receive exactly the configured policy and exemptions."
  }
}

run "invalid_threshold" {
  command = plan
  variables { ssh_ban_max_failures = 0 }
  expect_failures = [var.ssh_ban_max_failures]
}
run "fractional_duration" {
  command = plan
  variables { ssh_ban_duration_seconds = 0.5 }
  expect_failures = [var.ssh_ban_duration_seconds]
}
run "invalid_prefix" {
  command = plan
  variables { ssh_ban_ignore_cidrs = ["192.0.2.4/32 --control-socket=/tmp/evil"] }
  expect_failures = [var.ssh_ban_ignore_cidrs]
}
