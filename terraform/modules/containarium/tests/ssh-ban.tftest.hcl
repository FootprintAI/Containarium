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

# The text after the last ssh-ban-plugin mention is that plugin's own flags
# (it is the final plugin in each chain).
run "audit_records_off_by_default" {
  command = plan
  assert {
    condition     = alltrue([for unit in [local.sshpiper_service_unit, local.sshpiper_anon_service_unit] : !strcontains(element(split("ssh-ban-plugin", unit), length(split("ssh-ban-plugin", unit)) - 1), "--records-file")])
    error_message = "Without ssh_ban_audit_records the ban plugin must not be given --records-file (an older binary rejects the flag)."
  }
}

run "audit_records_on" {
  command = plan
  variables { ssh_ban_audit_records = true }
  assert {
    condition     = alltrue([for unit in [local.sshpiper_service_unit, local.sshpiper_anon_service_unit] : strcontains(element(split("ssh-ban-plugin", unit), length(split("ssh-ban-plugin", unit)) - 1), "--records-file /var/log/containarium/ssh-sessions.jsonl")])
    error_message = "With ssh_ban_audit_records both listeners' ban plugins must write to the shared session records file."
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

run "ssh_authz_audit_only_by_default" {
  command = plan
  assert {
    condition     = strcontains(local.sshpiper_service_unit, "ssh-authz-plugin") && !strcontains(local.sshpiper_service_unit, "--ssh-authz-enforce")
    error_message = "The tenant listener must stay audit-only unless enforcement is requested."
  }
}

run "ssh_authz_enforce" {
  command = plan
  variables { ssh_authz_enforce = true }
  assert {
    condition     = strcontains(local.sshpiper_service_unit, "--ssh-authz-enforce \\\n  --records-file /var/log/containarium/ssh-sessions.jsonl \\\n  -- \\\n  /usr/local/bin/containarium sentinel ssh-session-plugin")
    error_message = "Enforcement must be passed to ssh-authz-plugin, with its denied-record sink, before the session plugin."
  }
  assert {
    condition     = strcontains(local.sshpiper_service_unit, "ssh-authz-plugin \\\n  --ssh-authz-grace 5m \\\n  --ssh-authz-timeout 3s \\\n  --sshpiper-config /etc/sshpiper/config.yaml \\\n  --ssh-authz-enforce")
    error_message = "Enforcement must give ssh-authz-plugin the routing config yaml reads."
  }
}
