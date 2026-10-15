# Shared SSH upstream guard (#1138)

The sentinel Manager owns one private controller for the main and anonymous
listeners. The routing wrapper authorizes through the existing YAML/anonymous
child, reserves risk, then opens one bounded SSH setup. The trailing source-ban
plugin consumes typed backend-failure dispositions; invalid client credentials
and signatures still count. Established sessions do not consume setup capacity.

Both Terraform installation paths enable it. The module's metadata reconciler
installs the controller policy/drop-in before switching either listener. Upgrade
`containariumd` and the pinned sshpiperd v1.6.1 together before applying these
units. The existing audit observer, authorization, approval and source CIDR
exemptions remain in the chain. No public control API is added.

The module exposes `ssh_upstream_failure_budget` (2),
`ssh_upstream_risk_per_attempt` (1) and `ssh_upstream_window_seconds` (600).
These are backend jail-risk settings, separate from the sentinel's per-client
`ssh_ban_*` settings. The tested strict profile is `maxretry=3`, `findtime=600`,
`sshd[publickey=any]`, one matching rejection per admitted SSH setup. Inspect
effective backend filters, source IP and exemptions before choosing other values.
An arbitrary filter can count several records per setup; increase the risk cost
or reduce the budget accordingly. A TCP refusal has no sshd authentication record;
only a verified refusal refunds its reservation. Unknown setup failures retain it.
Pass-through password rejections also retain backend risk while still counting
as client failures; they do not declare an otherwise healthy backend down.

Backoff begins at one second, doubles to 30 seconds and adds up to 25% positive
jitter within that cap. One SSH-ready probe reopens a cooled backend. A trusted
Manager health recovery hint advances the probe deadline while preserving risk.
Once risk is exhausted, recovery waits for a safe unit to expire from the rolling
window. Repairing credentials or restarting a plugin cannot erase that history.

The controller reads strict protobuf JSON through `--ssh-upstream-policy` or
`CONTAINARIUM_SSH_UPSTREAM_POLICY`. The default socket is
`/run/containarium/ssh-upstream/control.sock`; durable state and its exclusive lock
live under `/var/lib/containarium/ssh-upstream/`. Keep the directory private and
preserve it across upgrades. On first installation or missing state, new upstream
setups wait a full configured window (10 minutes by default). Established sessions
continue; an existing backend ban is never automatically cleared. Corrupt state,
policy changes and control outages fail closed for new setups.

A policy change requires a planned maintenance window: stop both SSH listeners
and the controller, wait at least the previous setup timeout plus the longer of
the previous/new risk windows, retain the old checkpoint for diagnosis, then
install the new policy and restart. The fresh-state hold applies again. Do not
delete state during live traffic to work around a policy mismatch.

For deployed verification, record the commit, backend-visible source,
`fail2ban-client get sshd maxretry/findtime/bantime/ignoreip`, matching auth logs
and jail status. Drive both listeners through a multi-minute outage and recovery;
check aggregate dials, existing sessions and another healthy backend. Repeat with
rejected proxy keys: retain the budget even after keys are repaired. Exercise a
separate invalid client key/signature/password and confirm source enforcement.
The CI firewall proof runs in a fresh network namespace and verifies that a real
jail first blocks an authorized negative-control source, then leaves the guarded
sentinel unbanned. Its syslog bridge adds timestamps to real foreground sshd
messages; it does not synthesize authentication failures.

This change does not implement authentication-failure/ban audit shipping (#2419).
