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
or reduce the budget accordingly. A pure TCP connect failure, including a timeout,
has no sshd authentication record and refunds its reservation. Unknown post-dial
setup failures retain it.
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
Alert on `sentinel_ssh_upstream_faulted == 1`. Controller startup failures leave
HTTP/HTTPS, health and sync running; new guarded SSH setups stay closed. The
Manager retries startup or the same in-memory durable write every five seconds.
Repair storage without changing the policy/checkpoint or lock ownership. A
successful sync clears a transient fault without deleting pending risk; a corrupt
or incompatible checkpoint still needs the maintenance procedure. Replacing the
lock or closing the owner cannot be recovered by a write retry.

Both SSH units follow the sentinel with After/BindsTo/PartOf, and the sentinel's
ExecStartPost starts them again after daemon recovery. An already authenticated
SSH session survives a completion-RPC outage; new setups remain fail closed.
A full daemon restart stops both listener units and their sessions, then starts
the units again; it is distinct from an in-process guard storage fault.
Use `systemctl status containarium-sentinel sshpiper sshpiper-anon` after upgrade
and verify listener recovery by restarting the daemon in a maintenance window.
Initial rollout still imposes the ten-minute hold and requires an explicit
operator go/no-go decision; neither CI nor this runbook authorizes a rollout.

A metadata policy change is staged as `policy.pending.json`; reconciliation
preserves the active file and does not restart a running sentinel. A policy
change requires a planned maintenance window: stop both SSH listeners and the
controller, then wait at least the previous setup timeout plus the longer of the
previous/new risk windows. Move the old checkpoint away from the configured
`StatePath` to a diagnostic backup (at defaults, archive
`/var/lib/containarium/ssh-upstream/risk.json` as a timestamped sibling). Preserve
the lock file. The active checkpoint path must be absent before starting the
controller with the new policy; leaving the incompatible checkpoint there makes
`New` reject its old policy hash. Promote the pending policy to `policy.json`,
then restart the controller and listeners. The controller creates a compatible
checkpoint and applies the full fresh-state hold again. Do not delete state
during live traffic to work around a policy mismatch.

The GCE boot installer follows the same staging/rollback rule. Anonymous box
names no longer permanently union reused IPs; physical endpoint risk stays until
its jail window drains. Endpoint aliases are pruned only after an idle period of
max(window, max delay) plus setup timeout as well as complete risk drain;
active retries preserve backoff. The metadata cap
per normalized source is min(64, one quarter of global capacity), at least one,
shared across listeners, so one idle source cannot fill the default global table.

Known limitation under review: pinned sshpiperd may open the upstream during an
unsigned public-key probe. If the client abandons it before PipeStart, its
post-dial outcome is uncertain and retains risk. Two such probes can exhaust the
default backend budget even without possession of the client's private key.
The real regression characterizes this; it does not claim prevention. Safely
refunding it requires a typed backend-ready result absent from the current
plugin API. Maintainers must weigh this with the fail-closed rollout decision.

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
