# Threat-Detection Sentry Operator Guide

The threat-detection sentry is a background engine inside the daemon that
watches the eBPF flow/deny signals already collected by the network-policy
enforcer and raises typed **security findings** — mining-abuse egress,
cross-tenant fence breaches, and fence-probing deny bursts — without a
scan schedule or a separate process. Every rule raises a finding and
alerts. Only a HIGH mining-behavior finding can also act on its container:
the process responder applies the operator-set process policy, which is
`ALERT` (record and notify, touch nothing) unless an operator sets
`THROTTLE` or `FREEZE`. See [Process policy](#process-policy-what-a-mining-finding-does).

For the architecture and design rationale, see
[`docs/architecture/continuous-threat-detection.md`](architecture/continuous-threat-detection.md).
This guide is the operator-facing "how do I turn this on and use it" doc.

## Architecture

```
eBPF flow poll (15s) / deny events ──▶ NetworkPolicyEnforcer
                                          │  SetFlowHook / SetDenyHook
                                          ▼
                                    threatdetect.Engine
                                      • bad-destination rule   (HIGH)
                                      • cross-tenant-flow rule (CRITICAL)
                                      • deny-burst rule        (MEDIUM)
                                      • mining-behavior rule   (HIGH)
                                          │
                                          ▼
                                    FindingStore (Postgres)
                                      • events.Bus  (SubscribeEvents)
                                      • audit hash chain
                                      • WebhookNotifier ──▶ operator's webhook
                                          │
                                          ▼
                      containarium security sentry status / findings
                      MCP: security_sentry_status / list_security_sentry_findings
```

## Enabling the sentry

Set `CONTAINARIUM_THREAT_SENTRY=1` and restart the daemon. Off by default,
same opt-in convention as the platform's other security features.

Prerequisites:

- The eBPF network-policy object must be loaded
  (`CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` set) — the sentry runs in
  **observation mode**, so `CONTAINARIUM_NETWORK_POLICY_ENFORCE` does
  **not** need to be set. Detection works on a fleet that hasn't turned on
  enforcement yet.
- A working audit store (Postgres) — every finding rides the tamper-evident
  audit hash chain unconditionally, so no audit store means no sentry, not
  a degraded one.
- Postgres for `FindingStore` itself is optional but recommended: without
  it the sentry runs **DEGRADED**, backed by a bounded in-memory ring
  instead of persisted rows — findings still flow to the event bus, the
  audit chain, and the webhook, but they do not survive a daemon restart.

## The detection rules

| Rule | Severity | Fires when |
|------|----------|------------|
| Known-bad destination | HIGH | A flow's destination matches the embedded (versioned, mining-pools-first) or operator-added bad-destination list. |
| Cross-tenant flow | CRITICAL | A flow's source and destination resolve to containers in *different* tenants on the same backend — the continuous form of the one-shot isolation check. Never fires on an IP it can't attribute to a tenant. |
| Mining behavior | HIGH | A container's mean CPU over `window` (default 5 min) is at least `min(min_cores, min_fraction_of_limit × limits.cpu)` (defaults 1.5 cores and 0.75; a box with no CPU limit uses `min_cores` alone) **and** it holds a flow, at least `flow_min_age` (default 3 min) old and seen within the window, to a stratum port (default 3333, 4444, 5555, 7777, 14444, 14433) or to a listed bad destination on any port. Subject is the destination `ip:port`, so a second pool opens a second finding. Evidence: a CPU summary (mean, peak, window, samples) and the flow, with its first/last seen (anchored on the flow poll that reported it, since kernel flow stamps are monotonic) and what matched it (`port:<n>` or `bad-destination:<cidr>`). CPU samples come from the metrics collector's tick when one runs, otherwise from a standalone sampler in the daemon that reads each container's CPU counter every 30 s, so the rule does not need VictoriaMetrics. `containarium security sentry status` shows which source is active on its `cpu-sampler:` line. Thresholds are persisted in the daemon config store under `threatdetect.mining_behavior.thresholds` (protojson of `MiningBehaviorThresholds`; a zero field keeps its default) and are written with `containarium security process-policy set --rule mining-behavior` (see [Process policy](#process-policy-what-a-mining-finding-does)). |
| Deny burst | MEDIUM | A tenant accumulates ≥`CONTAINARIUM_THREAT_DENY_BURST_N` (default 20) policy denies within `CONTAINARIUM_THREAT_DENY_BURST_WINDOW_MINUTES` (default 5) minutes. Both tunable per operator, without a daemon rebuild — set the env var and restart. **Counts enforced drops only** by default: a would-deny from a tenant whose policy is only observed (`log_only`) is not counted, so enabling the sentry on an observation-only host does not raise "fence probing" findings for ordinary egress. Set `CONTAINARIUM_THREAT_DENY_BURST_COUNT_LOG_ONLY=1` to count those too. |

Two further finding types are not detection rules. They are raised by the
daemon itself and appear in the same findings list:

| Finding | Severity | Raised when |
|---------|----------|-------------|
| `SENTRY_UNAVAILABLE` | MEDIUM | The sentry is armed (`CONTAINARIUM_THREAT_SENTRY` set) but not running cleanly: status is `UNAVAILABLE` or `DEGRADED`, or any rule is unhealthy; it is also raised when status is `OK` but the `cpu-sampler:` line starts with `unavailable`, in which case its subject is `cpu-sampler unavailable`. The health loop only runs when a finding store exists, so it does not fire when the audit store (Postgres) is down. It is backend-level (no tenant or container), its subject is the status reason, and it resolves itself once status returns to `OK`. It is raised by a separate health loop, not a rule, because a rule cannot run when the engine is missing or broken. |
| `PROCESS_ACTION_EXPIRED` | MEDIUM | A throttle or freeze reached its TTL with no operator decision and was released automatically. Subject is the container name. |

A rule firing repeatedly for the same `(rule, tenant, subject)` dedupes
into one open finding with an updated count, rather than creating a new
row or re-alerting on every repeat.

### Soak first on an observation-only fleet

With `CONTAINARIUM_NETWORK_POLICY_ENFORCE` unset the enforcer logs every
flow that no allow-list covers as `deny ... log_only (not dropped)` and
nothing is dropped. Before enforcing, and before trusting deny-burst:

1. Run observation-only and review the would-deny volume per tenant in the
   daemon journal. Expect it to be large on a fleet with no curated
   allow-lists: one line per flow, so hundreds of lines per tenant per
   minute is possible, and journald growth of tens of MB per day on a busy
   host. `netbpf: perf ring lost N samples` means the event stream is
   incomplete at that volume.
2. Curate each tenant's allow-list until the would-deny volume reflects
   traffic you actually want blocked.
3. Only then enable enforcement. From that point the deny-burst rule counts
   the drops, and a burst is a real signal.

## Process policy: what a mining finding does

By default a finding only alerts. The process responder changes that for
HIGH `mining-behavior` findings only; no other rule's findings are acted
on. The action is chosen by the effective policy, resolved as a
per-container override, then the backend default, then the built-in
`ALERT` with a `10%` allowance and a 24 h TTL. The merge is per field, so
an override that sets only `action` still inherits the backend default's
allowance and TTL.

| Action | Effect on the container |
|--------|-------------------------|
| `alert` | Record the finding and notify. Nothing is done to the box. This is the default. |
| `throttle` | Record the box's current `limits.cpu` and `limits.cpu.allowance`, then set `limits.cpu.allowance` to the policy's throttle allowance, applied as a hard CPU quota: `N%` becomes `Nms/100ms`, and `Nms/Mms` is used as given. A box already limited below that quota keeps its tighter limit. |
| `freeze` | Pause the instance through Incus (cgroup freezer). Memory and disk are kept; no process runs until released. |

Every action is reversible and none destroys data. An applied action is
released by an operator, or by the TTL backstop, which also raises a
`PROCESS_ACTION_EXPIRED` finding so an unattended throttle never silently
becomes permanent. The finding's `response` records what was done and when.
On a backend whose finding store has no Postgres (`DEGRADED`), the
responder applies `ALERT` whatever the policy says, and status reports
"responses disabled".

```bash
containarium security process-policy get [--container <name>]
containarium security process-policy set --action throttle --throttle-allowance 10% --ttl 24h
containarium security process-policy set --action freeze --container <name>
containarium security process-policy set --container <name> --clear-override
containarium security process-policy set --rule mining-behavior --min-cores 2 --stratum-ports 3333,4444
containarium security process-policy release <container>
```

`--action` is `alert`, `throttle` or `freeze`; `--throttle-allowance` is
`N%` or `Nms/Mms`; omitted fields inherit. The mining-behavior thresholds
are backend-wide and cannot be combined with `--container`. `set` and
`release` are admin-only. Run `containarium security process-policy set
--help` for the full flag list. REST: `GET`/`PUT /v1/security/process-policy`
and `POST /v1/security/process-policy/release`.

MCP equivalents: `security_process_policy_get`,
`security_process_policy_set` and `security_process_policy_release`.

For the guardrail design and operating detail, see
[`docs/security/PROCESS-GUARDRAIL.md`](security/PROCESS-GUARDRAIL.md)
(added by PR #2716; the link resolves once that PR merges).

## Reading sentry status

```bash
containarium security sentry status
```

Reports one of four states:

| State | Meaning | Operator action |
|-------|---------|------------------|
| `DISABLED` | `CONTAINARIUM_THREAT_SENTRY` is unset — the engine was never constructed. | Set the env var and restart, if detection is wanted on this backend. |
| `UNAVAILABLE` | Enabled, but the eBPF object isn't loaded or the audit store is down. Nothing is being detected — never confused with "no findings." | Fix the missing prerequisite (load the eBPF object / restore Postgres connectivity), then restart. |
| `DEGRADED` | Running, but `FindingStore` has no Postgres connection — findings don't survive a restart. | Restore Postgres connectivity if persistence matters; otherwise no action needed. |
| `OK` | Running normally with Postgres-backed persistence. | None. |

`status` also lists every registered rule's health — a rule that
panicked shows `healthy=false` with its last error, while the engine and
every other rule keep running unaffected.

Add `--json` for the raw response. MCP equivalent: `security_sentry_status`
(no arguments).

## Triaging findings

```bash
containarium security findings [--severity --tenant --since --state --limit]
```

`findings` with no subcommand lists (an explicit `findings list` alias
runs the identical thing). Filters, all optional:

| Flag | Values |
|------|--------|
| `--severity` | `low`, `medium`, `high`, `critical` |
| `--tenant` | Tenant id — admin-only; a non-admin caller always sees their own tenant regardless of this flag. |
| `--since` | RFC3339 timestamp; only findings last seen at or after this time. |
| `--state` | `open`, `resolved` |
| `--limit` | Max rows (server default 50, cap 200). |

Resolve a finding once handled:

```bash
containarium security findings resolve <id>
```

MCP equivalents: `list_security_sentry_findings` (same filter arguments)
and `resolve_security_sentry_finding` (`id`).

> **Naming note:** this is distinct from the pre-existing
> `containarium security-findings <username>` (hyphenated) command, which
> lists ClamAV/pentest/ZAP scanner findings for one container — an
> unrelated, older surface. `security findings` (space-separated
> subcommand) is the sentry findings covered by this guide.

## Configuring webhook delivery

MEDIUM+ findings deliver asynchronously to the operator's configured
webhook — the same `alert_webhook_url` / `alert_webhook_secret`
configuration and HMAC-SHA256 signing scheme the existing alert-webhook
relay uses (see [ALERTING-SETUP.md](ALERTING-SETUP.md)), so there is
nothing new to configure if alerting is already set up. Delivery
deliberately bypasses the vmalert/alertmanager pipeline — a direct POST
works on any backend, including a minimal BYOC host with no
VictoriaMetrics container.

Every delivery attempt (success or failure) is recorded in the same
`alert.DeliveryStore` the existing relay uses — a dead or slow webhook
never blocks detection; delivery is downstream of persistence, not the
hot path.

## Managing the known-bad-destination list

```bash
containarium security bad-destinations list
containarium security bad-destinations add <cidr> [label]
containarium security bad-destinations remove <cidr>
```

The list is the embedded, versioned baseline (mining pools first) merged
with operator-added entries — additions take effect immediately, no
daemon rebuild required. Baseline entries cannot be removed; `remove`
only ever targets a previously operator-added entry.

MCP equivalents: `list_bad_destinations`, `add_bad_destination` (`cidr`,
`label`), `remove_bad_destination` (`cidr`).

## REST reference

Every CLI/MCP surface above is a thin wrapper over these RPCs
(`ThreatDetectionService`), reachable directly if needed:

| Method | Path |
|--------|------|
| `GET` | `/v1/security/sentry/status` |
| `GET` | `/v1/security/findings` |
| `POST` | `/v1/security/findings/{id}/resolve` |
| `GET` | `/v1/security/bad-destinations` |
| `POST` | `/v1/security/bad-destinations` |
| `DELETE` | `/v1/security/bad-destinations/{cidr}` |
| `GET` | `/v1/security/process-policy` |
| `PUT` | `/v1/security/process-policy` |
| `POST` | `/v1/security/process-policy/release` |

## Known gaps

- **Two-org e2e coverage**: the fence-probe rules (cross-tenant flow,
  deny-burst) ship with an engine-level test using a faked tenant-IP
  resolver, not a real two-org Incus deployment — tracked in #1660.
- **Cloud aggregation**: the cloud control plane does not yet forward
  findings from connected backends — P0 pass-through is tracked in
  `Containarium-cloud#1412`; a rolled-up UI is a later phase.
