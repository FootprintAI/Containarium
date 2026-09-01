# Threat-Detection Sentry Operator Guide

The threat-detection sentry is a background engine inside the daemon that
watches the eBPF flow/deny signals already collected by the network-policy
enforcer and raises typed **security findings** — mining-abuse egress,
cross-tenant fence breaches, and fence-probing deny bursts — without a
scan schedule or a separate process. It is detection-only: it observes and
alerts, it does not act.

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

## The three detection rules

| Rule | Severity | Fires when |
|------|----------|------------|
| Known-bad destination | HIGH | A flow's destination matches the embedded (versioned, mining-pools-first) or operator-added bad-destination list. |
| Cross-tenant flow | CRITICAL | A flow's source and destination resolve to containers in *different* tenants on the same backend — the continuous form of the one-shot isolation check. Never fires on an IP it can't attribute to a tenant. |
| Deny burst | MEDIUM | A tenant accumulates ≥`CONTAINARIUM_THREAT_DENY_BURST_N` (default 20) policy denies within `CONTAINARIUM_THREAT_DENY_BURST_WINDOW_MINUTES` (default 5) minutes. Both tunable per operator, without a daemon rebuild — set the env var and restart. |

A rule firing repeatedly for the same `(rule, tenant, subject)` dedupes
into one open finding with an updated count, rather than creating a new
row or re-alerting on every repeat.

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

## Known gaps

- **Two-org e2e coverage**: the fence-probe rules (cross-tenant flow,
  deny-burst) ship with an engine-level test using a faked tenant-IP
  resolver, not a real two-org Incus deployment — tracked in #1660.
- **Cloud aggregation**: the cloud control plane does not yet forward
  findings from connected backends — P0 pass-through is tracked in
  `Containarium-cloud#1412`; a rolled-up UI is a later phase.
