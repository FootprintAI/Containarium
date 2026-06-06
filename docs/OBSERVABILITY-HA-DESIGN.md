# Observability HA: where the monitoring stack lives (decision note)

**Status:** decided · **Date:** 2026-06 · **Relates to:** #514 (sentinel
spot recovery), [SPOT-RECOVERY.md](SPOT-RECOVERY.md),
[SENTINEL-DESIGN.md](SENTINEL-DESIGN.md), [ALERTING-SETUP.md](ALERTING-SETUP.md)

## Context

The monitoring/alerting stack — VictoriaMetrics + vmalert + Alertmanager
+ Grafana — runs as an Incus container (`containarium-core-victoriametrics`,
`internal/server/core_services.go`) **on the backend spot VM.** Daemons push
OTLP metrics into it; vmalert evaluates rules; Alertmanager relays to a
webhook.

This means the alerting stack **dies with the spot it is monitoring.** The
exact moment you most want an alert — the backend got preempted — is the
moment the thing that would fire it is gone. The question that surfaced
during #514: *should we move the monitoring stack to the always-on
sentinel to fix this?*

## Decision

**No. Do not move the observability stack onto the sentinel.** Instead,
split by concern:

| Concern | Lives on | Why |
| --- | --- | --- |
| Backend container/system metrics, 30-day history, dashboards | **The backend** (status quo) | Needs CPU/RAM/disk the sentinel doesn't have; its data survives preemption on the persistent disk. |
| "Backend is up / down" — the one alert that must not depend on the backend | **The sentinel**, lightweight + outbound (webhook + `/metrics`) | The sentinel is the only always-on component; this signal is small and self-contained. |
| Fully-resilient observability (dashboards + historical alerting that survive a multi-hour outage) | **External / managed** (Grafana Cloud, or a small dedicated always-on monitor) | Survives backend loss without overloading the e2-micro. |

## Rationale

Three reasons moving the stack to the sentinel is the wrong lever:

1. **It does not fit.** The sentinel is an **e2-micro: 1 shared vCPU, 1 GB
   RAM, free-tier** (`terraform/.../sentinel_machine_type = "e2-micro"`).
   The monitoring container alone is provisioned **1 GB** — the entire RAM
   of the sentinel — before its own work (sshpiper + Caddy + the proxy
   data path) and before the Incus overhead to host a container at all.
   The backend terraform deliberately *rejects* shared-core machine types
   "because of Incus overhead"; the sentinel is intentionally too small to
   run containers. Hosting the stack would force upsizing the sentinel,
   defeating its purpose (cheap, always-on, free-tier).

2. **It contradicts the sentinel's role.** The architecture is "the
   sentinel stays a dumb gateway; aggregation lives in the daemon layer."
   Adding a time-series DB, a rule engine, and a dashboard server expands
   its footprint and attack surface in exactly the wrong direction.

3. **It does not actually solve the problem.**
   - **Data is not lost on preemption.** Spot preemption *stops* the VM;
     the data disk (pd-balanced, not auto-delete) **persists**, so
     VictoriaMetrics history survives and returns when the spot restarts.
     The gap is alerting *availability during* the outage, not durability.
   - **The metrics you'd want during an outage are gone anyway.** Container
     and system metrics originate *on the backend*; during a preemption the
     workloads are down, so there is nothing to collect except the
     sentinel's own up/down signal.
   - **You cannot split off just the evaluator.** `vmalert` has to *query*
     VictoriaMetrics, which is on the dead backend — moving the rule
     engine without its data source helps nothing. The fundamental issue
     is that the data source is on the thing that dies.

The real requirement is narrow: **the alert that says "the backend is down"
must be emitted by something that is not the backend.** That is a small,
self-contained signal — not the whole stack.

## What we built instead (#514 follow-up)

The always-on sentinel emits the up/down signal itself, depending on nothing
on the spot:

- **Webhook** (`--alert-webhook-url` / `$CONTAINARIUM_SENTINEL_ALERT_WEBHOOK`):
  POSTed the instant the spot is preempted and the instant it returns to
  proxy. Payload carries `preempted_total`, `recovered_total`, and the net
  `outstanding` (> 0 == currently down).
- **`/metrics`** (Prometheus text on the sentinel's always-on HTTP server):
  `sentinel_preempted_total`, `sentinel_recovered_total` (counters),
  `sentinel_state` (1 up / 0 down), `sentinel_outage_seconds` (gauges) —
  for an **external** scraper to alert on the net.

Alert rule for an external monitor:

```promql
sentinel_preempted_total - sentinel_recovered_total > 0   # spot currently down, unrecovered
# or, equivalently:
sentinel_state == 0                                        # for: 2m
```

## Consequences

- The on-spot stack remains the source of truth for *workload* observability
  (CPU/mem/container/network), and its history is durable across preemption.
- "Is the platform down" is covered by the sentinel signal above, which is
  the only piece that has to be outage-independent.
- The one thing neither covers is **dashboarded / historical alerting that
  stays live through a long backend outage.** The correct answer to that is
  **external/managed observability** that scrapes *both* the backend's
  metrics and the sentinel's `/metrics` — never the e2-micro. This is left
  as a future option, gated on whether the operational need (and the cost)
  justifies it.

## Non-goals

- Running Incus / a TSDB / Grafana on the sentinel.
- Making the sentinel a metrics *aggregator* for backend workloads (that
  stays in the daemon layer, pushed to VictoriaMetrics).
