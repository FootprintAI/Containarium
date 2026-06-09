# Egress fan-out detection (crawler abuse) — design

**Status:** Proposed
**Last updated:** 2026-06-09
**Related:** [`internal/traffic/collector.go`](../internal/traffic/collector.go) (the conntrack collector that already observes egress destinations), [`internal/metrics/otel.go`](../internal/metrics/otel.go) (the metric pipeline this emits through), [`docs/REQUEST-RATE-PLANE-DESIGN.md`](REQUEST-RATE-PLANE-DESIGN.md) (the inbound sibling plane), eBPF network policy (#315, the egress *enforcement* counterpart).

## Context

Hosting a crawler/scraper on behalf of a customer is prohibited. A crawler has
a distinctive network signature: it makes outbound connections to a large,
constantly-changing set of **distinct destinations**, where a normal app talks
to a handful (its database, an upstream API, a CDN). We want a signal that
surfaces that fan-out so abuse can be detected and acted on.

Unlike the inbound request-rate plane (which had no data source and needed one
built), the **egress data already exists**. The conntrack traffic collector
(`internal/traffic`) records every container egress connection with its
destination IP — it classifies a connection as `EGRESS` when the source IP is a
container (`collector.go`), persists connections on close (7-day retention), and
`GetConnectionSummary` already aggregates per-destination connection counts and
a `TopDestinations` list. What's missing is a **continuously-emitted detection
metric**: today the fan-out is only visible at query time, so nothing can alert
on it.

## The signal

Per container, per collection window:

- **`container_egress_distinct_destinations`** — count of unique destination IPs
  the container connected out to. The primary crawler tell: a sustained spike
  separates a fan-out crawler from a normal app.
- **`container_egress_connections`** — total egress connection count (secondary;
  high churn alongside high distinct-count strengthens the signal).

Both carry the `container.id` attribute (the `cloud_container_id` label) so they
join to a tenant exactly like the bytes plane (#550), plus `container.name` and
`backend.id`.

## Privacy posture — count the fan-out, don't index the targets

The metric is a **per-container aggregate**. We deliberately do **not** emit a
per-destination-IP series. That would:

1. **Explode cardinality** — destination IPs are unbounded label values; a single
   crawler would create thousands of series.
2. **Be a privacy / recon liability** — it would turn "every site a customer's
   box visits" into indexed, retained time-series.

The raw destinations remain available where they already are — the conntrack
`GetConnectionSummary` (`TopDestinations`) and the persisted store — which are
query-time, access-controlled surfaces, not metric labels. If a confirmed abuse
case needs the actual targets, that's the surface to use.

## Architecture

```
   tenant container ──outbound──▶ conntrack (already running)
                                    │  EGRESS conn: srcIP=container, dstIP=...
                                    ▼
                      internal/traffic.Collector
                        • snapshot of active connections
                        • EgressFanout(): per-container
                          { distinct dst IPs, egress conn count, container_id }
                                    │  (EgressFanoutFetcherAdapter)
                                    ▼
                      internal/metrics OTel collector (every tick)
                        container.egress.distinct_destinations{container_id,...}
                        container.egress.connections{container_id,...}
                                    │  OTLP push
                                    ▼
                              VictoriaMetrics ──▶ threshold/alert
                                    (sentinel alerting plane: webhook + /metrics)
```

### Components (this slice)

- **`internal/traffic/fanout.go`** — `aggregateEgress` (pure, unit-tested):
  folds egress connections into per-container `{DistinctDestinations,
  EgressConnections, ContainerID}`, sorted by name. `Collector.EgressFanout()`
  snapshots the live conntrack state, filters EGRESS, and aggregates. Returns
  nil when conntrack is unavailable (macOS).
- **`internal/traffic/cache.go`** — `LookupID` resolves container name →
  `cloud_container_id` so the metric joins to a tenant.
- **`internal/metrics/otel.go`** — the two `container.egress.*` instruments,
  `EgressFanoutFetcher` interface + `SetEgressFetcher`, and `RecordEgressFanout`,
  recorded each collection tick.
- **`internal/server/egress_fanout_adapter.go`** + `dual_server.go` wiring —
  bridges the traffic collector to the metrics collector when conntrack is
  available.

## What is buildable offline vs. needs a live box

**Offline, unit-tested (shipped in this slice):** the `aggregateEgress` fold —
distinct-destination counting, connection totals, blank-dst handling, container
-id stamping, stable ordering.

**Already live (no new source needed):** the conntrack collector runs on Linux
daemons today and produces the egress connections this reads. The only thing
that was missing is the metric, which this slice adds and wires end-to-end.

**Needs a live box to confirm:** the emitted series in VictoriaMetrics under
real egress, and tuning the alert threshold (what distinct-destination count,
over what window, separates a crawler from a busy-but-legitimate app) — that's a
deployment decision, not code.

## Detection & response

- **Detect:** threshold `container_egress_distinct_destinations` via the sentinel
  alerting plane that just shipped (webhook + `/metrics`), or a cloud-side rule.
  A static ceiling is the v1; a baseline-relative anomaly check is a follow-on.
- **Respond:** the eBPF egress allowlist (#315, deny-by-default) is the
  enforcement clamp once a crawler is confirmed — detection (this metric) and
  enforcement (network policy) compose.

## Caveats

- **IPs, not hostnames.** conntrack sees destination IPs. Many hosts behind one
  CDN IP undercount the fan-out; conversely, many distinct IPs is a strong
  signal. Good enough for a detection trigger, not a precise crawl census.
- **Linux-only.** conntrack monitoring is unavailable on macOS; the fetcher
  returns nil and the plane stays dark (no false readings).
- **Window aliasing.** The count is over the snapshot window; a slow crawler
  spread across windows shows a lower instantaneous distinct-count. The
  persisted store covers longer-horizon analysis.
