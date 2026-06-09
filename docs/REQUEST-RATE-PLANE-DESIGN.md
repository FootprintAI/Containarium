# Request-rate metric plane — design

**Status:** Proposed
**Last updated:** 2026-06-09
**Related:** [`internal/metrics/otel.go`](../internal/metrics/otel.go) (the per-container metric collector this extends), [`internal/app/proxy.go`](../internal/app/proxy.go) (the Caddy edge that is the only request-volume source), [`docs/OTEL-COLLECTOR-DESIGN.md`](OTEL-COLLECTOR-DESIGN.md) (app-emitted OTel — the in-container alternative this complements).

## Context

The daemon already emits a per-container **bytes plane** — CPU, memory, disk, and
network rx/tx as cgroup-level gauges pushed to VictoriaMetrics every 30s
(`internal/metrics/otel.go`). When a box is a cloud-managed tenant, each
per-container series carries a `container.id` attribute (the
`cloud_container_id` label → VM `container_id` label), so the cloud's
`MetricsService` can join the series to a tenant and render history panels.

What's missing is the **request-rate plane**: `container_request_rate` —
HTTP requests per second hitting a tenant's container through the edge. The
metric name and a placeholder webui panel already exist on the cloud side
(`internal/metrics/names.go` `MetricRequestRate = "container_request_rate"`;
`RequestRatePanel`), and the cloud `QueryMetric` path scopes by
`{container_id="<uuid>"}` exactly as it does for the bytes plane. **The
contract is built; the source is not.** Nothing in the daemon emits
`container_request_rate` today, and nothing produces the data it would be
computed from.

This doc designs the source: where per-tenant request volume is observed,
how it's attributed to a container, and how it becomes a metric that lands in
VictoriaMetrics with the `container.id` label the cloud already joins on.

## The gap, precisely

Per-tenant HTTP request volume is visible in exactly one place: the **Caddy
edge reverse proxy** (`internal/app/proxy.go`). Every tenant container is
fronted by a route — `Match Host=<sub>.<base-domain>` → `reverse_proxy`
upstream `<containerIP>:<port>`. Caddy sees every request before it reaches
the container.

But Caddy is **not currently configured to emit any access record.** The
server config it builds is `{listen: [":80", ":443"], routes: [...]}` plus
the TLS app and (optionally) the PROXY listener wrappers — there is no `logs`
block and no metrics module. So there is no request-volume signal anywhere in
the system today. The request-rate plane cannot be "wired up" — its source
has to be created first.

## Goals / non-goals

**Goals**

- Emit `container_request_rate` (requests/sec) per tenant container, with a
  `container.id` attribute matching the bytes plane, so the existing cloud
  `QueryMetric` + `RequestRatePanel` render it with **zero cloud-side change**.
- Attribution is **platform-measured at the edge**, not trusted from the
  app — works whether or not the tenant instruments their own app.
- **Off by default**, opt-in via env flag — same posture as `--monitoring`
  (app OTel) and the eBPF network policy. Operators are not surprised by new
  edge logging or its disk cost.
- Bounded cardinality (one series per active tenant container) and bounded
  disk (rolled access logs).

**Non-goals (v1)**

- Per-route / per-path request rates, latency histograms, status-code
  breakdowns. v1 is a single rate per container. Latency and status planes are
  a clean follow-on once the source exists.
- Request rate for **TLS-passthrough (L4) routes** — those terminate no HTTP
  at the edge, so there is no request to count. Documented gap; such tenants
  show no request-rate series.
- Replacing app-emitted OTel. A tenant that instruments its own app
  (`OTEL-COLLECTOR-DESIGN.md`) gets richer in-app metrics; this plane is the
  platform-guaranteed floor that exists regardless.

## Candidate sources (and why the access log wins)

**1. Caddy native Prometheus metrics** (`caddy_http_requests_total`). Enabled
via the global `metrics` option, scraped from the admin endpoint. Labels are
`server`, `handler`, `code`, `method` — **there is no per-host or per-route
label**, so a count cannot be attributed to a specific tenant container. Usable
only for an edge-wide aggregate, not per-tenant. Rejected for v1.

**2. Caddy structured access log** (JSON). A per-server `logs` configuration
makes Caddy write one JSON object per request, including `request.host`. Host
→ tenant container is resolvable **in-process** from data the collector
already holds (route store gives host→upstream IP; the container list gives
IP→`cloud_container_id`). This is the chosen source: it is the only option
that yields per-tenant attribution without a custom Caddy module.

## Architecture

```
   client ──HTTP──▶ Caddy edge (srv0)
                      │  reverse_proxy  Host:<sub>.<base-domain> → <containerIP>:<port>
                      │
                      ├──▶ tenant container          (unchanged request path)
                      │
                      └──▶ JSON access log line       {"request":{"host":"<sub>.<base-domain>"},"status":200,...}
                                  │
                                  ▼
                       ┌────────────────────────────┐
                       │ request-rate aggregator     │   (new, in the daemon)
                       │  • tail JSON access log      │
                       │  • count per request.host    │
                       │  • host → container_id        │   (route store ∪ container labels)
                       │  • rate = Δcount / interval   │
                       └────────────┬─────────────────┘
                                    ▼  every collection tick (30s)
                       container_request_rate{container.id, container.name, backend.id}
                                    │
                                    ▼  OTLP push (existing collector pipeline)
                              VictoriaMetrics ──▶ cloud QueryMetric ──▶ RequestRatePanel
```

### A. Enable structured access logging (`internal/app/proxy.go`)

Add an access-log configuration to the Caddy edge, gated on an env flag
(`CONTAINARIUM_ACCESS_LOG=1`, default off):

- Define a named log in Caddy's `logging` app with a **file** writer to a
  known path (e.g. `<caddy-log-dir>/access.log`), a **json** encoder, and
  level `INFO` (access records only — no debug).
- Set **roll** options (`roll_size`, `roll_keep`, `roll_keep_days`) so disk is
  bounded regardless of traffic.
- Reference that log from the `srv0` server's `logs` field so request records
  flow to it.

This is the one piece that touches the existing Caddy-config builder. It must
be re-asserted by `EnsureBaseConfig` alongside the http app / TLS app / PROXY
wrappers, because the bundled core-caddy reverts to its stub Caddyfile on any
reload (the #400 self-heal path) — otherwise access logging silently stops
after the first caddy restart.

### B. The aggregator (new package, driven by the collector)

A goroutine, started only when the flag is on:

- **Tail** the JSON access log: open, seek to end, read appended lines;
  reopen on rotation (inode/size-truncation change) so a roll doesn't stall
  it. Only lines appended since the last tick are read — memory is bounded to
  the current window, not the whole file.
- Maintain a **per-host counter** for the current interval.
- On each collector tick (the existing 30s cadence), for each host:
  `rate = Δcount / interval_seconds`, resolve host → container, record the
  gauge, reset the window.

Parsing targets Caddy's **documented, stable** access-log schema
(`{"level","ts","logger","msg":"handled request","request":{"host",...},"status",...}`),
so the parser is unit-testable against captured sample lines without a live
edge — the same way the OTLP gateway (#361) is tested against the OTLP proto
without a live VictoriaMetrics.

### C. Host → container resolution

The collector already lists containers each tick with their `Labels` (incl.
`cloud_container_id`) and IPs, and `ProxyManager.ListRoutes()` returns
host→upstream `IP:port`. Join: `request.host` → upstream IP (route store) →
container (match by IP) → `cloud_container_id`. Cache the map, refresh per
tick. A host with no resolvable container (stale route, core service) is
counted but dropped before emit.

### D. The metric (`internal/metrics/otel.go`)

Add one instrument mirroring the bytes-plane gauges:

```go
c.containerRequestRate, _ = meter.Float64Gauge("container.request_rate",
    otelmetric.WithDescription("Container HTTP requests per second (edge-measured)"),
    otelmetric.WithUnit("1/s"))
```

Recorded with the same attribute set as the per-container bytes gauges —
`container.name`, `backend.id`, and (when present) `container.id` — so the VM
series is `container_request_rate{container_id="<uuid>",...}`, exactly what the
cloud `QueryMetric` already asks for. No cloud change.

> Naming: the OTel instrument name `container.request_rate` → VM
> `container_request_rate` (dots→underscores, no unit suffix) matches the
> cloud constant already shipped in `internal/metrics/names.go`. Confirm the
> mapping with a single live sample before declaring the plane done.

### E. Cloud side — already built

`MetricRequestRate`, the `QueryMetric` scoping, and `RequestRatePanel` are
shipped. Once the OSS metric flows with the `container_id` label, the panel
renders with no further work. The per-org cardinality cap in the OTLP gateway
(#361) already covers this series on the cloud ingest path.

## Cost & cardinality

- **Series:** one per active tenant container (`container_id` + `container_name`
  + `backend_id`). Bounded by container count, not request volume.
- **Disk:** bounded by the roll config; the flag stays off until an operator
  has sized it for a given edge.
- **CPU:** one JSON-decode per request line on the tail goroutine. For
  high-traffic edges, a sampling factor (count every Nth line × N) is the
  obvious lever if decode cost shows up — deferred until measured.

## What is buildable offline vs. what needs a live edge

**Offline, unit-tested (no live dependency):**

- The access-log parser (against captured Caddy JSON lines — documented schema).
- The per-host counter + rate computation over a window.
- The host→container resolver (given a route table + container list fixture).
- The new `container.request_rate` instrument and its attribute set.

**Requires a live edge (cannot be validated offline):**

- That Caddy actually writes the configured access log at the expected path /
  schema, survives a core-caddy stub revert, and rolls as configured.
- The end-to-end flow: real requests → log lines → gauge → VM series →
  `RequestRatePanel`.
- The instrument-name → VM-label mapping (one sample confirms it).
- Disk-usage behaviour on a high-traffic prod edge before enabling always-on.

## Live validation plan

1. On a lab edge, set `CONTAINARIUM_ACCESS_LOG=1`; `curl` a tenant host N
   times; confirm N JSON lines with the expected `request.host`.
2. Start the aggregator; confirm `container_request_rate{container_id=...}`
   appears in VictoriaMetrics with the right tenant id and a plausible rate.
3. Confirm the cloud `RequestRatePanel` renders the series.
4. Restart core-caddy; confirm `EnsureBaseConfig` re-asserts the log config and
   the series resumes.
5. Measure access-log disk growth under representative traffic before
   considering it for an always-on prod edge.

## Rollout / risk

- **Off by default.** `CONTAINARIUM_ACCESS_LOG=1` opt-in, like `--monitoring`
  and the eBPF enforce flag. No behaviour change for existing deployments.
- **TLS-passthrough (L4) routes** produce no HTTP access record — those tenants
  have no request-rate series. Documented, not silently zero.
- **gRPC routes** count each HTTP/2 request; a long-lived streaming RPC counts
  once at stream open, not per message. Documented so the panel isn't
  misread.
- **High-traffic prod edge:** gate behind the flag + roll config; size disk
  first. Sampling is the escape hatch if decode cost matters.

## Implementation slices

1. **Parser + aggregator + instrument** (offline, unit-tested) — the building
   block, no behaviour change (nothing calls it until the flag is on).
2. **Caddy access-log config in `proxy.go`** behind `CONTAINARIUM_ACCESS_LOG`,
   re-asserted by `EnsureBaseConfig`.
3. **Wire the aggregator into the collector** when the flag is on; record the
   gauge each tick.
4. **Live validation** per the plan above, then flip the cloud panel from
   placeholder to live.
