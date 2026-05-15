# Application OpenTelemetry collection — design

**Status:** Approved
**Last updated:** 2026-05-14
**Related:** [`internal/metrics/otel.go`](../internal/metrics/otel.go) (daemon-side metrics this design extends), [`docs/MULTI-POOL.md`](MULTI-POOL.md) (multi-VM aggregation pattern this builds on).

## Context

Today Containarium's daemon emits OTel metrics *about* containers (cgroup-level CPU/mem/disk/net via `internal/metrics/otel.go`, pushed to a co-located VictoriaMetrics container every 30s). It does not provide a path for the applications *inside* those containers to emit their own application-level OTel.

The gap: agents and humans deploying apps onto Containarium expect to instrument them — request count, request latency, queue depth, business metrics. Today the only options are (a) run their own collector inside their container, or (b) push directly to a public endpoint they provision themselves. Neither is acceptable for the "give my AI agent a Linux box and it Just Works" UX.

This doc designs a per-container, opt-in path for application-emitted OTel that lands in the same VictoriaMetrics instance the daemon already uses, so a single Grafana dashboard can correlate app metrics (e.g. `http.requests` from inside the container) with platform metrics (e.g. `container.cpu.usage` measured by the daemon).

## Goals / non-goals

**Goals**

- Apps inside containers can emit OTel metrics with **zero platform-specific code** — any vanilla OTel SDK call works, env vars do the routing.
- **Prometheus `/metrics` scrape compatibility** — legacy apps that expose `/metrics` instead of pushing OTLP get scraped by the collector and forwarded to VictoriaMetrics through the same pipeline. No second backend.
- App-emitted telemetry is a **per-container opt-in feature** — `containarium create alice --monitoring` enables it; the default is off. Tenants choose, operators don't get surprised.
- Per-container attribution is **enforced at the collector**, not trusted from the client (a misbehaving container can't claim `container.id=other-tenant`).
- Failure modes are bounded — a downed collector or a misbehaving app does not affect other tenants or the platform daemon.
- The flow extends cleanly across the `MoveContainer` migration shipped in #172.

**Non-goals (for v1)**

- **Tracing and logs — no receivers, no pipelines, no backends.** The collector config declares only `metrics` pipelines. Tempo / Loki / the trace+log OTLP receivers are all deferred to v2 (see "v2 TODO" below). Apps that emit traces via `OTEL_EXPORTER_OTLP_ENDPOINT` will get `404` from the collector — that's fine, the SDK buffers + drops without crashing the app.
- Operator-tunable per-tenant rate limits / quotas (the cardinality guard is the only protection in v1).
- Cross-VM metric query federation beyond what PeerPool already does for daemon metrics.
- Hosted "Containarium-managed" external endpoint — everything stays inside the VM.
- ~~A `ToggleMonitoring` RPC for live-flipping the flag on an existing container.~~ **Shipped 2026-05-15.** `containarium monitoring enable|disable <username>` (CLI) / `toggle_monitoring` (MCP) / `POST /v1/containers/{username}/monitoring` (REST). Stamps or unsets OTEL_* env vars and restarts the container.

## Architecture

Single-VM scope; cross-VM aggregation reuses the existing PeerPool path. Diagram:

```
┌──────────────────────────────── one Containarium VM ──────────────────────────────────┐
│                                                                                       │
│   incusbr0 (10.0.3.0/24)                                                              │
│                                                                                       │
│   ┌─────────────────────────┐                                                         │
│   │  alice-container         │   monitoring=true → daemon injects OTEL_* env vars     │
│   │  (LXC, user's app)       │                                                        │
│   │                          │   ① app calls SDK.Counter.Add(...)                     │
│   │  OTEL_EXPORTER_OTLP_     │   ② SDK batches in-process (10s default)               │
│   │    ENDPOINT=http://      │   ③ SDK POSTs OTLP/HTTP every batch tick               │
│   │    10.0.3.<col>:4318     │      → 10.0.3.<col>:4318                                │
│   │  OTEL_SERVICE_NAME=alice │                                                        │
│   └────────────┬─────────────┘                                                        │
│                │                                                                      │
│                │             ┌───────────────────────────────────────┐                │
│                └────────────▶│  containarium-core-otel-collector     │                │
│                              │  (new core LXC)                        │                │
│                              │  :4317 OTLP gRPC, :4318 OTLP HTTP      │                │
│   ┌────────────────────────┐ │                                        │                │
│   │ bob-container           │ │  receivers: otlp                       │                │
│   │ monitoring=false        │ │  processors:                           │                │
│   │ (no OTEL_* env vars,    │ │    - attributes/identity               │                │
│   │  SDK buffers + drops)   │ │      (rewrite container.id from        │                │
│   └────────────────────────┘ │       source IP, anti-spoofing)        │                │
│                              │    - transform                         │                │
│   ┌────────────────────────┐ │      (drop high-cardinality labels)    │                │
│   │ carol-container         │ │    - batch                             │                │
│   │ monitoring=true         │─┘  exporters: otlphttp → VM:8428         │                │
│   └────────────────────────┘                                          │                │
│                                                       │ ④ OTLP/HTTP   │                │
│                                                       ▼                                │
│                                   ┌────────────────────────────────┐                  │
│                                   │  containarium-core-             │                  │
│                                   │    victoriametrics              │                  │
│                                   │  (10.0.3.<vm-ip>:8428)          │                  │
│                                   │                                  │                  │
│                                   │  also receives daemon's OWN     │                  │
│                                   │  cgroup metrics — single TSDB.  │                  │
│                                   └────────────┬─────────────────────┘                  │
│                                                │ ⑤ PromQL                              │
│                                                ▼                                        │
│                                   ┌─────────────────────────────────┐                  │
│                                   │  containarium-core-grafana       │                  │
│                                   │  dashboards correlate app       │                  │
│                                   │  metrics + daemon-emitted       │                  │
│                                   │  cgroup metrics for same        │                  │
│                                   │  container.id label             │                  │
│                                   └─────────────────────────────────┘                  │
│                                                                                       │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

All hops are intra-bridge on `10.0.3.0/24` — no public exposure, no iptables redirects, no Caddy hop.

## Detailed design

### 1. The `--monitoring` per-container flag

The central design choice: app-emitted telemetry is **opt-in per container**, not a platform-wide default.

**Proto.** `CreateContainerRequest` gains:

```proto
// Enable application-emitted OpenTelemetry. When true, the daemon
// stamps the container with OTEL_EXPORTER_OTLP_ENDPOINT and related
// env vars pointing at the core OTel collector, so any OTel SDK
// inside the container ships telemetry to the platform's
// VictoriaMetrics without app-side configuration. Default false —
// off matches the "platform doesn't move data unless told to"
// principle and avoids surprise telemetry from prototype workloads.
bool monitoring = N;
```

**CLI / MCP.** `containarium create alice --monitoring` and `create_container(..., monitoring: true)`. Default off in both surfaces.

**Persistence.** A new `monitoring_enabled` boolean on whatever table tracks per-container settings today (likely `containers` or `apps`). Surfaced in `ListContainers` / `GetContainer` responses so operators can see at a glance which containers are emitting.

**Independence from daemon-emitted metrics.** This flag controls app-emitted OTel only. The daemon's cgroup-level metrics (CPU / mem / disk / net per container) continue for *every* container regardless — that's operator-side observability of platform health, not tenant-controlled app telemetry. Two different things, two different label namespaces (`container.*` from daemon vs `app.*` / whatever the app emits).

### 2. The collector container

**Binary choice.** OpenTelemetry Collector Contrib (`otelcol-contrib`). Vector is lighter but its OTLP ingestion is less canonical and the Rust ecosystem is unfamiliar to most operators of this stack. The contrib build's binary is ~80MB; plenty for the `e2-micro`-tier sentinel pattern.

**Container shape.** Same as the other `containarium-core-*` LXCs:

- Image: `ubuntu:24.04`
- Resources: 256MB RAM / 0.5 CPU / 2GB disk (revisit if collector becomes a bottleneck)
- IP: assigned by incusbr0 DHCP, **pinned via Incus's static-IP feature** so env-var injection has a stable target across VM restarts
- Restart policy: `unless-stopped`

**Config** (`/etc/otelcol-contrib/config.yaml`):

```yaml
receivers:
  otlp:
    protocols:
      http:        # :4318
      grpc:        # :4317

  # Prometheus scrape compatibility for legacy apps that expose
  # /metrics instead of pushing OTLP. The daemon writes the target
  # list (every monitoring=true container's :<scrape-port>/metrics
  # endpoint, populated from a per-container annotation) and the
  # collector reloads via filewatcher. The same anti-spoofing rule
  # applies: container.id is rewritten from the source IP, not
  # trusted from the metric labels. Off when the target list is
  # empty (no scrape-enabled containers).
  prometheus:
    config:
      scrape_configs:
        - job_name: containarium-apps
          file_sd_configs:
            - files: [/var/lib/containarium/prometheus_targets.json]

processors:
  # Anti-spoofing: regardless of what container.id the client claimed,
  # rewrite it from the source IP. iptables + bridge guarantee the
  # client can't fake source IP within incusbr0. Map source-IP →
  # container.id via a daemon-maintained file mounted into the
  # collector container (see §4).
  attributes/identity:
    actions:
      - key: container.id
        action: upsert
        from_attribute: "client.address"

  # Cardinality guard: cap labels per metric to prevent a misbehaving
  # app from blowing up VictoriaMetrics with per-request user_id
  # labels. Default drop-list; operator can extend via daemon flag.
  transform:
    metric_statements:
      - context: datapoint
        statements:
          - delete_matching_keys(attributes, "^request_id$|^trace_id$|^user_email$|^session_id$|^correlation_id$")

  batch:
    timeout: 5s
    send_batch_size: 1024

exporters:
  otlphttp:
    endpoint: http://10.0.3.<vm-static-ip>:8428/opentelemetry
    # Same VM instance that already receives daemon-emitted metrics.
    # No new backend dependency.

service:
  pipelines:
    metrics:
      receivers: [otlp, prometheus]
      processors: [attributes/identity, transform, batch]
      exporters: [otlphttp]
    # NO traces or logs pipelines in v1. Apps emitting OTLP traces
    # / logs to this endpoint will get 404 — SDK buffers and drops
    # without crashing the app. v2 will add the receivers + Tempo
    # / Loki exporters.
```

**Provisioning.** Add a new entry to the daemon's core-services bring-up (same place `containarium-core-victoriametrics` lives today). Same lifecycle as the existing core containers — created once at first `--app-hosting` startup, idempotent on re-run.

### 3. Env-var injection on `create_container`

**Variables set on every new container WITH `monitoring=true`:**

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://<collector-ip>:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_SERVICE_NAME=<username>
OTEL_RESOURCE_ATTRIBUTES=container.id=<container-name>,backend.id=<backend-id>
```

Containers created with `monitoring=false` (the default) get none of these. Any OTel SDK inside such a container will fall back to its built-in "no endpoint, buffer + drop with backoff" behavior — apps don't crash, they just don't ship metrics anywhere.

**Where in code.** `pkg/core/incus/client.go`'s container create path, alongside the existing `--podman` and other defaults. ~10 lines: a lookup of the collector container's static IP, four `incus config set environment.OTEL_*` calls.

**When.** At create time, gated on `req.Monitoring`. We do NOT re-inject on every restart — operators can override per-container by hand-editing the LXC's environment if they want a different endpoint. Surprise-overwriting an intentional operator override would be bad.

### 4. Source-IP → container.id mapping

The collector's `attributes/identity` processor needs to know which source IP corresponds to which container. The bridge guarantees the source IP is real (can't be spoofed by a hostile container); the mapping from IP → name is the daemon's responsibility.

**Approach: daemon writes a JSON file the collector reads.** The daemon maintains `/var/lib/containarium/container_ips.json` (`{"10.0.3.42": "alice-container", "10.0.3.43": "bob-container", ...}`) and updates it on every container create / delete / migrate. The collector container mounts that path read-only and the `attributes/identity` processor refreshes via filewatcher.

This is simpler than the alternative (collector polls daemon's `/v1/containers` over the REST API) because there's no auth dependency between the collector and the daemon — the collector just reads a file. Risk: file goes stale if daemon crashes between write and reality; acceptable for v1, monitored via the daemon's own health check.

**v1 implementation note (added during build-out):** the upstream OTel `attributes` processor does not actually support filewatched JSON lookups out of the box. v1 therefore ships in two stages:

- The collector's `attributes/identity` processor stamps `source.ip` from `client.address` — the anti-spoofing security boundary stays intact and unforgeable.
- The daemon still writes `/var/lib/containarium/container_ips.json` into the collector LXC on every lifecycle event, but the collector does not consume it yet.
- v2 will either add a small custom lookup processor or auto-regenerate the `transform` processor's OTTL statements (`set(attributes["container.id"], "alice") where attributes["source.ip"] == "10.0.3.42"`) and SIGHUP the collector. Both approaches use the JSON file v1 is already maintaining as the source of truth.

This keeps v1 functional (operators correlate via `source.ip` joined to the daemon's own cgroup-metric stream, which carries both name and IP) without inventing a fictional collector feature.

### 5. Cardinality guard defaults

The `transform` processor drops a hard-coded list of high-cardinality labels by default:

```
request_id, trace_id, user_email, session_id, correlation_id
```

These are the ones that most often blow up TSDBs in practice. Operators can extend the list via a daemon flag `--otel-drop-labels=a,b,c`. v2 could add per-tenant overrides if we find tenants legitimately wanting some of those.

## Failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| Collector LXC OOM / restart | App SDKs buffer ~10s of metrics, then drop with backoff. App processes not affected. | Restart policy `unless-stopped` + Grafana panel for collector availability. |
| App emits at 100k metrics/sec | Collector batches and back-pressures (slows OTLP `204` responses). Eventually drops. | `transform` cardinality guard limits damage; per-tenant rate limit deferred to v2. |
| Hostile container claims `container.id=admin-container` | `attributes/identity` processor overwrites from source IP. Spoof attempt is silently ignored (logged at debug). | The processor is the security boundary; its config is verified in CI to make sure the overwrite step is always present. |
| Daemon's `container_ips.json` is stale | Some metrics arrive with an unknown `container.id` label until next refresh. | Filewatch with debounce (1s); operator alert if the file's `mtime` is > 5min old. |
| Collector container IP changes after VM restart | All `monitoring=true` apps' env-var endpoint is now wrong. | Static IP via Incus DHCP reservation. Verified in v1 install script. |
| `MoveContainer`: adopt-side forgets to re-stamp env | App's metrics keep flowing to the source VM's collector (still reachable from the destination VM via VPC), then to the source's VM — wrong tenant attribution. | `AdoptMigratedContainer` test asserts env vars are re-stamped with destination collector IP when `monitoring_enabled=true`. |

## `MoveContainer` interaction

Pre-copy migration (#172) preserves the container's filesystem and identity but not the env vars (which live in the LXC's runtime config and are platform-injected). The `AdoptMigratedContainer` handler does:

1. Read the migrated container's `monitoring_enabled` from the daemon's container metadata (transferred as part of `AdoptMigratedContainerRequest`).
2. If `true`, look up the local collector container's IP.
3. Stamp the four `OTEL_*` env vars on the migrated LXC via `incus config set`.
4. Restart the LXC for env-var changes to take effect — already part of the adopt flow.

If `monitoring_enabled=false`, the adopt handler skips env-var injection entirely. The flag travels with the container; the env-var stamping is just the destination's collector-IP-specific binding.

Ping-pong migration (A → B → A) re-stamps with the current VM's collector IP each time. No accumulation, no leak.

## Test plan

- **Unit:** env-var injection logic gated on the `monitoring` flag — mockable via the existing container manager interface. Asserts presence/absence of the four env vars for both flag values.
- **Unit:** daemon's `container_ips.json` writer — table-driven for various lifecycle events (create, delete, rename, migrate-in, migrate-out).
- **Integration (smoke):** bring up a fresh demo cluster via terraform, run `containarium create alice --monitoring`, exec inside alice and `curl $OTEL_EXPORTER_OTLP_ENDPOINT/v1/metrics` with a hand-crafted OTLP payload, assert it lands in VictoriaMetrics via PromQL.
- **Integration (negative):** `containarium create bob` (no `--monitoring`), exec inside bob and verify `echo $OTEL_EXPORTER_OTLP_ENDPOINT` is empty; assert nothing shows up in VictoriaMetrics for `service.name=bob`.
- **Integration (cardinality):** emit a metric with 10k unique `user_email` values; verify the collector drops the label (not the metric).
- **Integration (spoof):** emit OTLP with `container.id=other-tenant`; verify the collector overwrites to the real source.
- **Integration (migration):** `MoveContainer` a `monitoring=true` container from VM1 → VM2; verify env vars now point at VM2's collector; verify metrics emitted post-migration land in VM2's VictoriaMetrics, not VM1's.

## Resolved decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | `--monitoring` defaults to **`false`** (per-container opt-in). Operators wanting blanket-enable can pass `--default-monitoring=true` to the daemon to flip the default. | "Platform doesn't move data unless told to." Avoids surprise telemetry from prototype workloads. |
| 2 | Collector container uses **Incus DHCP-assigned IP, pinned** via Incus's static-reservation feature. Verified in v1 install script. | Stable target for env-var injection across VM restarts; no manual IP allocation. |
| 3 | **Prometheus `/metrics` scrape compatibility is in v1.** The collector config declares a `prometheus` receiver that file-discovers targets from `/var/lib/containarium/prometheus_targets.json`. | Legacy apps that expose `/metrics` instead of pushing OTLP work without app-side changes. Adding the receiver is cheap. |
| 4 | **PII labels are dropped by default** at the cardinality-guard layer. Default drop-list: `request_id`, `trace_id`, `user_email`, `session_id`, `correlation_id`. Operators can extend or override via `--otel-drop-labels=...`. | Defensible defaults beat permissive defaults for tenant data flowing through shared infra. |
| 5 | **v1 ships metrics only — no trace/log pipelines, even as placeholders.** Empty pipeline scaffolding would still require explainer code paths in the collector. Cleaner to add the receivers + Tempo/Loki exporters together when v2 picks them up. | Smaller v1 surface; v2 doesn't inherit broken half-built pipelines. |

## v2 TODO

When a real user needs them, layer these on:

- **Traces pipeline** — add `otlp` traces receiver to the collector config; add Tempo container as a new core-services entry; add `otlphttp` traces exporter targeting Tempo. ~1 day.
- **Logs pipeline** — same shape: add `otlp` logs receiver; add Loki container; add `otlphttp` logs exporter. (Or use Vector/Fluent Bit for log shipping if Loki proves heavy.) ~1 day.
- **Per-tenant rate limits / quotas** — extend the cardinality guard with a `limit` processor keyed on `container.id`. Operators set per-tenant ingestion budgets. ~1 day.
- ~~**`ToggleMonitoring` RPC**~~ — **Shipped 2026-05-15.** See above.
- **Cross-VM Grafana data source federation** — query unified view across all peer VMs without each one needing its own dashboard URL. Reuses PeerPool. ~1-2 days.

These are tracked in the project task list; this doc gets a follow-up edit when any of them ship.

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **0. RFC accepted** | this doc + decisions on the 5 open questions | (you) |
| **1. `--monitoring` flag plumbing** | proto + CLI + MCP + metadata field + tests | ~½ day |
| **2. Collector container + provisioning** | new core-services entry, config baked in, idempotent install | ~1 day |
| **3. Env-var injection** | create + adopt path, daemon flag for collector endpoint override | ~½ day |
| **4. Source-IP attribution** | `container_ips.json` writer + collector filewatcher processor | ~½ day |
| **5. Cardinality guard** | default drop-list, operator flag | ~½ day |
| **6. Tests** | unit + integration as listed above | ~1 day |

**Total: ~4 days** for metrics-only with the per-container flag. Traces (Tempo container + new exporter) and logs (Loki + exporter) each add ~1 day if added later.

## History

| Date | Author | Change |
|---|---|---|
| 2026-05-14 | hsinhoyeh, drafted in chat | Initial draft. v1 design with per-container `--monitoring` opt-in, single-VM collector container, source-IP-based identity attribution, cardinality guard. Status: Draft. |
| 2026-05-14 | hsinhoyeh | Resolved all 5 open questions: monitoring defaults off, Incus-pinned static IP, Prometheus scrape in v1, PII drop-list default-on, traces/logs deferred to v2 (no placeholders). Status: Draft → Approved. |
| 2026-05-15 | hsinhoyeh | Implementation note in §4: v1 stamps `source.ip` (anti-spoofing boundary), still maintains `container_ips.json`; v2 will materialize `container.id` via a custom processor or regenerated OTTL. Avoids inventing a filewatched-attributes feature OTel doesn't ship. |
