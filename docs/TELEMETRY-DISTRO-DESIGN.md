# Containarium telemetry distros (Python, Go) — design

**Status:** Approved
**Last updated:** 2026-05-28
**Related:**
- [`docs/OTEL-COLLECTOR-DESIGN.md`](OTEL-COLLECTOR-DESIGN.md) — the central collector this distro emits to (directly or via the sidecar).
- [`docs/OTEL-AGENT-RELAY-DESIGN.md`](OTEL-AGENT-RELAY-DESIGN.md) — the per-LXC OTel sidecar this distro pairs with when the app runs in docker-compose. **Read this first.**
- [`docs/PLATFORM-SIDECAR-DESIGN.md`](PLATFORM-SIDECAR-DESIGN.md) — the umbrella pattern for platform-published images.
- [`pkg/core/container/otel.go`](../pkg/core/container/otel.go) — the daemon-side env-var stamping these distros consume.

## Context

Containarium ships the *plumbing* for application telemetry: when an LXC
is created with `--monitoring=true`, the daemon stamps a fixed set of
standard OTel env vars on it (`OTEL_EXPORTER_OTLP_ENDPOINT`,
`OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SERVICE_NAME`, optionally
`OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer ...`), and either the
app reaches the central collector directly or — preferred for docker
stacks — through the per-LXC `otel-sidecar` over `localhost:4318`.

That plumbing is deliberately vendor-neutral: any conformant OTel SDK
discovers those env vars and Just Works (`docs/OTEL-COLLECTOR-DESIGN.md`
Goal #1). What it doesn't solve is the **app-side ceremony**: pick the
right SDK packages, write the init code, choose batch settings, register
auto-instrumentations, attach Containarium-specific resource attrs that
aren't already in `OTEL_RESOURCE_ATTRIBUTES`. A junior engineer or AI
agent deploying a new service has to read three OTel docs before they
can ship one metric.

The pattern other clouds settled on is the **distro**: a small,
opinionated wrapper that calls vanilla OTel `init()` with sane defaults
plus vendor-specific resource detection (AWS ADOT, Splunk Distribution
of OpenTelemetry, Honeycomb beeline, Datadog ddtrace, etc.). Distros
preserve the underlying SDK contract — anything an OTel API user can do
still works — they just remove the first-mile setup pain.

This doc designs the first two Containarium distros: Python (where most
agent-deployed apps live today, including `examples/helloworld-python/`)
and Go (where Containarium itself lives, so dogfooding closes the loop).

## Goals / non-goals

**Goals**

- **One-line init.** `from containarium_telemetry import init; init()`
  (Python) or `containariumotel.Init(ctx)` (Go) wires the OTel SDK with
  the env vars Containarium stamps. No `OTLPMetricExporter` imports, no
  manual `Resource.create(...)` calls in the app.
- **Zero-code instrumentation for Python**, via the same
  `opentelemetry-instrument` exec shim the upstream distro uses
  (`containarium-instrument python app.py` works without import-time
  changes).
- **Containarium-specific resource attrs.** Attach `container.id`,
  `backend.id`, `tenant.id`, `service.version` (from `SERVICE_VERSION`),
  and `containarium.distro={py|go}/<version>` for support-ability. The
  app keeps full authority over `service.name`, `service.namespace`,
  and any business attrs.
- **Sane defaults that match the central collector.** Same batch
  timeout (5s) / size (1024) as `sidecars/otel-sidecar/config.yaml`;
  `http/protobuf` protocol; bearer-aware header parsing.
- **Vanilla OTel underneath.** A user can still call any
  `opentelemetry-api` / `go.opentelemetry.io/otel` API after `Init()`.
  The distro is a starter, not an SDK.
- **Both LXC delivery shapes supported.** Whether the LXC runs the
  `otel-sidecar` (endpoint = `http://localhost:4318`) or talks to the
  central collector directly (endpoint = `http://<collector-ip>:4318`),
  the distro behaves the same — the env var decides.

**Non-goals (for v1)**

- **No traces or logs init.** The central collector is metrics-only in
  v1 (`docs/OTEL-COLLECTOR-DESIGN.md` decision #5). The distro
  registers a no-op tracer provider so SDK trace calls don't crash, but
  it does not configure trace export. v2 adds tracing init alongside
  the collector's Tempo pipeline.
- **No custom transport.** The distros use the stock `OTLPMetricExporter`
  / `otlpmetrichttp` exporter. No bespoke OTLP client.
- **No auto-discovery of frameworks the upstream community hasn't
  packaged.** Python distro depends on `opentelemetry-instrumentation-*`
  packages; Go has no auto-instrument equivalent so it stays
  middleware-only.
- **No proprietary metric semantics.** Default metrics follow
  OpenTelemetry semantic conventions
  (`http.server.request.duration`, etc.) — not Containarium-named.
  Switching off Containarium later means changing the distro, not
  rewriting dashboards.
- **No JS/Java distro this round.** Possible in a follow-up — same
  contract, same versioning, same release calendar — once Python +
  Go are live and the contract has stabilized in use.

## Architecture

```
┌─────────── one Containarium user LXC (--monitoring=true) ────────────┐
│                                                                      │
│   docker-compose stack                                               │
│                                                                      │
│   ┌────────────────────────────────┐    ┌─────────────────────────┐  │
│   │  payment-api (Python)          │    │  payment-api-otel       │  │
│   │                                │    │  (otel-sidecar:vX.Y.Z)  │  │
│   │  import containarium_telemetry │    │                         │  │
│   │  containarium_telemetry.init() │───▶│  receives OTLP at       │  │
│   │                                │    │   :4318 (shared netns)  │  │
│   │  ① reads env (set by Containarium │ │                         │  │
│   │     and compose interpolation):│    │  upserts container.id / │  │
│   │   OTEL_EXPORTER_OTLP_ENDPOINT  │    │   backend.id from env   │  │
│   │   OTEL_SERVICE_NAME            │    │                         │  │
│   │   OTEL_RESOURCE_ATTRIBUTES     │    │  forwards to central    │  │
│   │   CONTAINARIUM_CONTAINER_ID    │    │   collector LXC         │  │
│   │   CONTAINARIUM_BACKEND_ID      │    │                         │  │
│   │   CONTAINARIUM_TENANT_ID       │    └─────────────────────────┘  │
│   │   SERVICE_VERSION              │                                 │
│   │   OTEL_EXPORTER_OTLP_HEADERS   │      (or: direct-to-collector   │
│   │                                │       LXC for non-docker apps)  │
│   │  ② registers MeterProvider with│                                 │
│   │     batch=5s/1024,             │                                 │
│   │     OTLP/HTTP protobuf,        │                                 │
│   │     resource attrs merged.     │                                 │
│   │                                │                                 │
│   │  ③ auto-instruments Flask /    │                                 │
│   │     FastAPI / requests / etc.  │                                 │
│   │     if installed (Python).     │                                 │
│   └────────────────────────────────┘                                 │
└──────────────────────────────────────────────────────────────────────┘
```

The distro is **app-side library code only**. It never opens a network
socket of its own — it configures the OTel SDK, and the SDK does the
exporting. This keeps the failure-mode boundary at the SDK, where the
upstream OTel community already does the hard work.

## The Containarium distro contract

Every Containarium telemetry distro — Python today, Go today, Node/Java
later — satisfies the same contract:

1. **Public init returns a shutdown handle.** Idiomatic per language:
   - Python: `init() -> Shutdown` where `Shutdown` is callable with
     `.shutdown(timeout_s=5.0)`. Used by frameworks that own lifecycle
     (FastAPI `lifespan`, Django `apps.AppConfig.ready`).
   - Go: `Init(ctx) (shutdown func(context.Context) error, err error)`.
     Caller `defer shutdown(ctx)` in `main`.

2. **Reads env vars and **does not** override what the SDK already
   honors.** If the user pre-set `OTEL_EXPORTER_OTLP_ENDPOINT`, the
   distro doesn't second-guess it. The distro adds *defaults* (batch
   settings, protocol, resource attrs) — never overrides explicit user
   input. This preserves the "any vanilla OTel works" promise.

3. **Resource attribute precedence** (low to high — later wins):
   1. SDK defaults (`telemetry.sdk.*`).
   2. Standard OTel detectors (host, process, container).
   3. Containarium-stamped attrs synthesized from `CONTAINARIUM_*`
      env vars: `container.id`, `backend.id`, `service.namespace`
      (defaults to tenant), `service.version` (from `SERVICE_VERSION`).
   4. Distro stamp: `containarium.distro=py/<version>` or
      `go/<version>`. Never user-overridable — it's a support signal.
   5. `OTEL_RESOURCE_ATTRIBUTES` parsed by stock SDK.
   6. Anything the app sets via `init(extra_attrs=...)`.

   **`service.name` is not in this list** — the SDK already resolves it
   from `OTEL_SERVICE_NAME` env, then `service.name` in
   `OTEL_RESOURCE_ATTRIBUTES`, then the SDK default
   `unknown_service:<lang>`. The distro adds no opinion on top.

4. **Fails open.** If env discovery fails or the exporter can't be
   constructed, `init()` logs a warning at WARN and returns a no-op
   shutdown. The app starts. This is the inverse of the *sidecar*'s
   fail-closed posture: a sidecar that can't stamp identity must not
   forward; an app that can't ship telemetry must still serve traffic.

5. **No goroutines / threads beyond what the SDK starts.** The distro
   is pure setup code. Reload / re-init on env change is out of scope —
   the LXC restarts when monitoring is toggled, which means a fresh
   process anyway.

6. **Version is one number per Containarium release**, matching the
   sidecar (`docs/PLATFORM-SIDECAR-DESIGN.md` decision #4). PyPI
   `containarium-telemetry==0.20.0` and Go module
   `github.com/footprintai/containarium-telemetry-go v0.20.0` both
   track Containarium daemon `v0.20.0`. Operators inheriting a
   Containarium release inherit its distros — no separate compat matrix.

## `containarium-telemetry-python`

### Package, install, exec shim

- Distribution name: `containarium-telemetry` on PyPI.
- Import name: `containarium_telemetry`.
- Install:
  ```
  pip install 'containarium-telemetry[all]==0.20.0'
  ```
  Extras:
  - `[all]` — pulls every framework instrumentation the distro
    supports. Recommended for greenfield apps.
  - `[flask]`, `[fastapi]`, `[django]`, `[requests]`, `[httpx]`,
    `[sqlalchemy]`, `[asyncpg]`, `[psycopg]`, `[redis]` — narrow
    extras for image-size-sensitive deployments.
  - No extras (bare `pip install containarium-telemetry`) installs
    the SDK + Containarium init logic only, with no auto-instrumentation.
- Exec shim: `containarium-instrument python app.py`. Thin alias over
  the upstream `opentelemetry-instrument` entrypoint that pre-loads the
  distro's resource detector and instrumentor registrations. Zero-code
  path for apps that can't change their import order. The shim is
  **always installed** with the base package (decision D8) — it's a
  console-script entrypoint with no extra runtime cost.
- Dry-run: `containarium-instrument --dry-run python app.py` resolves
  the config, prints endpoint / resource attrs / bearer-redacted
  headers / enabled instrumentors, and exits 0 without launching the
  app. First-line debug tool for "why no metrics" (decision D12).

### Public API

```python
from containarium_telemetry import init, Shutdown

handle: Shutdown = init(
    # All optional. Sensible defaults read from env.
    service_name=None,         # default: $OTEL_SERVICE_NAME
    extra_attrs=None,          # dict[str, str] merged with highest precedence
    instrumentations="auto",   # "auto" | "off" | list[str] of instrumentation names
    metric_readers="default",  # "default" enables periodic OTLP/HTTP reader
    log_level="warning",       # distro's own warning/error logs (not app logs)
)

# Idiomatic with FastAPI / Starlette:
@app.on_event("shutdown")
def _flush_telemetry():
    handle.shutdown(timeout_s=5.0)
```

`init()` is idempotent: calling it twice in the same process logs at
DEBUG and returns the existing handle. This matters for app frameworks
that import the entrypoint module twice under reloaders.

### What `init()` actually does

1. Read env into a typed dataclass (`_DistroConfig`). The dataclass
   exists so tests can construct it directly without monkey-patching
   `os.environ`.
2. Construct a `Resource` by merging SDK detectors → Containarium
   attrs → distro stamp → `OTEL_RESOURCE_ATTRIBUTES` → caller's
   `extra_attrs`. Precedence per the contract.
3. Build the `OTLPMetricExporter`:
   - Endpoint from `OTEL_EXPORTER_OTLP_ENDPOINT` (raises if unset and
     no `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` either).
   - Protocol pinned to `http/protobuf` (the v1 collector and sidecar
     both speak this; gRPC support deferred until we find an app that
     needs it).
   - Headers parsed from `OTEL_EXPORTER_OTLP_HEADERS` — the SDK already
     does this; the distro just makes sure we don't double-parse.
4. Wrap in a `PeriodicExportingMetricReader(export_interval_ms=5_000,
   export_timeout_ms=10_000)`. Matches the sidecar's `batch` processor.
5. Install a `MeterProvider` globally.
6. Register a **no-op TracerProvider**. Apps using the trace API
   (`opentelemetry.trace.get_tracer(...).start_span(...)`) get spans
   that record nothing but don't crash. Once the v2 traces pipeline
   lands, this swaps to a real provider in a point release.
7. If `instrumentations="auto"`, iterate over every registered
   `opentelemetry.instrumentor` entrypoint from installed packages and
   call `.instrument()` once. Failures from individual instrumentors
   are logged at WARN and skipped — one broken integration doesn't
   abort init.

### Default instrumentations enabled with `[all]`

| Package | Instrumentation | Why |
|---|---|---|
| `flask` | HTTP server metrics + spans | Most common WSGI framework in tenant apps. |
| `fastapi` / `starlette` | HTTP server metrics + spans | Standard for modern Python services + agent code. |
| `django` | HTTP server metrics + spans | Plenty of legacy Django deployments. |
| `requests` | HTTP client metrics + spans | Outbound visibility. |
| `httpx` | HTTP client metrics + spans | Async-native; used by FastAPI ecosystem. |
| `sqlalchemy` | DB query duration | Common ORM. |
| `asyncpg` / `psycopg` | Postgres query duration | Most-deployed DB driver. |
| `redis` | Cache call duration | Caches show up everywhere. |
| `logging` | Trace-context injection only | No log shipping yet; this just makes future log correlation free. |

When traces+logs ship in v2, the same auto-instrumentors light up
traces/logs automatically because they already produce them — the
collector just starts accepting them.

### Resource-attribute synthesis

Stamped by the distro before the SDK's own `OTEL_RESOURCE_ATTRIBUTES`
parsing, so the SDK still wins for anything explicitly listed there:

| Key | Source | Notes |
|---|---|---|
| `container.id` | `$CONTAINARIUM_CONTAINER_ID` | Distro reads the split form for consistency with the sidecar. |
| `backend.id` | `$CONTAINARIUM_BACKEND_ID` | |
| `service.namespace` | `$CONTAINARIUM_TENANT_ID` | Insert-if-absent — matches the sidecar's behavior. |
| `service.version` | `$SERVICE_VERSION` | Insert-if-absent. |
| `containarium.distro` | `py/0.20.0` | Always — support signal, never overridable. |

The Python distro never reaches into the LXC's Incus config; it reads
env only. Compose interpolation handles the LXC→container env hop
identically to how the sidecar consumes it.

### Failure modes (Python-specific)

| Failure | Effect | Mitigation |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` unset | `init()` logs WARN, returns no-op handle. App runs without metrics. | Fail-open per contract. WARN is greppable. |
| User's `[all]` extras pull a conflicting transitive | One instrumentor fails `.instrument()` | Caught + WARN; init continues. |
| `opentelemetry-instrumentation-*` not installed despite `[all]` | Entrypoint missing → skipped silently | Test asserts `[all]` extras lock-file shape. |
| Collector returns 5xx | SDK retries per `PeriodicExportingMetricReader` semantics. | Inherits OTel behavior. |
| User calls `init()` from gunicorn pre-fork worker | Workers inherit MeterProvider; each gets its own exporter goroutine. | Documented; recommend init in `post_fork` hook for clean per-worker resource attrs. |

## `containarium-telemetry-go`

### Module, import

- Module path: `github.com/footprintai/containarium` (the main repo —
  decision D13).
- Import path:
  `github.com/footprintai/containarium/distros/go/containariumotel`.
- Versioning: shares the main module's `v0.20.0` tags. No separate
  module tagging — the distro travels with the daemon release, which
  is exactly the cadence we want (decision D10).

```bash
go get github.com/footprintai/containarium/distros/go/containariumotel@v0.20.0
```

Because the distro is in the daemon repo, **the daemon itself imports
it directly** for its own metric emission (the dogfood step in Phase 7
of the rollout). No sibling-repo round-trip, no `replace` directives.

### Public API

```go
import "github.com/footprintai/containarium-telemetry-go/containariumotel"

func main() {
    ctx := context.Background()
    shutdown, err := containariumotel.Init(ctx)
    if err != nil {
        // Init is fail-open, but Init may still return an error for
        // truly broken env (e.g. malformed bearer header). Treat as
        // log-and-continue, not log.Fatal.
        log.Printf("telemetry init: %v", err)
    }
    defer shutdown(ctx)

    // Optional: HTTP server middleware (no extra config needed).
    mux := http.NewServeMux()
    mux.Handle("/api", containariumotel.HTTPMiddleware(myAPIHandler))
}
```

Options pattern for things people legitimately customize:

```go
shutdown, err := containariumotel.Init(ctx,
    containariumotel.WithServiceName("payment-api"),  // override env
    containariumotel.WithExtraAttrs(map[string]string{"region": "us-west-1"}),
    containariumotel.WithMetricInterval(10 * time.Second),
)
```

### What `Init()` actually does

1. Build a `*resource.Resource` from
   `resource.New(ctx, resource.WithFromEnv(), resource.WithHost(),
   resource.WithProcess(), resource.WithContainer())` plus
   `resource.NewSchemaless(attribute.String("container.id", ...), ...)`
   for the Containarium attrs and the `containarium.distro=go/<ver>`
   stamp. Precedence per the contract — Containarium attrs *before*
   `WithFromEnv` so that `OTEL_RESOURCE_ATTRIBUTES` overrides cleanly.
2. Construct `otlpmetrichttp.New(...)` with the endpoint from env,
   `WithCompression(otlpmetrichttp.GzipCompression)`, and
   `WithHeaders(...)` parsed from `OTEL_EXPORTER_OTLP_HEADERS`.
3. Wrap in a `metric.NewPeriodicReader(exp,
   metric.WithInterval(5*time.Second), metric.WithTimeout(10*time.Second))`.
4. Build `metric.NewMeterProvider(metric.WithResource(res),
   metric.WithReader(reader))`. Install via `otel.SetMeterProvider`.
5. Register a no-op `noop.NewTracerProvider()` globally for the same
   reason as Python: `otel.Tracer(...).Start(...)` calls don't crash
   pre-v2.
6. Return a shutdown func that calls `MeterProvider.Shutdown(ctx)` and
   logs WARN if it errors. Idempotent on repeat calls.

### HTTP middleware

Vanilla OTel's `otelhttp.NewHandler(...)` already provides solid
HTTP-server instrumentation. The distro re-exports it under a stable
name with Containarium-flavored defaults applied:

```go
func HTTPMiddleware(next http.Handler, opts ...otelhttp.Option) http.Handler {
    defaults := []otelhttp.Option{
        otelhttp.WithSpanNameFormatter(spanNameFromRoute),
        otelhttp.WithMessageEvents(otelhttp.ReadEvents, otelhttp.WriteEvents),
        otelhttp.WithMeterProvider(otel.GetMeterProvider()),
        otelhttp.WithTracerProvider(otel.GetTracerProvider()),
    }
    return otelhttp.NewHandler(next, "containarium-http-server",
        append(defaults, opts...)...)
}
```

The point of re-exporting is discovery — a Go dev grepping for
`containariumotel.` finds the middleware without having to know about
`go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp`.

### gRPC middleware (sub-package)

Per decision D11, gRPC instrumentation ships as a separate importable
sub-package — `github.com/footprintai/containarium/distros/go/containariumotel/grpc`
— so the gRPC transitive dependency only lands in apps that import it:

```go
import containariumgrpc "github.com/footprintai/containarium/distros/go/containariumotel/grpc"

s := grpc.NewServer(
    grpc.UnaryInterceptor(containariumgrpc.UnaryServerInterceptor()),
    grpc.StreamInterceptor(containariumgrpc.StreamServerInterceptor()),
)
```

Same shape on the client side. These are thin wrappers over
`otelgrpc.*Interceptor()` that apply the distro's defaults
(`MeterProvider` / `TracerProvider` from the global state set up by
`Init`).

### Dry-run / config resolver

```go
// Print resolved config to any io.Writer and continue, OR exit early
// for debug. Bearer header is redacted to "Bearer ***".
containariumotel.PrintConfig(ctx, os.Stdout)
```

`PrintConfig` does no network I/O — it just resolves env vars and
emits the same fields the Python `--dry-run` mode prints. Pair with
a `-print-telemetry-config` CLI flag in dogfood services.

### What we don't provide in Go

- **No `database/sql` wrapper.** Upstream `otelsql` is the well-trodden
  path; documenting it is enough.
- **No init from main()-by-side-effect.** Go doesn't have
  `opentelemetry-instrument`-style monkey-patching; explicit `Init` call
  is idiomatic and we don't reinvent it.

### Resource-attribute synthesis

Identical to Python — same keys, same sources, same precedence — just
constructed via the Go SDK's `resource.Resource` API. The
`containarium.distro` stamp reads `go/<module-version>` where the
version is baked at build time via a `//go:embed VERSION` file.

### Failure modes (Go-specific)

| Failure | Effect | Mitigation |
|---|---|---|
| Endpoint env unset | `Init` returns nil shutdown + `ErrNoEndpoint`. Caller decides; default pattern is log-and-continue. | App still runs. |
| Bearer header malformed | `Init` returns an error from the OTLP exporter constructor. | Sentinel `ErrBadHeaders` so callers can branch. |
| `shutdown` called twice | Second call is a no-op. | `sync.Once`. |
| Long-running app, collector restarts | OTel exporter handles retry/backoff. | Inherited from SDK. |
| App forks subprocesses that try to re-`Init` | Each subprocess gets its own exporter goroutine — correct but wasteful. | Documented; recommend a single init in PID 1. |

## Resource-attribute precedence (shared reference)

The full precedence table for both distros, low to high:

| # | Source | Wins over | Why |
|---|---|---|---|
| 1 | SDK defaults | — | Baseline. |
| 2 | OTel host/process/container detectors | #1 | Standard semantic-convention attrs. |
| 3 | Containarium `CONTAINARIUM_*` env → resource | #1, #2 | Platform identity. Insert-if-absent for `service.namespace` / `service.version`. |
| 4 | `containarium.distro` stamp | all of above | Support signal, never user-overridable. |
| 5 | `OTEL_RESOURCE_ATTRIBUTES` env (SDK parses) | #1–#4 except `containarium.distro` | User's deliberate env-level overrides. |
| 6 | Caller's `extra_attrs` (Python) / `WithExtraAttrs` (Go) | #1–#5 except `containarium.distro` | Programmatic overrides at init site. |

`containarium.distro` is the only attribute the distro defends — it's
how support can quickly correlate a misbehaving metric stream with
"which distro version did this app ship with?"

## Cross-cutting failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| App in `--monitoring=false` LXC imports the distro | `init()` finds no `OTEL_EXPORTER_OTLP_ENDPOINT`; logs WARN; returns no-op handle. App runs. | Fail-open per contract. |
| Sidecar in compose, but app forgot `network_mode: "service:<sidecar>"` | App emits to `localhost:4318` which nothing listens on. SDK buffers + drops with backoff. | Documented in `OTEL-AGENT-RELAY-DESIGN.md` failure modes. Distro can't detect this — same problem any OTel app has. |
| Distro version skew across services in one LXC | Two compose services with `containarium-telemetry==0.19.0` and `==0.20.0` co-exist. Resource attrs may differ in newly-added keys. | OTLP wire is stable; collector tolerates. Documented; recommend `==<containarium-release>` pinning. |
| User explicitly imports vanilla OTel SDK alongside the distro | Whichever calls `set_meter_provider` last wins. | Distro's idempotent-init guard; documented precedence. |
| Bearer rotation (`OTEL_EXPORTER_OTLP_HEADERS` changes) | App must restart to pick up the new header. | Documented limitation — distro is one-shot init. |

## Resolved decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Two distros in v1 (Python, Go).** Node/Java deferred. | Python covers the agent-deployed app surface; Go dogfoods Containarium itself. Adding more languages later doesn't change the contract — they slot in. |
| D2 | **One PyPI package + one Go module per language**, not split per framework. Per-framework extras handle image size for Python; Go has no equivalent footprint cost. | Discoverability beats granularity here. One name to remember. |
| D3 | **`http/protobuf` only**, no gRPC exporter in v1. | The central collector and sidecar both speak HTTP/protobuf. gRPC adds dependencies (httpx for Python's grpc package, etc.) for no win until an app actually needs it. |
| D4 | **No-op tracer provider registered by default.** | App code using `tracer.start_span(...)` shouldn't crash because the platform hasn't shipped traces yet. Easy upgrade in v2. |
| D5 | **Distro version tracks Containarium release version**, mirroring the sidecar. | Single number for daemon + sidecars + distros. Operators upgrade one thing. |
| D6 | **Fail-open in the distro, fail-closed in the sidecar.** | App availability beats telemetry completeness at the app boundary. Identity-stamping integrity beats forwarding-availability at the sidecar boundary. Two different concerns, two different defaults. |
| D7 | **`containarium.distro` is the only stamped attribute the distro defends from override.** Everything else, user wins. | Support signal worth protecting; everything else respects user intent per the OTel philosophy. |
| D8 | **`containarium-instrument` exec shim is always installed** with the base `pip install containarium-telemetry`, not gated behind an `[exec]` extra. | Tiny console-script entrypoint; gating it would make the zero-code path invisible to users who don't read the README. |
| D9 | **No git-SHA fallback for `service.version`.** Only `$SERVICE_VERSION` is honored; absent if unset. | Inside docker, `.git` is almost never shipped. Detection would succeed in dev and silently fail in prod — worse than honest absence. |
| D10 | **`init()` is always fail-open.** No `strict=True` flag, no env-var-keyed strict mode. | One behavior to remember: distro never blocks app startup. Operators who want strict can wrap `init()` in 3 lines themselves. |
| D11 | **Go gRPC instrumentation ships as a separate sub-package** (`containariumotel/grpc`), not folded into the base distro. | Keeps the gRPC transitive out of the main module for HTTP-only users; matches the symmetry with HTTP middleware for users who want it. |
| D12 | **Dry-run / config-resolver mode in both distros, in v1.** Python: `containarium-instrument --dry-run python app.py`. Go: `containariumotel.PrintConfig(ctx, w)` helper. | First-line debug tool for "why aren't metrics flowing." ~½-day each — pays for itself the first real incident. |
| D13 | **Distros live as sub-directories of the main `Containarium` repo** (`distros/py/`, `distros/go/`), mirroring how `sidecars/otel-sidecar/` is laid out today. **Not** sibling repos. | Atomic PRs across daemon env-stamping and distro consumption; consistent with the project's existing layout pattern for platform components. Go module is the daemon module — daemon imports the distro directly for dogfood with no module-graph friction. Python publishing workflow lives in the daemon repo's CI alongside the GHCR sidecar workflow. |

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **0. RFC accepted** | This doc + open-question resolution | (you) |
| **1. Python distro scaffold** | New `distros/py/` directory in the main repo: package layout (`containarium_telemetry/`), `init()` with env discovery + MeterProvider, OTLP exporter, fail-open behavior, unit tests on the config dataclass and resource composition. | ~1 day |
| **2. Python auto-instrument extras + dry-run** | `[all]` extras_require, exec shim wired through `opentelemetry-instrument` entrypoints (always installed per D8), `--dry-run` config printer (D12), integration test with Flask + FastAPI sample apps. | ~1 day |
| **3. Python publish** | PyPI release workflow under `.github/workflows/distros-py-release.yml`, gated on Containarium release tags. pkg metadata + classifiers. | ~½ day |
| **4. Go distro scaffold** | New `distros/go/containariumotel/` package under the main module: `Init` with options pattern, resource composition, OTLP/HTTP exporter, shutdown, `PrintConfig` (D12), unit tests. No new module — shares the daemon's go.mod (D13). | ~1 day |
| **5. Go HTTP middleware + gRPC sub-package** | `otelhttp` re-export with Containarium defaults under `containariumotel.HTTPMiddleware`. Separate `containariumotel/grpc` sub-package for `otelgrpc` interceptors (D11). | ~½ day |
| **6. Go release surface** | Version stamp baked at build via `//go:embed VERSION`. Smoke test that `go get .../distros/go/containariumotel@v0.20.0` resolves cleanly from outside the repo. | ~½ day |
| **7. Dogfood** | Replace `internal/metrics/otel.go`'s ad-hoc init with `containariumotel.Init()`. Direct import path within the same module — no `replace` directive. Validates the contract end-to-end against our own daemon. | ~1 day |
| **8. Re-deploy `examples/helloworld-python`** | With `containarium-telemetry` and a 2-line init. Verify metrics land in Grafana via PromQL. Lives as the docs/quickstart sample. | ~½ day |
| **9. Sample Go service** | New `examples/helloworld-go/` with the Go distro. Symmetric with the Python example. | ~½ day |

**Total: ~6 days OSS** for both distros end-to-end through dogfood. Cuts
roughly in half if Python and Go are built by different people in
parallel.

## History

| Date | Author | Change |
|---|---|---|
| 2026-05-28 | hsinhoyeh, drafted with Claude | Initial draft. Two-distro v1 (Python, Go) over the existing env-var-stamping plumbing. Shared contract, per-language sections, 7 resolved decisions, 6 open questions. Status: Draft. |
| 2026-05-28 | hsinhoyeh | Resolved all 6 open questions in one pass: exec shim always-installed (D8); no git-SHA fallback (D9); fail-open is the only mode (D10); Go gRPC ships as sub-package (D11); dry-run config printer in both distros (D12); distros live in main repo as `distros/py/` and `distros/go/` (D13). Rolled the layout decision into the phased rollout. Status: Draft → Approved. |
