# helloworld-go

Tiny Go HTTP server demonstrating the `containariumotel` distro.

`main.go` shows the canonical three-piece wiring:

- `containariumotel.Init(ctx)` — env-driven SDK init (fail-open).
- `containariumotel.HTTPMiddleware(mux)` — auto-instrumented HTTP server metrics.
- `meter.Int64Counter("helloworld.requests", ...)` — hand-rolled custom metric.

For the broader deploy flow (containers, push, expose-port, dashboards), see [examples/helloworld-python/README.md](../helloworld-python/README.md) — the Go example follows the same shape with a `go build` step in `deploy.sh`.

Related design docs:

- [TELEMETRY-DISTRO-DESIGN.md](../../docs/TELEMETRY-DISTRO-DESIGN.md) — distro contract + decisions.
- [OTEL-COLLECTOR-DESIGN.md](../../docs/OTEL-COLLECTOR-DESIGN.md) — the central collector this app exports to.
- [OTEL-AGENT-RELAY-DESIGN.md](../../docs/OTEL-AGENT-RELAY-DESIGN.md) — the per-LXC otel-sidecar that sits between this app and the central collector.
