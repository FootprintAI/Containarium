// Package containariumotel is the Go telemetry distro for apps and
// services running on the Containarium platform.
//
// It pairs with the daemon's per-LXC env-stamping (--monitoring=true)
// and the central otel-collector / otel-sidecar pair: callers get a
// MeterProvider wired with the resource attrs Containarium expects
// (container.id, backend.id, tenant.id, service.version) plus the
// defended containarium.distro stamp, and an OTLP/HTTP exporter
// pointed at whatever endpoint the env sets.
//
// Basic usage:
//
//	shutdown, err := containariumotel.Init(ctx)
//	if err != nil {
//	    log.Printf("telemetry init: %v", err)
//	}
//	defer shutdown(ctx)
//
// With options:
//
//	shutdown, err := containariumotel.Init(ctx,
//	    containariumotel.WithServiceName("payment-api"),
//	    containariumotel.WithExtraAttrs(map[string]string{"region": "us-west-1"}),
//	    containariumotel.WithMetricInterval(10*time.Second),
//	)
//
// See docs/TELEMETRY-DISTRO-DESIGN.md in the main repo for the
// design and decision history.
package containariumotel
