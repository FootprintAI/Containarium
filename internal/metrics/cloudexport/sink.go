// Package cloudexport is the seam for opt-in export of Containarium's
// host/container infra metrics to a host cloud's native monitoring
// (GCP Cloud Monitoring first — #1069/#1070/#1071).
//
// #1069 delivers the toggle (enable/disable/status), typed config
// persistence, and the enable-time credential probe. The full collector
// (CloudExportCollector + Sources + the allowlisted OTel instrument set
// described in docs/CLOUD-NATIVE-METRICS-EXPORT-DESIGN.md) lands with
// #1070 (host series) and #1071 (container series); this package is the
// skeleton those land into.
package cloudexport

import (
	"context"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	apioption "google.golang.org/api/option"
)

// SinkConfig carries the parameters a Sink needs to build its OTel metric
// exporter. Provider-specific fields (GCP project ID, AWS region, ...)
// land here as #1070/#1071 wire the collector.
type SinkConfig struct {
	// ProjectID is the GCP project the exported series should land in.
	// Empty lets the resource detector infer it from the metadata server.
	ProjectID string

	// MonitoringClientOptions are extra client options threaded into the
	// provider's monitoring API client. Empty in production (ADC over
	// the real endpoint); tests set an insecure gRPC dial + a fake
	// endpoint so the real exporter code path runs against an
	// in-process Cloud Monitoring server without calling GCP.
	MonitoringClientOptions []apioption.ClientOption
}

// Sink abstracts one cloud provider's metrics backend. GCP is the only
// implementation in the MVP (gcpSink, gcp.go); AWS is a reserved
// CloudMetricsProvider enum value with no Sink registered — the server
// layer returns Unimplemented for it before ever reaching this
// interface.
type Sink interface {
	// NewExporter builds the OTel SDK metric exporter that pushes to
	// this provider. Not implemented by any Sink as of #1069 — the
	// CloudExportCollector that would call it lands with #1070/#1071.
	NewExporter(ctx context.Context, cfg SinkConfig) (sdkmetric.Exporter, error)

	// Probe verifies the host can authenticate to this provider's
	// monitoring API right now, without emitting anything. Returns nil
	// when export can proceed; otherwise an error carrying an
	// actionable remediation hint. The server layer maps a non-nil
	// error to FAILED_PRECONDITION and persists nothing.
	Probe(ctx context.Context) error
}

// ResourceProvider is an optional capability a Sink may implement to
// supply the provider's monitored-resource identity (e.g. a GCP
// gce_instance) that every exported series should be tagged with. The
// collector consumes the resulting vendor-neutral *resource.Resource, so
// provider-specific detection stays contained in the Sink. A Sink that
// does not implement this leaves the collector on the SDK default
// resource.
type ResourceProvider interface {
	DetectResource(ctx context.Context) (*resource.Resource, error)
}
