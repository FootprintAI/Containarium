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
)

// SinkConfig carries the parameters a Sink needs to build its OTel metric
// exporter. Provider-specific fields (GCP project ID, AWS region, ...)
// land here as #1070/#1071 wire the collector; #1069 only needs enough
// surface to define the interface.
type SinkConfig struct {
	// ProjectID is the GCP project the exported series should land in.
	// Empty lets the resource detector infer it from the metadata server.
	ProjectID string
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
