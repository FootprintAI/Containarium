package cloudexport

import (
	"context"
	"fmt"

	mexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	gcpdetector "go.opentelemetry.io/contrib/detectors/gcp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"golang.org/x/oauth2/google"
)

// monitoringWriteScope is the OAuth2 scope required to write custom
// metrics to Google Cloud Monitoring (CreateTimeSeries).
const monitoringWriteScope = "https://www.googleapis.com/auth/monitoring.write"

// gcpCredentialsLookup resolves Application Default Credentials scoped
// for Cloud Monitoring writes. It is a package-level var — rather than a
// direct call to google.FindDefaultCredentials — so tests can inject a
// fake lookup (missing ADC, or a credential whose token source fails)
// without touching the network or the real ADC search path
// (GOOGLE_APPLICATION_CREDENTIALS, gcloud's well-known file, or the GCE
// metadata server).
var gcpCredentialsLookup = func(ctx context.Context) (*google.Credentials, error) {
	return google.FindDefaultCredentials(ctx, monitoringWriteScope)
}

// gcpSink implements Sink for Google Cloud Monitoring.
type gcpSink struct{}

// NewGCPSink returns the GCP Sink implementation.
func NewGCPSink() Sink { return &gcpSink{} }

// NewExporter builds the OTel SDK metric exporter that pushes to Google
// Cloud Monitoring (CreateTimeSeries) via the official
// opentelemetry-operations-go bridge. Authentication is ADC only — the
// exporter's monitoring client resolves the same Application Default
// Credentials that Probe validated at enable time; no key file is ever
// read here. This is the sole place in the daemon that imports the GCP
// exporter SDK — everything else sees the Sink interface.
func (g *gcpSink) NewExporter(ctx context.Context, cfg SinkConfig) (sdkmetric.Exporter, error) {
	opts := []mexporter.Option{
		// Do not create/patch metric descriptors on every push — the
		// series names are fixed and self-describing, and skipping
		// descriptor writes keeps the write path to CreateTimeSeries
		// only (fewer API calls, fewer IAM surfaces).
		mexporter.WithDisableCreateMetricDescriptors(),
	}
	// Empty ProjectID lets the exporter/resource detector infer the
	// project from the GCE metadata server (the common on-VM case).
	if cfg.ProjectID != "" {
		opts = append(opts, mexporter.WithProjectID(cfg.ProjectID))
	}
	if len(cfg.MonitoringClientOptions) > 0 {
		opts = append(opts, mexporter.WithMonitoringClientOptions(cfg.MonitoringClientOptions...))
	}

	exporter, err := mexporter.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudexport: build GCP Cloud Monitoring exporter: %w", err)
	}
	return exporter, nil
}

// DetectResource resolves this host's GCP monitored-resource identity so
// exported series land tagged as a gce_instance in Metrics Explorer. It
// uses the OTel contrib GCP resource detector; off GCP (or with the
// metadata server unreachable) it returns whatever partial resource the
// detector can assemble, which the exporter maps to a generic resource
// rather than failing the whole export. gcpSink is the only type that
// touches the GCP detector — the collector consumes the resulting
// vendor-neutral *resource.Resource.
func (g *gcpSink) DetectResource(ctx context.Context) (*resource.Resource, error) {
	return resource.New(ctx, resource.WithDetectors(gcpdetector.NewDetector()))
}

// Probe resolves ADC with the Cloud Monitoring write scope and confirms
// a token can actually be minted from it. A host with no ADC configured,
// or ADC that can't produce a usable token (revoked, wrong scope, no
// service account attached), fails with an actionable IAM hint —
// SetMetricsExport surfaces this as FAILED_PRECONDITION and persists
// nothing.
func (g *gcpSink) Probe(ctx context.Context) error {
	const iamHint = "run 'gcloud auth application-default login' for a workstation, " +
		"or attach a service account with the roles/monitoring.metricWriter IAM role to this VM"

	creds, err := gcpCredentialsLookup(ctx)
	if err != nil {
		return fmt.Errorf("no Application Default Credentials found for GCP Cloud Monitoring (%s): %w", iamHint, err)
	}
	if creds == nil || creds.TokenSource == nil {
		return fmt.Errorf("resolved GCP Application Default Credentials have no usable token source (%s)", iamHint)
	}
	if _, err := creds.TokenSource.Token(); err != nil {
		return fmt.Errorf("GCP Application Default Credentials could not mint a monitoring-write token (%s): %w", iamHint, err)
	}
	return nil
}
