package cloudexport

import (
	"context"
	"crypto/tls"
	"fmt"

	gcpdetector "go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// monitoringWriteScope is the OAuth2 scope required to write custom
// metrics to Google Cloud Monitoring (CreateTimeSeries).
const monitoringWriteScope = "https://www.googleapis.com/auth/monitoring.write"

// gcpOTLPEndpoint is Google Cloud's Telemetry API OTLP ingestion endpoint
// (see https://cloud.google.com/stackdriver/docs/otlp-metrics/overview).
// It accepts standard OTLP-over-gRPC and maps each metric's OTLP name to
// a Cloud Monitoring metric type by prefixing it with
// "workload.googleapis.com/" — the same default the deprecated
// opentelemetry-operations-go exporter used — so instrument names defined
// in collector.go land under identical series names post-migration.
const gcpOTLPEndpoint = "telemetry.googleapis.com:443"

// projectHeader is the header Google Cloud's OTLP ingestion reads to
// attribute incoming series to a project (the OTLP equivalent of the
// deprecated exporter's WithProjectID option), mirroring the
// "x-goog-user-project" convention used across GCP client libraries.
const projectHeader = "x-goog-user-project"

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
// Cloud Monitoring over standard OTLP-over-gRPC, per upstream's
// MIGRATION.md for the now-deprecated opentelemetry-operations-go
// exporter (#1979). Authentication is ADC, unchanged from before the
// migration: gcpCredentialsLookup resolves the same Application Default
// Credentials that Probe validates at enable time, wrapped as gRPC
// per-RPC credentials — no key file is ever read here, and no separate
// monitoring API client is built. This is the sole place in the daemon
// that dials the GCP OTLP endpoint — everything else sees the Sink
// interface.
func (g *gcpSink) NewExporter(ctx context.Context, cfg SinkConfig) (sdkmetric.Exporter, error) {
	var opts []otlpmetricgrpc.Option

	if cfg.GRPCConn != nil {
		// Test seam: dial straight into a fake in-process OTLP collector,
		// bypassing TLS and ADC entirely.
		opts = append(opts, otlpmetricgrpc.WithGRPCConn(cfg.GRPCConn))
	} else {
		creds, err := gcpCredentialsLookup(ctx)
		if err != nil {
			return nil, fmt.Errorf("cloudexport: resolve ADC for GCP OTLP metric export: %w", err)
		}
		opts = append(opts,
			otlpmetricgrpc.WithEndpoint(gcpOTLPEndpoint),
			otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(&tls.Config{})),
			otlpmetricgrpc.WithDialOption(grpc.WithPerRPCCredentials(oauth.TokenSource{TokenSource: creds.TokenSource})),
		)
	}

	// Empty ProjectID leaves project attribution to whatever quota
	// project ADC itself resolves (the GCE metadata server's project,
	// the common on-VM case) — same default behavior as the deprecated
	// exporter's empty WithProjectID.
	if cfg.ProjectID != "" {
		opts = append(opts, otlpmetricgrpc.WithHeaders(map[string]string{projectHeader: cfg.ProjectID}))
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudexport: build GCP OTLP metric exporter: %w", err)
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
