package cloudexport

import (
	"context"
	"errors"
	"fmt"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
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

// NewExporter is not yet implemented — the Cloud Monitoring OTel
// exporter and the CloudExportCollector that would call this land with
// #1070/#1071. #1069 only needs Probe to gate the enable-time
// credential check.
func (g *gcpSink) NewExporter(ctx context.Context, cfg SinkConfig) (sdkmetric.Exporter, error) {
	return nil, errors.New("cloudexport: gcp exporter not yet implemented (lands with #1070/#1071)")
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
