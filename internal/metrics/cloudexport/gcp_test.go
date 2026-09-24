package cloudexport

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	colmetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// fakeTokenSource lets tests simulate a credential that resolves but
// can't actually mint a token (revoked, wrong scope, expired refresh
// token, ...) without any network call.
type fakeTokenSource struct {
	token *oauth2.Token
	err   error
}

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.token, nil
}

// TestProbe_ADC is the table from the design doc's test strategy:
// (no ADC / wrong-scope token / ok) -> (actionable error / actionable
// error / nil). No network or filesystem ADC search is exercised —
// gcpCredentialsLookup is swapped for the duration of each case.
func TestProbe_ADC(t *testing.T) {
	tests := []struct {
		name    string
		lookup  func(ctx context.Context) (*google.Credentials, error)
		wantErr bool
		wantSub string // substring the error must contain, if wantErr
	}{
		{
			name: "no ADC configured",
			lookup: func(ctx context.Context) (*google.Credentials, error) {
				return nil, errors.New("could not find default credentials")
			},
			wantErr: true,
			wantSub: "roles/monitoring.metricWriter",
		},
		{
			name: "credentials resolve but token source is nil",
			lookup: func(ctx context.Context) (*google.Credentials, error) {
				return &google.Credentials{}, nil
			},
			wantErr: true,
			wantSub: "roles/monitoring.metricWriter",
		},
		{
			name: "credentials resolve but token mint fails (revoked / wrong scope)",
			lookup: func(ctx context.Context) (*google.Credentials, error) {
				return &google.Credentials{
					TokenSource: &fakeTokenSource{err: errors.New("invalid_grant: token has been revoked")},
				}, nil
			},
			wantErr: true,
			wantSub: "roles/monitoring.metricWriter",
		},
		{
			name: "ok",
			lookup: func(ctx context.Context) (*google.Credentials, error) {
				return &google.Credentials{
					TokenSource: &fakeTokenSource{token: &oauth2.Token{
						AccessToken: "fake-token",
						Expiry:      time.Now().Add(time.Hour),
					}},
				}, nil
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := gcpCredentialsLookup
			gcpCredentialsLookup = tc.lookup
			defer func() { gcpCredentialsLookup = orig }()

			sink := NewGCPSink()
			err := sink.Probe(context.Background())

			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if tc.wantErr && tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain expected hint %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// fakeOTLPMetricsServer is an in-process OTLP metrics collector: it
// records the ExportMetricsServiceRequest batches the real
// otlpmetricgrpc exporter code path sends, so the exporter can be
// exercised end-to-end without touching Google Cloud's OTLP ingestion
// endpoint (#1979 migration off the deprecated GAPIC-based exporter).
type fakeOTLPMetricsServer struct {
	colmetricpb.UnimplementedMetricsServiceServer
	mu       sync.Mutex
	requests []*colmetricpb.ExportMetricsServiceRequest
}

func (f *fakeOTLPMetricsServer) Export(ctx context.Context, req *colmetricpb.ExportMetricsServiceRequest) (*colmetricpb.ExportMetricsServiceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	return &colmetricpb.ExportMetricsServiceResponse{}, nil
}

func (f *fakeOTLPMetricsServer) received() []*colmetricpb.ExportMetricsServiceRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*colmetricpb.ExportMetricsServiceRequest(nil), f.requests...)
}

// metricNames flattens every Metric.Name across every ResourceMetrics/
// ScopeMetrics in every received batch, deduplicated and sorted — the
// exact set of OTLP metric names the exporter sent, independent of how
// many ticks/batches they arrived in.
func (f *fakeOTLPMetricsServer) metricNames() []string {
	seen := map[string]bool{}
	var names []string
	for _, req := range f.received() {
		for _, rm := range req.GetResourceMetrics() {
			for _, sm := range rm.GetScopeMetrics() {
				for _, m := range sm.GetMetrics() {
					if name := m.GetName(); !seen[name] {
						seen[name] = true
						names = append(names, name)
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// startFakeOTLPCollector spins up the fake OTLP metrics collector on a
// loopback listener and returns it plus an insecure gRPC connection
// pointed at it, suitable for SinkConfig.GRPCConn.
func startFakeOTLPCollector(t *testing.T) (*fakeOTLPMetricsServer, *grpc.ClientConn) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fake := &fakeOTLPMetricsServer{}
	srv := grpc.NewServer()
	colmetricpb.RegisterMetricsServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial fake OTLP collector: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return fake, conn
}

// TestGCPSink_NewExporter_PushesToFakeOTLPCollector is the #1979 OTLP
// migration's replacement for the pre-migration GAPIC-based
// TestGCPSink_NewExporter_PushesToFakeMonitoring: NewExporter must still
// return a real, usable sdkmetric.Exporter, and driving the
// CloudExportCollector against it must land an OTLP export batch
// carrying the allowlisted host series at a fake OTLP collector — the
// real exporter code path, only Google's OTLP endpoint faked.
func TestGCPSink_NewExporter_PushesToFakeOTLPCollector(t *testing.T) {
	ctx := context.Background()
	fake, conn := startFakeOTLPCollector(t)

	sink := NewGCPSink()
	exp, err := sink.NewExporter(ctx, SinkConfig{
		ProjectID: "test-project",
		GRPCConn:  conn,
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	if exp == nil {
		t.Fatal("NewExporter returned a nil exporter")
	}

	c := NewCollector(CollectorOptions{
		Sources:  &fakeSources{sr: sampleResources()},
		Exporter: exp,
		Labels:   sampleLabels(),
	})
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = c.Stop(ctx) }()

	if err := c.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	reqs := fake.received()
	if len(reqs) == 0 {
		t.Fatal("fake OTLP collector received no ExportMetricsServiceRequest")
	}
	var haveHostSeries bool
	for _, name := range fake.metricNames() {
		if strings.Contains(name, "containarium.host.") {
			haveHostSeries = true
		}
	}
	if !haveHostSeries {
		t.Errorf("no containarium.host.* series in the OTLP export batches: %v", fake.metricNames())
	}
}

// TestGCPSink_NewExporter_SeriesNamesPinned is the #1979 migration's
// characterization test: it pins the EXACT set of OTLP metric names the
// GCP sink sends for the default (host-only) collector configuration, as
// they leave gcp.go's exporter, unprefixed.
//
// Google Cloud's OTLP ingestion endpoint (telemetry.googleapis.com)
// applies the same "workload.googleapis.com/<name>" default metric-type
// prefix the deprecated opentelemetry-operations-go exporter applied
// client-side (see
// https://docs.cloud.google.com/stackdriver/docs/otlp-metrics/overview:
// "the OTLP metric name is prefixed with the string
// workload.googleapis.com/, unless the OTLP metric name already contains
// this string or another valid metric domain") — so an unchanged name
// here is an unchanged Cloud Monitoring series name end-to-end, which is
// the #1979 acceptance criterion this test exists to prove. Any diff in
// this list is exactly the "series names changed" regression that
// criterion forbids: touching it requires a deliberate review of the
// billed cost surface, same as collector.go's instrument allowlist.
func TestGCPSink_NewExporter_SeriesNamesPinned(t *testing.T) {
	ctx := context.Background()
	fake, conn := startFakeOTLPCollector(t)

	sink := NewGCPSink()
	exp, err := sink.NewExporter(ctx, SinkConfig{GRPCConn: conn})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}

	c := NewCollector(CollectorOptions{
		Sources:  &fakeSources{sr: sampleResources()},
		Exporter: exp,
		Labels:   sampleLabels(),
	})
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = c.Stop(ctx) }()

	if err := c.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	// The default CollectorOptions.Groups (nil) normalizes to [HOST], so
	// this is the host allowlist (collector.go's registerHostInstruments)
	// plus the unconditional heartbeat — nothing more, nothing renamed.
	want := []string{
		MetricCPULoad1m,
		MetricCPULoad5m,
		MetricCPULoad15m,
		MetricMemoryUsed,
		MetricMemoryTotal,
		MetricDiskUsed,
		MetricDiskTotal,
		MetricContainerCount,
		MetricHeartbeat,
	}
	sort.Strings(want)

	got := fake.metricNames()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exported OTLP metric names changed (this is the series-name regression #1979 forbids):\n got:  %v\nwant: %v", got, want)
	}
}

// TestGCPSink_ImplementsResourceProvider asserts the GCP sink supplies a
// monitored-resource detector (so series land as gce_instance), keeping
// the GCP detector import contained to gcp.go.
func TestGCPSink_ImplementsResourceProvider(t *testing.T) {
	if _, ok := NewGCPSink().(ResourceProvider); !ok {
		t.Fatal("gcpSink must implement ResourceProvider for gce_instance tagging")
	}
}
