package cloudexport

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	monitoringpb "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	apioption "google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
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

// fakeMetricServer is an in-process Cloud Monitoring gRPC server: it
// records the CreateTimeSeries requests the real exporter code path
// sends, so the exporter can be exercised end-to-end without touching
// GCP.
type fakeMetricServer struct {
	monitoringpb.UnimplementedMetricServiceServer
	mu       sync.Mutex
	requests []*monitoringpb.CreateTimeSeriesRequest
}

func (f *fakeMetricServer) CreateTimeSeries(ctx context.Context, req *monitoringpb.CreateTimeSeriesRequest) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	return &emptypb.Empty{}, nil
}

func (f *fakeMetricServer) received() []*monitoringpb.CreateTimeSeriesRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*monitoringpb.CreateTimeSeriesRequest(nil), f.requests...)
}

// startFakeMonitoring spins up the fake Cloud Monitoring server on a
// loopback listener and returns it plus an insecure client option
// pointed at it.
func startFakeMonitoring(t *testing.T) (*fakeMetricServer, apioption.ClientOption) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fake := &fakeMetricServer{}
	srv := grpc.NewServer()
	monitoringpb.RegisterMetricServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial fake monitoring: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return fake, apioption.WithGRPCConn(conn)
}

// TestGCPSink_NewExporter_PushesToFakeMonitoring is the #1070
// replacement for the #1069 not-yet-implemented placeholder: NewExporter
// must now return a real, usable sdkmetric.Exporter, and driving the
// CloudExportCollector against it must land a CreateTimeSeries batch
// carrying the allowlisted host series at the fake Cloud Monitoring
// endpoint — the real exporter code path, only the Google endpoint faked.
func TestGCPSink_NewExporter_PushesToFakeMonitoring(t *testing.T) {
	ctx := context.Background()
	fake, clientOpt := startFakeMonitoring(t)

	sink := NewGCPSink()
	exp, err := sink.NewExporter(ctx, SinkConfig{
		ProjectID:               "test-project",
		MonitoringClientOptions: []apioption.ClientOption{clientOpt},
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
		t.Fatal("fake Cloud Monitoring received no CreateTimeSeries request")
	}
	var haveHostSeries bool
	for _, r := range reqs {
		for _, ts := range r.GetTimeSeries() {
			if strings.Contains(ts.GetMetric().GetType(), "containarium.host.") {
				haveHostSeries = true
			}
		}
	}
	if !haveHostSeries {
		t.Errorf("no containarium.host.* series in the CreateTimeSeries batches: %v", reqs)
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
