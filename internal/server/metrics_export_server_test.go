package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/metrics/cloudexport"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeMetricsExportSink lets handler tests control Probe's outcome
// without touching real GCP ADC.
type fakeMetricsExportSink struct {
	probeErr error
	probed   int
}

func (f *fakeMetricsExportSink) NewExporter(ctx context.Context, cfg cloudexport.SinkConfig) (sdkmetric.Exporter, error) {
	return nil, errors.New("not used in tests")
}

func (f *fakeMetricsExportSink) Probe(ctx context.Context) error {
	f.probed++
	return f.probeErr
}

// newMetricsExportTestServer builds a bare ContainerServer wired with a
// fake GCP sink so SetMetricsExport's probe never touches the network.
func newMetricsExportTestServer(gcpProbeErr error) (*ContainerServer, *fakeMetricsExportSink) {
	sink := &fakeMetricsExportSink{probeErr: gcpProbeErr}
	s := &ContainerServer{}
	s.SetMetricsExportSinks(map[pb.CloudMetricsProvider]cloudexport.Sink{
		pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP: sink,
	})
	return s, sink
}

func TestSetMetricsExport_RejectsNonAdmin(t *testing.T) {
	s, _ := newMetricsExportTestServer(nil)
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")

	_, err := s.SetMetricsExport(ctx, &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

func TestGetMetricsExport_RejectsNonAdmin(t *testing.T) {
	s, _ := newMetricsExportTestServer(nil)
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")

	_, err := s.GetMetricsExport(ctx, &pb.GetMetricsExportRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

// TestSetMetricsExport_EnumValidation is the design doc's table:
// UNSPECIFIED -> InvalidArgument, AWS -> Unimplemented, GCP -> ok
// (probe permitting).
func TestSetMetricsExport_EnumValidation(t *testing.T) {
	tests := []struct {
		name     string
		provider pb.CloudMetricsProvider
		wantCode codes.Code
	}{
		{
			name:     "unspecified provider is InvalidArgument",
			provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_UNSPECIFIED,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "AWS is Unimplemented",
			provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_AWS,
			wantCode: codes.Unimplemented,
		},
		{
			name:     "GCP with a healthy probe succeeds",
			provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
			wantCode: codes.OK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newMetricsExportTestServer(nil)
			resp, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
				Enabled:  true,
				Provider: tc.provider,
			})
			if tc.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !resp.Enabled || resp.Provider != tc.provider {
					t.Errorf("response = %+v, want enabled=true provider=%v", resp, tc.provider)
				}
				return
			}
			if status.Code(err) != tc.wantCode {
				t.Fatalf("error = %v, want code %v", err, tc.wantCode)
			}
		})
	}
}

// TestSetMetricsExport_ProbeFailure_PersistsNothing locks the
// acceptance criterion: a host with no resolvable GCP credentials fails
// the enable call with FailedPrecondition and the config remains
// disabled/unconfigured afterward.
func TestSetMetricsExport_ProbeFailure_PersistsNothing(t *testing.T) {
	s, sink := newMetricsExportTestServer(errors.New("no Application Default Credentials found (attach roles/monitoring.metricWriter)"))

	_, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "roles/monitoring.metricWriter") {
		t.Errorf("error %q does not carry the IAM remediation hint", err)
	}
	if sink.probed != 1 {
		t.Fatalf("expected exactly one probe call, got %d", sink.probed)
	}

	// Nothing was persisted: status still reports disabled/unconfigured.
	statusResp, statusErr := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if statusErr != nil {
		t.Fatalf("unexpected error from GetMetricsExport: %v", statusErr)
	}
	if statusResp.Enabled {
		t.Errorf("GetMetricsExport.Enabled = true after a failed probe, want false")
	}
	if statusResp.Provider != pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_UNSPECIFIED {
		t.Errorf("GetMetricsExport.Provider = %v after a failed probe, want UNSPECIFIED", statusResp.Provider)
	}
}

// TestSetMetricsExport_EnableDisableStatusRoundTrip covers the headline
// acceptance criterion: enable -> status reflects it -> disable ->
// status reflects it, all without a daemon restart (same in-process
// ContainerServer throughout).
func TestSetMetricsExport_EnableDisableStatusRoundTrip(t *testing.T) {
	s, _ := newMetricsExportTestServer(nil)

	// Initially unconfigured.
	initial, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if initial.Enabled {
		t.Fatalf("expected export disabled by default, got enabled")
	}

	// Enable.
	enableResp, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
	})
	if err != nil {
		t.Fatalf("unexpected error enabling: %v", err)
	}
	if !enableResp.Enabled || enableResp.Provider != pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP {
		t.Fatalf("enable response = %+v", enableResp)
	}
	if enableResp.IntervalSeconds != cloudexport.DefaultIntervalSeconds {
		t.Errorf("interval_seconds = %d, want default %d", enableResp.IntervalSeconds, cloudexport.DefaultIntervalSeconds)
	}

	afterEnable, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !afterEnable.Enabled || afterEnable.Provider != pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP {
		t.Fatalf("status after enable = %+v, want enabled=true provider=GCP", afterEnable)
	}

	// Disable.
	disableResp, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error disabling: %v", err)
	}
	if disableResp.Enabled {
		t.Fatalf("disable response still reports enabled: %+v", disableResp)
	}

	afterDisable, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if afterDisable.Enabled {
		t.Fatalf("status after disable = %+v, want enabled=false", afterDisable)
	}
	// Provider is sticky across a disable (operationally useful: a bare
	// `enable` after `disable` doesn't need --provider again). Only
	// enabled flips.
	if afterDisable.Provider != pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP {
		t.Errorf("status after disable dropped the provider: got %v, want it to stay GCP", afterDisable.Provider)
	}
}

// TestSetMetricsExport_NoSinkRegistered_Unimplemented covers a host
// where SetMetricsExportSinks was never called (e.g. an older daemon
// build or a runtime with no sinks wired) — enabling GCP must fail
// closed, not panic on a nil map lookup.
func TestSetMetricsExport_NoSinkRegistered_Unimplemented(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("error = %v, want Unimplemented", err)
	}
}
