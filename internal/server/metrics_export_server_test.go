package server

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/metrics/cloudexport"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestDefaultMetricsExportSinks_RegistersGCP pins exactly the gap a PR
// review of #1069 found: NewDualServer must actually call
// SetMetricsExportSinks(defaultMetricsExportSinks()) at startup, or
// every real daemon returns Unimplemented for GCP regardless of valid
// credentials — a failure mode the handler tests above can't catch
// because they inject a fake sink directly into a bare ContainerServer.
// This test pins defaultMetricsExportSinks' own contract (GCP
// registered, AWS deliberately absent); dual_server.go wiring it into
// NewDualServer is a one-line call, verified by reading the source
// rather than booting a full daemon (NewContainerServer needs a real
// incus/runtime backend unavailable in unit tests).
func TestDefaultMetricsExportSinks_RegistersGCP(t *testing.T) {
	sinks := defaultMetricsExportSinks()

	gcpSink, ok := sinks[pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP]
	if !ok || gcpSink == nil {
		t.Fatalf("defaultMetricsExportSinks() has no GCP sink registered: %+v", sinks)
	}
	if _, aws := sinks[pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_AWS]; aws {
		t.Errorf("AWS should not be registered yet (no Sink implementation) — SetMetricsExport's enum check must reject it before any sink lookup")
	}
	if len(sinks) != 1 {
		t.Errorf("defaultMetricsExportSinks() = %d entries, want exactly 1 (GCP only)", len(sinks))
	}
}

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

// fakeExportSources is a cloudexport.Sources with no Incus dependency,
// so a server-level enable test can start a real collector in-process.
type fakeExportSources struct{}

func (fakeExportSources) SystemResources(ctx context.Context) (*cloudexport.SystemResources, error) {
	return &cloudexport.SystemResources{ContainerCount: 3, MemoryTotalBytes: 1 << 30}, nil
}
func (fakeExportSources) AllContainerMetrics(ctx context.Context) (map[string]*pb.ContainerMetrics, error) {
	return nil, nil
}

// fakeExportExporter is a no-network sdkmetric.Exporter that counts
// pushes and can be told to fail the next one, so the server-level test
// can exercise the health-field wiring end to end.
type fakeExportExporter struct {
	mu       sync.Mutex
	exports  int
	failNext bool
}

func (e *fakeExportExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return sdkmetric.DefaultTemporalitySelector(k)
}
func (e *fakeExportExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}
func (e *fakeExportExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failNext {
		e.failNext = false
		return errors.New("simulated export failure")
	}
	e.exports++
	return nil
}
func (e *fakeExportExporter) ForceFlush(ctx context.Context) error { return nil }
func (e *fakeExportExporter) Shutdown(ctx context.Context) error   { return nil }

// fakeCollectorBuilder returns a metricsExportBuilder that stands up a
// real CloudExportCollector over the given exporter and a no-Incus
// Sources, and (optionally) captures it so a test can drive ForceFlush.
func fakeCollectorBuilder(exp sdkmetric.Exporter, capture **cloudexport.CloudExportCollector) func(context.Context, cloudexport.Config, cloudexport.Sink) (*cloudexport.CloudExportCollector, error) {
	return func(ctx context.Context, cfg cloudexport.Config, sink cloudexport.Sink) (*cloudexport.CloudExportCollector, error) {
		c := cloudexport.NewCollector(cloudexport.CollectorOptions{
			Sources:         fakeExportSources{},
			Exporter:        exp,
			Labels:          cloudexport.Labels{BackendID: "backend-test"},
			IntervalSeconds: cfg.IntervalSeconds,
		})
		if capture != nil {
			*capture = c
		}
		return c, nil
	}
}

// newMetricsExportTestServer builds a bare ContainerServer wired with a
// fake GCP sink so SetMetricsExport's probe never touches the network,
// and a fake collector builder so enabling starts a real in-process
// collector without Incus.
func newMetricsExportTestServer(gcpProbeErr error) (*ContainerServer, *fakeMetricsExportSink) {
	sink := &fakeMetricsExportSink{probeErr: gcpProbeErr}
	s := &ContainerServer{}
	s.SetMetricsExportSinks(map[pb.CloudMetricsProvider]cloudexport.Sink{
		pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP: sink,
	})
	s.metricsExportBuilder = fakeCollectorBuilder(&fakeExportExporter{}, nil)
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

// TestSetMetricsExport_StartsAndStopsCollector is the #1070 wiring: an
// enable actually starts a running collector, and a disable stops it —
// GetMetricsExport is no longer a config echo but reflects a live
// pipeline.
func TestSetMetricsExport_StartsAndStopsCollector(t *testing.T) {
	s, _ := newMetricsExportTestServer(nil)

	s.metricsExportMu.RLock()
	if s.metricsExportCollector != nil {
		t.Fatal("collector should be nil before enable")
	}
	s.metricsExportMu.RUnlock()

	if _, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
	}); err != nil {
		t.Fatalf("enable: %v", err)
	}

	s.metricsExportMu.RLock()
	running := s.metricsExportCollector
	s.metricsExportMu.RUnlock()
	if running == nil {
		t.Fatal("enable did not start a collector")
	}

	if _, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{Enabled: false}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	s.metricsExportMu.RLock()
	stopped := s.metricsExportCollector
	s.metricsExportMu.RUnlock()
	if stopped != nil {
		t.Fatal("disable did not stop the collector")
	}
}

// TestGetMetricsExport_ReflectsRealHealth locks the second #1070 gap:
// last_success_at / last_error / export_failures come from the running
// collector, not the zero-value stub #1069 shipped.
func TestGetMetricsExport_ReflectsRealHealth(t *testing.T) {
	sink := &fakeMetricsExportSink{}
	exp := &fakeExportExporter{}
	var collector *cloudexport.CloudExportCollector

	s := &ContainerServer{}
	s.SetMetricsExportSinks(map[pb.CloudMetricsProvider]cloudexport.Sink{
		pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP: sink,
	})
	s.metricsExportBuilder = fakeCollectorBuilder(exp, &collector)

	if _, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
	}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	defer func() { _, _ = s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{Enabled: false}) }()

	// Before any export tick, health is zero-valued.
	before, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if before.LastSuccessAt != nil || before.ExportFailures != 0 || before.LastError != "" {
		t.Errorf("expected zero health before first tick, got %+v", before)
	}

	// Force a successful export.
	if err := collector.ForceFlush(context.Background()); err != nil {
		t.Fatalf("force flush: %v", err)
	}
	afterSuccess, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if afterSuccess.LastSuccessAt == nil {
		t.Error("expected last_success_at set after a successful export")
	}
	if afterSuccess.ExportFailures != 0 {
		t.Errorf("expected 0 failures after success, got %d", afterSuccess.ExportFailures)
	}

	// Force a failing export.
	exp.mu.Lock()
	exp.failNext = true
	exp.mu.Unlock()
	_ = collector.ForceFlush(context.Background())
	afterFail, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if afterFail.ExportFailures != 1 {
		t.Errorf("expected 1 export failure, got %d", afterFail.ExportFailures)
	}
	if afterFail.LastError == "" {
		t.Error("expected last_error set after a failed export")
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

// groupSet turns an unordered slice of groups into a set for
// order-independent comparison in the group assertions below.
func groupSet(groups []pb.CloudMetricsGroup) map[pb.CloudMetricsGroup]bool {
	m := map[pb.CloudMetricsGroup]bool{}
	for _, g := range groups {
		m[g] = true
	}
	return m
}

// TestSetMetricsExport_EmptyGroupsDefaultsHost pins the backward-compat
// acceptance criterion: enabling without naming any groups keeps today's
// behavior — the effective set is [HOST] on both the enable response and
// a follow-up status read.
func TestSetMetricsExport_EmptyGroupsDefaultsHost(t *testing.T) {
	s, _ := newMetricsExportTestServer(nil)

	resp, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
		// Groups intentionally omitted.
	})
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	wantHost := []pb.CloudMetricsGroup{pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST}
	if !reflect.DeepEqual(resp.Groups, wantHost) {
		t.Errorf("enable response groups = %v, want %v", resp.Groups, wantHost)
	}

	statusResp, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !reflect.DeepEqual(statusResp.Groups, wantHost) {
		t.Errorf("status groups = %v, want %v", statusResp.Groups, wantHost)
	}
}

// TestSetMetricsExport_EnablesExactlyRequestedGroups covers the headline
// #1081 acceptance criterion: --groups host,platform enables exactly
// those two groups (typed on the wire), reflected on the enable response
// and the status read.
func TestSetMetricsExport_EnablesExactlyRequestedGroups(t *testing.T) {
	s, _ := newMetricsExportTestServer(nil)

	want := groupSet([]pb.CloudMetricsGroup{
		pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST,
		pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM,
	})

	resp, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
		Groups: []pb.CloudMetricsGroup{
			pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM,
			pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST,
		},
	})
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := groupSet(resp.Groups); !reflect.DeepEqual(got, want) {
		t.Errorf("enable response groups = %v, want %v", resp.Groups, want)
	}

	statusResp, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := groupSet(statusResp.Groups); !reflect.DeepEqual(got, want) {
		t.Errorf("status groups = %v, want %v", statusResp.Groups, want)
	}
}

// TestSetMetricsExport_RejectsInvalidGroups pins the typed-input guard: a
// request naming CLOUD_METRICS_GROUP_UNSPECIFIED (or an out-of-range
// value) is rejected with InvalidArgument before anything is persisted.
func TestSetMetricsExport_RejectsInvalidGroups(t *testing.T) {
	s, _ := newMetricsExportTestServer(nil)

	_, err := s.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
		Groups: []pb.CloudMetricsGroup{
			pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_UNSPECIFIED,
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error = %v, want InvalidArgument", err)
	}

	// Nothing persisted: status still reports disabled.
	statusResp, statusErr := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if statusErr != nil {
		t.Fatalf("status: %v", statusErr)
	}
	if statusResp.Enabled {
		t.Errorf("export enabled after a rejected groups request, want disabled")
	}
}

// TestSetMetricsExport_GroupsPersistAndResume pins that the enabled
// groups survive a daemon restart exactly like the enable toggle: enable
// [host,platform] on one server persists to the store; a fresh server
// sharing that store resumes with both groups.
func TestSetMetricsExport_GroupsPersistAndResume(t *testing.T) {
	kv := &fakeDaemonConfigKV{}

	first, _ := newMetricsExportTestServer(nil)
	first.daemonConfigStore = kv
	if _, err := first.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
		Groups: []pb.CloudMetricsGroup{
			pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST,
			pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM,
		},
	}); err != nil {
		t.Fatalf("enable: %v", err)
	}

	restarted, _ := newMetricsExportTestServer(nil)
	restarted.daemonConfigStore = kv
	restarted.StartMetricsExportIfEnabled(context.Background())

	got, err := restarted.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("status after resume: %v", err)
	}
	want := groupSet([]pb.CloudMetricsGroup{
		pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST,
		pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM,
	})
	if gotSet := groupSet(got.Groups); !reflect.DeepEqual(gotSet, want) {
		t.Errorf("resumed groups = %v, want %v", got.Groups, want)
	}
}

// TestGetMetricsExport_V060ConfigDefaultsHost pins the JSON
// compatibility path: a config persisted by v0.60.0 (no groups field)
// reports [HOST] rather than an empty group set.
func TestGetMetricsExport_V060ConfigDefaultsHost(t *testing.T) {
	kv := &fakeDaemonConfigKV{}
	kv.m = map[string]string{
		cloudexport.ConfigStoreKey: `{"enabled":true,"provider":1,"interval_seconds":60}`,
	}

	s, _ := newMetricsExportTestServer(nil)
	s.daemonConfigStore = kv

	got, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantHost := []pb.CloudMetricsGroup{pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST}
	if !reflect.DeepEqual(got.Groups, wantHost) {
		t.Errorf("v0.60.0 config groups = %v, want %v", got.Groups, wantHost)
	}
}

// fakeDaemonConfigKV backs daemonConfigKV with an in-memory map so
// persist/resume tests cover the real store round trip without
// Postgres.
type fakeDaemonConfigKV struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *fakeDaemonConfigKV) Get(ctx context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[key], nil
}

func (f *fakeDaemonConfigKV) Set(ctx context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]string{}
	}
	f.m[key] = value
	return nil
}

// TestStartMetricsExportIfEnabled_ResumesFromPersistedConfig pins the
// restart round trip end to end: enable on one server persists to the
// store; a fresh server sharing that store (a restarted daemon) must
// resume the collector from StartMetricsExportIfEnabled alone, with no
// operator re-enable.
func TestStartMetricsExportIfEnabled_ResumesFromPersistedConfig(t *testing.T) {
	kv := &fakeDaemonConfigKV{}

	first, _ := newMetricsExportTestServer(nil)
	first.daemonConfigStore = kv
	if _, err := first.SetMetricsExport(testCtx(), &pb.SetMetricsExportRequest{
		Enabled:  true,
		Provider: pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP,
	}); err != nil {
		t.Fatalf("enable: %v", err)
	}

	restarted, _ := newMetricsExportTestServer(nil)
	restarted.daemonConfigStore = kv
	restarted.StartMetricsExportIfEnabled(context.Background())

	restarted.metricsExportMu.RLock()
	running := restarted.metricsExportCollector
	restarted.metricsExportMu.RUnlock()
	if running == nil {
		t.Fatal("restarted server did not resume the export collector from the persisted config")
	}

	got, err := restarted.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("GetMetricsExport after resume: %v", err)
	}
	if !got.Enabled || got.Provider != pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP {
		t.Errorf("after resume: enabled=%v provider=%v, want enabled GCP", got.Enabled, got.Provider)
	}
}

// TestMetricsExport_LateStoreWiring_NotCachedAsDisabled pins the exact
// live-caught #1070 bug: StartMetricsExportIfEnabled used to run before
// the daemon-config store was wired (it arrived only via
// SetAlertManager, much later in NewDualServer), hydrate the disabled
// default from the nil store, and cache it as loaded — so both resume
// AND every later status read reported disabled even though the DB row
// said enabled. A nil-store hydration must not poison the config once
// the store shows up.
func TestMetricsExport_LateStoreWiring_NotCachedAsDisabled(t *testing.T) {
	kv := &fakeDaemonConfigKV{}
	kv.m = map[string]string{
		cloudexport.ConfigStoreKey: `{"enabled":true,"provider":1,"interval_seconds":60}`,
	}

	s, _ := newMetricsExportTestServer(nil)
	// Startup ordering bug: resume runs with no store wired. It must
	// no-op without caching "disabled" as authoritative.
	s.StartMetricsExportIfEnabled(context.Background())

	// Store gets wired later in startup.
	s.daemonConfigStore = kv

	got, err := s.GetMetricsExport(testCtx(), &pb.GetMetricsExportRequest{})
	if err != nil {
		t.Fatalf("GetMetricsExport: %v", err)
	}
	if !got.Enabled {
		t.Fatal("persisted enabled=true was shadowed by a cached nil-store hydration")
	}
}

// TestCurrentExportLabels pins the label snapshot a collector is built
// with: it must read the daemon's identity as of the call, so identity
// wired after the ContainerServer is constructed (as DualServer.Start
// does) is reflected — not frozen at construction. This is the #1080
// invariant: the resumed and runtime-enabled collectors share this one
// snapshot function, so both carry the same backend_id/region.
func TestCurrentExportLabels(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*ContainerServer)
		wantBackID string
		wantRegion string
	}{
		{
			name: "pooled backend with region -> real identity",
			setup: func(s *ContainerServer) {
				s.SetPeerPool(NewPeerPool("backend-live-7", "", nil, "us-central1"))
				s.SetCapabilityIdentity("us-central1", "us-central1")
			},
			wantBackID: "backend-live-7",
			wantRegion: "us-central1",
		},
		{
			name: "identity applied after construction is reflected (not frozen early)",
			setup: func(s *ContainerServer) {
				// Emulate DualServer.Start wiring identity onto an
				// already-constructed server, the exact sequence the
				// #1080 fix depends on.
				s.SetCapabilityIdentity("eu-west1", "eu-west1")
				s.SetPeerPool(NewPeerPool("backend-eu-2", "", nil, "eu-west1"))
			},
			wantBackID: "backend-eu-2",
			wantRegion: "eu-west1",
		},
		{
			name:       "no pool, empty region -> documented single-host placeholder",
			setup:      func(s *ContainerServer) {},
			wantBackID: "local",
			wantRegion: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ContainerServer{}
			tc.setup(s)
			got := s.currentExportLabels("host-1")
			if got.BackendID != tc.wantBackID || got.Region != tc.wantRegion {
				t.Errorf("currentExportLabels() = {backend_id:%q region:%q}, want {backend_id:%q region:%q}",
					got.BackendID, got.Region, tc.wantBackID, tc.wantRegion)
			}
			if got.Hostname != "host-1" {
				t.Errorf("hostname = %q, want the passed-in host-1", got.Hostname)
			}
		})
	}
}

// TestStartMetricsExportIfEnabled_ResumeCapturesLiveIdentity is the
// #1080 regression. The live bug: StartMetricsExportIfEnabled ran inline
// in NewDualServer, before SetPeerPool/SetCapabilityIdentity, so the
// resumed collector snapshotted the "local"/"" placeholders instead of
// the daemon's real backend_id/region — every daemon restart re-emitted
// the host's series under a second identity, splitting dashboards and
// alerts keyed on backend_id. This drives the real resume path and
// observes, via the builder seam, exactly the identity the collector is
// built with. The fix sequences resume after identity is wired
// (DualServer.Start), so the "identity wired" case is the post-fix world
// and the "identity absent" case documents what the old ordering emitted.
func TestStartMetricsExportIfEnabled_ResumeCapturesLiveIdentity(t *testing.T) {
	newEnabledResumeServer := func() (*ContainerServer, *cloudexport.Labels) {
		s := &ContainerServer{}
		s.SetMetricsExportSinks(map[pb.CloudMetricsProvider]cloudexport.Sink{
			pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP: &fakeMetricsExportSink{},
		})
		s.daemonConfigStore = &fakeDaemonConfigKV{m: map[string]string{
			cloudexport.ConfigStoreKey: `{"enabled":true,"provider":1,"interval_seconds":60}`,
		}}
		captured := &cloudexport.Labels{}
		s.metricsExportBuilder = func(ctx context.Context, cfg cloudexport.Config, sink cloudexport.Sink) (*cloudexport.CloudExportCollector, error) {
			// Snapshot identity the same way the real
			// buildMetricsExportCollector does, at invoke time.
			*captured = s.currentExportLabels("host-1")
			return cloudexport.NewCollector(cloudexport.CollectorOptions{
				Sources:  fakeExportSources{},
				Exporter: &fakeExportExporter{},
				Labels:   *captured,
			}), nil
		}
		return s, captured
	}

	t.Run("identity wired before resume -> real labels (post-#1080-fix ordering)", func(t *testing.T) {
		s, captured := newEnabledResumeServer()
		s.SetPeerPool(NewPeerPool("backend-live-7", "", nil, "us-central1"))
		s.SetCapabilityIdentity("us-central1", "us-central1")

		s.StartMetricsExportIfEnabled(context.Background())

		if captured.BackendID != "backend-live-7" || captured.Region != "us-central1" {
			t.Fatalf("resumed collector labels = {backend_id:%q region:%q}, want the daemon's live identity {backend-live-7 us-central1}",
				captured.BackendID, captured.Region)
		}
	})

	t.Run("identity absent -> placeholder labels (the pre-fix NewDualServer ordering)", func(t *testing.T) {
		s, captured := newEnabledResumeServer()
		// No SetPeerPool / SetCapabilityIdentity: reproduces resume
		// running before the daemon's identity was wired.
		s.StartMetricsExportIfEnabled(context.Background())

		if captured.BackendID != "local" || captured.Region != "" {
			t.Fatalf("with identity unwired, labels = {backend_id:%q region:%q}, want the placeholder {local \"\"} the #1080 bug emitted",
				captured.BackendID, captured.Region)
		}
	})
}
