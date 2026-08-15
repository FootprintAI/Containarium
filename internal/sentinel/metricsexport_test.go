package sentinel

import (
	"context"
	"runtime"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/footprintai/containarium/internal/metrics/cloudexport"
)

// #1358, part two: the series exist on /metrics but nothing scrapes them, and
// nothing can — the bundled monitoring stack runs ON the spot VM, so it is
// gone during exactly the outage worth observing. This pushes them to Cloud
// Monitoring from the always-on sentinel instead.
//
// These tests drive the real instrument registration through a ManualReader,
// so the names, values and attributes are asserted without a network. The
// GCP wire path itself is already covered by cloudexport's own
// TestGCPSink_NewExporter_PushesToFakeMonitoring.

// collectOnce registers the sentinel instruments against a ManualReader and
// returns the single collected scope's metrics.
func collectOnce(t *testing.T, m *Manager, sentinelID string) []metricdata.Metrics {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	if err := registerSentinelInstruments(provider.Meter("test"), m, sentinelID); err != nil {
		t.Fatalf("registerSentinelInstruments: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(rm.ScopeMetrics) == 0 {
		t.Fatal("no scope metrics collected — nothing was registered")
	}
	return rm.ScopeMetrics[0].Metrics
}

func findMetric(ms []metricdata.Metrics, name string) *metricdata.Metrics {
	for i := range ms {
		if ms[i].Name == name {
			return &ms[i]
		}
	}
	return nil
}

// gaugeValue returns the single int64 gauge datapoint's value.
func gaugeValue(t *testing.T, md *metricdata.Metrics) int64 {
	t.Helper()
	g, ok := md.Data.(metricdata.Gauge[int64])
	if !ok {
		t.Fatalf("%s is %T, want Gauge[int64]", md.Name, md.Data)
	}
	if len(g.DataPoints) != 1 {
		t.Fatalf("%s has %d datapoints, want 1", md.Name, len(g.DataPoints))
	}
	return g.DataPoints[0].Value
}

func sumValue(t *testing.T, md *metricdata.Metrics) int64 {
	t.Helper()
	s, ok := md.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("%s is %T, want Sum[int64]", md.Name, md.Data)
	}
	if !s.IsMonotonic {
		t.Errorf("%s is not monotonic; a _total counter must be", md.Name)
	}
	if len(s.DataPoints) != 1 {
		t.Fatalf("%s has %d datapoints, want 1", md.Name, len(s.DataPoints))
	}
	return s.DataPoints[0].Value
}

func TestSentinelInstrumentsExportTheLeakDetectionSeries(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.state.Store(StateProxy)
	m.preemptCount = 2
	m.recoveredCount = 1
	m.recordFailover()
	m.recordFailover()
	m.recordFailover()

	ms := collectOnce(t, m, "sentinel-test")

	// state: 1 = proxy (serving), 0 = maintenance.
	if md := findMetric(ms, metricSentinelState); md == nil {
		t.Errorf("missing %s", metricSentinelState)
	} else if got := gaugeValue(t, md); got != 1 {
		t.Errorf("%s = %d, want 1 (proxy)", metricSentinelState, got)
	}

	for _, tc := range []struct {
		name string
		want int64
	}{
		{metricSentinelPreempted, 2},
		{metricSentinelRecovered, 1},
		// The series that would have made the 09:17 backend loss visible.
		{metricSentinelFailover, 3},
	} {
		md := findMetric(ms, tc.name)
		if md == nil {
			t.Errorf("missing %s", tc.name)
			continue
		}
		if got := sumValue(t, md); got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, got, tc.want)
		}
	}

	// Goroutines are portable; RSS/fds need /proc (see the omission test).
	if md := findMetric(ms, metricSentinelGoroutines); md == nil {
		t.Errorf("missing %s", metricSentinelGoroutines)
	} else if got := gaugeValue(t, md); got < 1 {
		t.Errorf("%s = %d, want >= 1", metricSentinelGoroutines, got)
	}
}

// Resident memory is the whole point of exporting: it is what the OOM killer
// scores, and the series an alert on #1349 would key off.
func TestResidentMemoryIsExportedWhereProcExists(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("no /proc on %s — this is exercised on linux, where the sentinel runs", runtime.GOOS)
	}
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	ms := collectOnce(t, m, "sentinel-test")

	md := findMetric(ms, metricSentinelRSS)
	if md == nil {
		t.Fatalf("missing %s", metricSentinelRSS)
	}
	if got := gaugeValue(t, md); got <= 0 {
		t.Errorf("%s = %d, want > 0", metricSentinelRSS, got)
	}
	if findMetric(ms, metricSentinelOpenFDs) == nil {
		t.Errorf("missing %s", metricSentinelOpenFDs)
	}
}

// Same rule as #1351's /metrics rendering: where /proc is unreadable the
// process series must be ABSENT, never reported as zero. A zero here would
// read as "this process uses no memory" and silence the alert this exists to
// enable — and unlike the text endpoint, a zero datapoint would also be
// persisted forever in Cloud Monitoring.
func TestProcessSeriesOmittedWithoutProc(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this asserts the no-/proc branch; linux has /proc")
	}
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	ms := collectOnce(t, m, "sentinel-test")

	for _, name := range []string{metricSentinelRSS, metricSentinelOpenFDs} {
		if md := findMetric(ms, name); md != nil {
			t.Errorf("%s was exported with no /proc available — a zero would silence the leak alert", name)
		}
	}
	// The portable series must survive: losing /proc must not cost everything.
	if findMetric(ms, metricSentinelGoroutines) == nil {
		t.Error("runtime series dropped along with the proc series")
	}
}

func TestBackendHealthCarriesAPerBackendAttribute(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.recordBackendHealth("gcp", false)
	m.recordBackendHealth("tunnel-fts", true)

	ms := collectOnce(t, m, "sentinel-test")
	md := findMetric(ms, metricSentinelBackendHealthy)
	if md == nil {
		t.Fatalf("missing %s", metricSentinelBackendHealthy)
	}
	g, ok := md.Data.(metricdata.Gauge[int64])
	if !ok {
		t.Fatalf("%s is %T, want Gauge[int64]", md.Name, md.Data)
	}
	if len(g.DataPoints) != 2 {
		t.Fatalf("got %d datapoints, want one per backend (2)", len(g.DataPoints))
	}

	got := map[string]int64{}
	for _, dp := range g.DataPoints {
		v, ok := dp.Attributes.Value("backend")
		if !ok {
			t.Fatalf("datapoint has no 'backend' attribute: %v", dp.Attributes)
		}
		got[v.AsString()] = dp.Value
	}
	if got["gcp"] != 0 || got["tunnel-fts"] != 1 {
		t.Errorf("per-backend values = %v, want gcp:0 tunnel-fts:1", got)
	}
}

// Every datapoint must carry the sentinel's identity, or two sentinels'
// series collide into one meaningless line in Cloud Monitoring.
func TestSeriesCarrySentinelIdentity(t *testing.T) {
	ms := collectOnce(t, NewManager(Config{}, &fakeRecoveryProvider{}), "asia-sentinel")

	md := findMetric(ms, metricSentinelState)
	if md == nil {
		t.Fatal("missing state metric")
	}
	g := md.Data.(metricdata.Gauge[int64])
	v, ok := g.DataPoints[0].Attributes.Value("sentinel")
	if !ok {
		t.Fatalf("no 'sentinel' attribute on the datapoint: %v", g.DataPoints[0].Attributes)
	}
	if v.AsString() != "asia-sentinel" {
		t.Errorf("sentinel attribute = %q, want %q", v.AsString(), "asia-sentinel")
	}
}

// Custom metrics are billed per ingested sample, so a misconfigured (or
// hostile) sub-minute interval must not be honoured. Mirrors the daemon's
// existing clamp rather than inventing a second policy.
func TestExportIntervalClampedToBillingFloor(t *testing.T) {
	for _, tc := range []struct{ in, want int32 }{
		{0, cloudexport.MinIntervalSeconds},
		{-30, cloudexport.MinIntervalSeconds},
		{1, cloudexport.MinIntervalSeconds},
		{59, cloudexport.MinIntervalSeconds},
		{60, 60},
		{300, 300},
	} {
		if got := clampExportInterval(tc.in); got != tc.want {
			t.Errorf("clampExportInterval(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestStartMetricsExportRequiresAnExporter(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	if _, err := StartMetricsExport(m, MetricsExportOptions{}); err == nil {
		t.Error("StartMetricsExport with no exporter returned nil error; it cannot push anywhere")
	}
}

// Start must hand back a working stop so the sentinel can shut the exporter
// down without leaking its periodic reader goroutine.
func TestStartMetricsExportStops(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	stop, err := StartMetricsExport(m, MetricsExportOptions{
		Exporter:        &noopExporter{},
		SentinelID:      "test",
		IntervalSeconds: 60,
	})
	if err != nil {
		t.Fatalf("StartMetricsExport: %v", err)
	}
	if stop == nil {
		t.Fatal("nil stop func")
	}
	if err := stop(context.Background()); err != nil {
		t.Errorf("stop: %v", err)
	}
}

// noopExporter is a minimal sdkmetric.Exporter for lifecycle tests.
type noopExporter struct{}

func (n *noopExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return sdkmetric.DefaultTemporalitySelector(k)
}
func (n *noopExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}
func (n *noopExporter) Export(context.Context, *metricdata.ResourceMetrics) error { return nil }
func (n *noopExporter) ForceFlush(context.Context) error                          { return nil }
func (n *noopExporter) Shutdown(context.Context) error                            { return nil }
