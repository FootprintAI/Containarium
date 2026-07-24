package cloudexport

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/footprintai/containarium/internal/metrics/platformstats"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeSources is a Sources whose SystemResources snapshot and error are
// fully controlled by the test. AllContainerMetrics is present to
// satisfy the interface (the #1070 host collector never calls it).
type fakeSources struct {
	sr  *SystemResources
	err error
}

func (f *fakeSources) SystemResources(ctx context.Context) (*SystemResources, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.sr, nil
}

func (f *fakeSources) AllContainerMetrics(ctx context.Context) (map[string]*pb.ContainerMetrics, error) {
	return nil, nil
}

func sampleResources() *SystemResources {
	return &SystemResources{
		CPULoad1Min:      1.5,
		CPULoad5Min:      2.5,
		CPULoad15Min:     3.5,
		MemoryUsedBytes:  4 << 30,
		MemoryTotalBytes: 16 << 30,
		DiskUsedBytes:    100 << 30,
		DiskTotalBytes:   500 << 30,
		ContainerCount:   7,
	}
}

func sampleLabels() Labels {
	return Labels{BackendID: "backend-xyz", Hostname: "host-1", Region: "us-central1"}
}

// collectOnce stands up a ManualReader-backed MeterProvider through the
// same buildMeterProvider path the production PeriodicReader uses, then
// pulls exactly one collection so tests can assert on the emitted series.
func collectOnce(t *testing.T, sources Sources, labels Labels) metricdata.ResourceMetrics {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	c := NewCollector(CollectorOptions{Sources: sources, Labels: labels})
	mp, err := c.buildMeterProvider(reader)
	if err != nil {
		t.Fatalf("buildMeterProvider: %v", err)
	}
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rm
}

// flattenGauges returns every emitted gauge datapoint as (name, value,
// attributes), independent of whether it was float64 or int64.
type point struct {
	name  string
	fval  float64
	ival  int64
	isInt bool
	attrs attribute.Set
}

func flattenGauges(t *testing.T, rm metricdata.ResourceMetrics) []point {
	t.Helper()
	var pts []point
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch g := m.Data.(type) {
			case metricdata.Gauge[float64]:
				for _, dp := range g.DataPoints {
					pts = append(pts, point{name: m.Name, fval: dp.Value, attrs: dp.Attributes})
				}
			case metricdata.Gauge[int64]:
				for _, dp := range g.DataPoints {
					pts = append(pts, point{name: m.Name, ival: dp.Value, isInt: true, attrs: dp.Attributes})
				}
			default:
				t.Fatalf("metric %q is not a gauge (%T) — the allowlist is gauge-only", m.Name, m.Data)
			}
		}
	}
	return pts
}

// TestExportedSeries_MatchesAllowlistGolden is the golden test: the exact
// set of series names and per-series values emitted for one snapshot.
// Any drift — an added series, a removed one, a renamed instrument, a
// wrong value mapping — fails here.
func TestExportedSeries_MatchesAllowlistGolden(t *testing.T) {
	rm := collectOnce(t, &fakeSources{sr: sampleResources()}, sampleLabels())
	pts := flattenGauges(t, rm)

	got := map[string]point{}
	for _, p := range pts {
		if _, dup := got[p.name]; dup {
			t.Fatalf("series %q emitted more than once", p.name)
		}
		got[p.name] = p
	}

	type want struct {
		isInt bool
		fval  float64
		ival  int64
	}
	golden := map[string]want{
		MetricCPULoad1m:      {fval: 1.5},
		MetricCPULoad5m:      {fval: 2.5},
		MetricCPULoad15m:     {fval: 3.5},
		MetricMemoryUsed:     {isInt: true, ival: 4 << 30},
		MetricMemoryTotal:    {isInt: true, ival: 16 << 30},
		MetricDiskUsed:       {isInt: true, ival: 100 << 30},
		MetricDiskTotal:      {isInt: true, ival: 500 << 30},
		MetricContainerCount: {isInt: true, ival: 7},
		// Heartbeat/up series (#1072): constant 1, emitted alongside the
		// host series every tick.
		MetricHeartbeat: {isInt: true, ival: 1},
	}

	if len(got) != len(golden) {
		var names []string
		for n := range got {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Fatalf("emitted %d series %v, want exactly %d (the allowlist)", len(got), names, len(golden))
	}

	for name, w := range golden {
		p, ok := got[name]
		if !ok {
			t.Errorf("missing allowlisted series %q", name)
			continue
		}
		if p.isInt != w.isInt {
			t.Errorf("series %q int-ness mismatch: got isInt=%v want %v", name, p.isInt, w.isInt)
			continue
		}
		if w.isInt && p.ival != w.ival {
			t.Errorf("series %q = %d, want %d", name, p.ival, w.ival)
		}
		if !w.isInt && p.fval != w.fval {
			t.Errorf("series %q = %v, want %v", name, p.fval, w.fval)
		}
	}
}

// fakePlatformSources is a PlatformSources whose API snapshot is fully
// controlled by the test.
type fakePlatformSources struct {
	api platformstats.APISnapshot
}

func (f *fakePlatformSources) APIStats() platformstats.APISnapshot {
	return f.api
}

// flattenPoints returns every emitted datapoint (gauge OR cumulative
// counter) as (name, value, attributes). Separate from flattenGauges
// (which deliberately fatals on anything but a gauge, locking in that
// the #1070 host/heartbeat series are gauge-only) because the platform
// group's api.requests/api.errors are Int64ObservableCounters —
// asserting on them needs a helper that accepts Sum[int64] too.
func flattenPoints(t *testing.T, rm metricdata.ResourceMetrics) []point {
	t.Helper()
	var pts []point
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch g := m.Data.(type) {
			case metricdata.Gauge[float64]:
				for _, dp := range g.DataPoints {
					pts = append(pts, point{name: m.Name, fval: dp.Value, attrs: dp.Attributes})
				}
			case metricdata.Gauge[int64]:
				for _, dp := range g.DataPoints {
					pts = append(pts, point{name: m.Name, ival: dp.Value, isInt: true, attrs: dp.Attributes})
				}
			case metricdata.Sum[int64]:
				for _, dp := range g.DataPoints {
					pts = append(pts, point{name: m.Name, ival: dp.Value, isInt: true, attrs: dp.Attributes})
				}
			default:
				t.Fatalf("metric %q has unhandled data type %T", m.Name, m.Data)
			}
		}
	}
	return pts
}

// collectGroupsOnce stands up a ManualReader-backed MeterProvider for a
// specific set of enabled groups and pulls one collection, so the
// per-group golden can assert exactly which series each group emits.
// platformSources may be nil — the platform group registers no
// instruments without one, matching production's "not wired yet"
// behavior.
func collectGroupsOnce(t *testing.T, groups []pb.CloudMetricsGroup, sources Sources, platformSources PlatformSources, labels Labels) metricdata.ResourceMetrics {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	c := NewCollector(CollectorOptions{Sources: sources, PlatformSources: platformSources, Labels: labels, Groups: groups})
	mp, err := c.buildMeterProvider(reader)
	if err != nil {
		t.Fatalf("buildMeterProvider: %v", err)
	}
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rm
}

// TestExportedSeries_PerGroupGolden is the #1081 per-group golden: it
// pins the exact set of series names each combination of enabled groups
// emits, so the billed sample surface stays reviewable in one file (the
// #1070 rule, now scoped per group). host emits the eight-series #1070
// allowlist; container and platform are reserved by #1081 (their series
// land in #1071/#1072 and #1082/#1083/#1084 respectively) so they add
// nothing yet — enabling them today is a deliberate, zero-series opt-in.
// Any drift in what a group exports fails here.
//
// The heartbeat/up series (#1072) is deliberately NOT a group: it is
// registered unconditionally by buildMeterProvider, independent of which
// groups are enabled, so it accompanies every combination below —
// including the reserved-only cases, which therefore emit the heartbeat
// alone rather than nothing. Each want set below lists the group-specific
// series; the harness adds the always-on heartbeat before asserting.
func TestExportedSeries_PerGroupGolden(t *testing.T) {
	host := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST
	container := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM

	hostSeries := []string{
		MetricCPULoad1m, MetricCPULoad5m, MetricCPULoad15m,
		MetricMemoryUsed, MetricMemoryTotal,
		MetricDiskUsed, MetricDiskTotal, MetricContainerCount,
	}

	tests := []struct {
		name   string
		groups []pb.CloudMetricsGroup
		want   []string
	}{
		{"default (nil) is host", nil, hostSeries},
		{"host only", []pb.CloudMetricsGroup{host}, hostSeries},
		{"container reserved, no series", []pb.CloudMetricsGroup{container}, nil},
		{"platform reserved, no series", []pb.CloudMetricsGroup{platform}, nil},
		{"host and platform is host series", []pb.CloudMetricsGroup{host, platform}, hostSeries},
		{"host and container is host series", []pb.CloudMetricsGroup{host, container}, hostSeries},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rm := collectGroupsOnce(t, tc.groups, &fakeSources{sr: sampleResources()}, nil, sampleLabels())
			pts := flattenGauges(t, rm)

			got := map[string]bool{}
			for _, p := range pts {
				if got[p.name] {
					t.Fatalf("series %q emitted more than once", p.name)
				}
				got[p.name] = true
			}

			wantSet := map[string]bool{}
			for _, n := range tc.want {
				wantSet[n] = true
			}
			// The heartbeat rides every collector regardless of groups
			// (registered unconditionally by buildMeterProvider, #1072),
			// so it is part of the emitted set for every case here.
			wantSet[MetricHeartbeat] = true

			if len(got) != len(wantSet) {
				var names []string
				for n := range got {
					names = append(names, n)
				}
				sort.Strings(names)
				t.Fatalf("groups %v emitted %d series %v, want exactly %d", tc.groups, len(got), names, len(wantSet))
			}
			for n := range wantSet {
				if !got[n] {
					t.Errorf("groups %v missing expected series %q", tc.groups, n)
				}
			}
			for n := range got {
				if !wantSet[n] {
					t.Errorf("groups %v emitted unexpected series %q", tc.groups, n)
				}
			}
		})
	}
}

// TestNoTenantLabels asserts every emitted series carries exactly the
// three allowlisted labels and nothing else — no org/tenant identifier —
// even when a hostile Sources snapshot exists. The labels come from the
// collector's fixed identity, not from Sources, so there is structurally
// no channel to inject one; this test locks that in.
func TestNoTenantLabels(t *testing.T) {
	rm := collectOnce(t, &fakeSources{sr: sampleResources()}, sampleLabels())
	pts := flattenGauges(t, rm)
	if len(pts) == 0 {
		t.Fatal("no series emitted")
	}

	// Per-series allowlist: host series carry backend_id/hostname/region;
	// the heartbeat carries backend_id/hostname/daemon_version. Neither
	// may carry any org/tenant identifier.
	hostAllowed := map[string]string{
		LabelBackendID: "backend-xyz",
		LabelHostname:  "host-1",
		LabelRegion:    "us-central1",
	}
	heartbeatAllowed := map[string]string{
		LabelBackendID:     "backend-xyz",
		LabelHostname:      "host-1",
		LabelDaemonVersion: "", // sampleLabels leaves DaemonVersion empty; value asserted in TestHeartbeatLabels.
	}
	forbidden := []string{"org", "org_id", "tenant", "tenant_id", "username", "user", "uuid"}

	for _, p := range pts {
		allowed := hostAllowed
		if p.name == MetricHeartbeat {
			allowed = heartbeatAllowed
		}
		iter := p.attrs.Iter()
		seen := map[string]bool{}
		for iter.Next() {
			kv := iter.Attribute()
			key := string(kv.Key)
			for _, f := range forbidden {
				if key == f {
					t.Errorf("series %q carries forbidden label %q", p.name, key)
				}
			}
			wantVal, ok := allowed[key]
			if !ok {
				t.Errorf("series %q carries non-allowlisted label %q", p.name, key)
				continue
			}
			if kv.Value.AsString() != wantVal {
				t.Errorf("series %q label %q = %q, want %q", p.name, key, kv.Value.AsString(), wantVal)
			}
			seen[key] = true
		}
		if len(seen) != len(allowed) {
			t.Errorf("series %q has %d allowlisted labels, want all %d", p.name, len(seen), len(allowed))
		}
	}
}

// hostSeriesCount counts emitted series that are not the heartbeat — the
// host gauges whose values come from Sources.
func hostSeriesCount(pts []point) int {
	n := 0
	for _, p := range pts {
		if p.name != MetricHeartbeat {
			n++
		}
	}
	return n
}

// TestSourceErrorSkipsTickWithoutPanic asserts that a Sources error mid-
// tick is skipped cleanly: no panic, no crash, and no host series emitted
// for that tick (so no stale values reach the cloud). The heartbeat, which
// does not depend on Sources, still emits — a Sources error is not daemon
// death and must not trip the dead-man alert.
func TestSourceErrorSkipsTickWithoutPanic(t *testing.T) {
	rm := collectOnce(t, &fakeSources{err: errors.New("incus unavailable")}, sampleLabels())
	pts := flattenGauges(t, rm)
	if got := hostSeriesCount(pts); got != 0 {
		t.Fatalf("expected no host series on a Sources error, got %d", got)
	}
	heartbeatOf(t, pts) // heartbeat still present; fails if absent.
}

// TestNilSnapshotSkipsTick guards the nil-without-error edge: a Sources
// that returns (nil, nil) is skipped, not dereferenced — again without
// suppressing the Sources-independent heartbeat.
func TestNilSnapshotSkipsTick(t *testing.T) {
	rm := collectOnce(t, &fakeSources{sr: nil}, sampleLabels())
	pts := flattenGauges(t, rm)
	if got := hostSeriesCount(pts); got != 0 {
		t.Fatalf("expected no host series on a nil snapshot, got %d", got)
	}
	heartbeatOf(t, pts) // heartbeat still present; fails if absent.
}

// recordingExporter is a fake sdkmetric.Exporter that counts Export
// calls and captures the last batch, letting the lifecycle test observe
// a tick and confirm emission stops after Stop.
type recordingExporter struct {
	exports   int
	shutdowns int
	last      metricdata.ResourceMetrics
	failNext  bool
}

func (r *recordingExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return sdkmetric.DefaultTemporalitySelector(k)
}
func (r *recordingExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}
func (r *recordingExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if r.failNext {
		r.failNext = false
		return errors.New("simulated export failure")
	}
	r.exports++
	r.last = *rm
	return nil
}
func (r *recordingExporter) ForceFlush(ctx context.Context) error { return nil }
func (r *recordingExporter) Shutdown(ctx context.Context) error {
	r.shutdowns++
	return nil
}

// TestStartShutsDownReaderWhenProviderBuildFails guards the error path:
// the PeriodicReader starts a goroutine during construction, so a failed
// provider build must shut the reader down before returning.
func TestStartShutsDownReaderWhenProviderBuildFails(t *testing.T) {
	exp := &recordingExporter{}
	c := NewCollector(CollectorOptions{
		Sources:  &fakeSources{sr: sampleResources()},
		Exporter: exp,
		Labels:   sampleLabels(),
	})
	c.groups = []pb.CloudMetricsGroup{pb.CloudMetricsGroup(999)}

	err := c.Start(context.Background())

	if err == nil {
		t.Fatal("expected Start to fail for an unknown metric group")
	}
	if exp.shutdowns != 1 {
		t.Fatalf("exporter Shutdown calls = %d, want 1", exp.shutdowns)
	}
	if c.started {
		t.Fatal("collector marked started after provider build failure")
	}
}

// TestEnableDisableRebuild is the toggle lifecycle: enable → observe
// series via a forced flush → disable → assert the reader is shut down
// and no further observations happen.
func TestEnableDisableRebuild(t *testing.T) {
	ctx := context.Background()
	exp := &recordingExporter{}
	c := NewCollector(CollectorOptions{
		Sources:  &fakeSources{sr: sampleResources()},
		Exporter: exp,
		Labels:   sampleLabels(),
	})

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Start is idempotent.
	if err := c.Start(ctx); err != nil {
		t.Fatalf("second Start: %v", err)
	}

	if err := c.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	if exp.exports == 0 {
		t.Fatal("expected at least one export after ForceFlush")
	}
	exported := flattenGauges(t, exp.last)
	if got := len(exported); got != 9 {
		t.Fatalf("expected 9 series exported (8 host + heartbeat), got %d", got)
	}
	heartbeatOf(t, exported) // the heartbeat rides the same export batch.

	if err := c.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	countAfterStop := exp.exports

	// After disable, a flush is a no-op and no further observations
	// reach the exporter.
	if err := c.ForceFlush(ctx); err != nil {
		t.Fatalf("post-stop ForceFlush: %v", err)
	}
	if exp.exports != countAfterStop {
		t.Fatalf("export happened after Stop: %d -> %d", countAfterStop, exp.exports)
	}
	// Stop is idempotent.
	if err := c.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// TestHealthTracksExportOutcome asserts GetMetricsExport's health fields
// are wired to real export outcomes: a success sets last_success_at and
// clears last_error; a failure increments export_failures and records
// last_error.
func TestHealthTracksExportOutcome(t *testing.T) {
	ctx := context.Background()
	exp := &recordingExporter{}
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
	last, lastErr, fails := c.Health()
	if last.IsZero() {
		t.Error("expected last_success_at set after a successful export")
	}
	if lastErr != "" {
		t.Errorf("expected no last_error after success, got %q", lastErr)
	}
	if fails != 0 {
		t.Errorf("expected 0 failures, got %d", fails)
	}

	exp.failNext = true
	_ = c.ForceFlush(ctx)
	_, lastErr, fails = c.Health()
	if fails != 1 {
		t.Errorf("expected 1 export failure, got %d", fails)
	}
	if lastErr == "" {
		t.Error("expected last_error set after a failed export")
	}
}

// TestIntervalFloor asserts the sub-minute cost guard: a config below the
// floor is clamped up to MinIntervalSeconds.
func TestIntervalFloor(t *testing.T) {
	for _, in := range []int32{0, 1, 30, 59} {
		c := NewCollector(CollectorOptions{IntervalSeconds: in})
		if got := c.interval; got != MinIntervalSeconds*time.Second {
			t.Errorf("IntervalSeconds=%d -> interval %v, want floored to %ds", in, got, MinIntervalSeconds)
		}
	}
	c := NewCollector(CollectorOptions{IntervalSeconds: 120})
	if got := c.interval; got != 120*time.Second {
		t.Errorf("IntervalSeconds=120 -> interval %v, want 120s", got)
	}
}

// samplePlatformSnapshot is a representative, non-trivial API snapshot
// for the platform-series tests below.
func samplePlatformSnapshot() platformstats.APISnapshot {
	return platformstats.APISnapshot{
		RequestsByClass: map[platformstats.CodeClass]int64{
			platformstats.CodeClassOK:          42,
			platformstats.CodeClassClientError: 3,
			platformstats.CodeClassServerError: 1,
		},
		ErrorsByClass: map[platformstats.CodeClass]int64{
			platformstats.CodeClassClientError: 3,
			platformstats.CodeClassServerError: 1,
		},
	}
}

// pointsByNameAndClass indexes flattened points by (series name,
// code_class label value) for easy per-class assertions.
func pointsByNameAndClass(pts []point) map[string]map[string]point {
	out := map[string]map[string]point{}
	for _, p := range pts {
		class, _ := p.attrs.Value(attribute.Key(LabelCodeClass))
		if out[p.name] == nil {
			out[p.name] = map[string]point{}
		}
		out[p.name][class.AsString()] = p
	}
	return out
}

// TestExportedSeries_PlatformAPIHealth is #1082's acceptance criterion:
// enabling the platform group with a wired PlatformSources emits
// containarium.platform.api.requests/.errors, one point per code_class,
// with the exact cumulative values the snapshot reports.
func TestExportedSeries_PlatformAPIHealth(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, &fakePlatformSources{api: samplePlatformSnapshot()}, sampleLabels())
	pts := flattenPoints(t, rm)
	byNameClass := pointsByNameAndClass(pts)

	wantRequests := map[string]int64{"ok": 42, "client_error": 3, "server_error": 1}
	for class, want := range wantRequests {
		p, ok := byNameClass[MetricPlatformAPIRequests][class]
		if !ok {
			t.Fatalf("missing %s{code_class=%q}", MetricPlatformAPIRequests, class)
		}
		if p.ival != want {
			t.Errorf("%s{code_class=%q} = %d, want %d", MetricPlatformAPIRequests, class, p.ival, want)
		}
	}

	// api.errors carries only the error classes — "ok" is never an error
	// and must not appear as a series point at all.
	wantErrors := map[string]int64{"client_error": 3, "server_error": 1}
	for class, want := range wantErrors {
		p, ok := byNameClass[MetricPlatformAPIErrors][class]
		if !ok {
			t.Fatalf("missing %s{code_class=%q}", MetricPlatformAPIErrors, class)
		}
		if p.ival != want {
			t.Errorf("%s{code_class=%q} = %d, want %d", MetricPlatformAPIErrors, class, p.ival, want)
		}
	}
	if _, ok := byNameClass[MetricPlatformAPIErrors]["ok"]; ok {
		t.Errorf("%s must not emit a code_class=ok point (ok is never an error)", MetricPlatformAPIErrors)
	}
}

// TestExportedSeries_PlatformGroupNilSourcesEmitsNothing guards the
// "not wired yet" default: enabling the platform group without a
// PlatformSources must emit zero platform series, never panic.
func TestExportedSeries_PlatformGroupNilSourcesEmitsNothing(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, nil, sampleLabels())
	pts := flattenPoints(t, rm)
	for _, p := range pts {
		if p.name == MetricPlatformAPIRequests || p.name == MetricPlatformAPIErrors {
			t.Errorf("platform series %q emitted with no PlatformSources wired", p.name)
		}
	}
}

// TestNoTenantLabels_PlatformSeries locks in #1082's cardinality
// acceptance criterion: the platform API series carry exactly
// backend_id/hostname/region/code_class and nothing else — no
// per-route, per-user, or per-org label, even though platformstats
// itself has no channel to supply one.
func TestNoTenantLabels_PlatformSeries(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, &fakePlatformSources{api: samplePlatformSnapshot()}, sampleLabels())
	all := flattenPoints(t, rm)

	// Enabling the platform group also emits the always-on heartbeat
	// (buildMeterProvider registers it unconditionally, independent of
	// groups) — it has its own label contract and its own test
	// (TestHeartbeatLabels); only the two platform series belong here.
	var pts []point
	for _, p := range all {
		if p.name == MetricPlatformAPIRequests || p.name == MetricPlatformAPIErrors {
			pts = append(pts, p)
		}
	}
	if len(pts) == 0 {
		t.Fatal("no platform series emitted")
	}

	allowed := map[string]string{
		LabelBackendID: "backend-xyz",
		LabelHostname:  "host-1",
		LabelRegion:    "us-central1",
		// code_class value varies per point; checked separately below.
	}
	forbidden := []string{"org", "org_id", "tenant", "tenant_id", "username", "user", "uuid", "route", "method", "path"}

	for _, p := range pts {
		iter := p.attrs.Iter()
		seen := map[string]bool{}
		for iter.Next() {
			kv := iter.Attribute()
			key := string(kv.Key)
			seen[key] = true
			for _, f := range forbidden {
				if key == f {
					t.Errorf("series %q carries forbidden label %q", p.name, key)
				}
			}
			if key == LabelCodeClass {
				continue // value asserted by TestExportedSeries_PlatformAPIHealth
			}
			if wantVal, ok := allowed[key]; !ok {
				t.Errorf("series %q carries non-allowlisted label %q", p.name, key)
			} else if kv.Value.AsString() != wantVal {
				t.Errorf("series %q label %q = %q, want %q", p.name, key, kv.Value.AsString(), wantVal)
			}
		}
		for want := range allowed {
			if !seen[want] {
				t.Errorf("series %q missing allowlisted label %q", p.name, want)
			}
		}
		if !seen[LabelCodeClass] {
			t.Errorf("series %q missing required label %q", p.name, LabelCodeClass)
		}
	}
}
