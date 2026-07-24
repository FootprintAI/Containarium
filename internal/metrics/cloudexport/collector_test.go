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

// fakeSources is a Sources whose SystemResources/AllContainerMetrics
// snapshots and errors are fully controlled by the test.
type fakeSources struct {
	sr  *SystemResources
	err error

	containers    map[string]*pb.ContainerMetrics
	containersErr error
}

func (f *fakeSources) SystemResources(ctx context.Context) (*SystemResources, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.sr, nil
}

func (f *fakeSources) AllContainerMetrics(ctx context.Context) (map[string]*pb.ContainerMetrics, error) {
	if f.containersErr != nil {
		return nil, f.containersErr
	}
	return f.containers, nil
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

// fakePlatformSources is a PlatformSources whose snapshots are fully
// controlled by the test.
type fakePlatformSources struct {
	api       platformstats.APISnapshot
	provision platformstats.ProvisionSnapshot
	peers     []PeerState
}

func (f *fakePlatformSources) APIStats() platformstats.APISnapshot {
	return f.api
}

func (f *fakePlatformSources) ProvisionStats() platformstats.ProvisionSnapshot {
	return f.provision
}

func (f *fakePlatformSources) Peers() []PeerState {
	return f.peers
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
			case metricdata.Sum[float64]:
				for _, dp := range g.DataPoints {
					pts = append(pts, point{name: m.Name, fval: dp.Value, attrs: dp.Attributes})
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
	exports  int
	last     metricdata.ResourceMetrics
	failNext bool
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
func (r *recordingExporter) Shutdown(ctx context.Context) error   { return nil }

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

// sampleProvisionSnapshot is a representative, non-trivial provisioning
// snapshot for the tests below — mirrors what Stats.SnapshotProvision()
// always returns: both operations present, even one with zero failures.
func sampleProvisionSnapshot() platformstats.ProvisionSnapshot {
	return platformstats.ProvisionSnapshot{
		Attempts: map[platformstats.Operation]int64{
			platformstats.OperationCreate: 10,
			platformstats.OperationDelete: 4,
		},
		Failures: map[platformstats.Operation]int64{
			platformstats.OperationCreate: 2,
			platformstats.OperationDelete: 0,
		},
		DurationSecondsSum: map[platformstats.Operation]float64{
			platformstats.OperationCreate: 55.5,
			platformstats.OperationDelete: 8.0,
		},
	}
}

// pointsByNameAndOperation indexes flattened points by (series name,
// operation label value), the provisioning-series analog of
// pointsByNameAndClass.
func pointsByNameAndOperation(pts []point) map[string]map[string]point {
	out := map[string]map[string]point{}
	for _, p := range pts {
		op, _ := p.attrs.Value(attribute.Key(LabelOperation))
		if out[p.name] == nil {
			out[p.name] = map[string]point{}
		}
		out[p.name][op.AsString()] = p
	}
	return out
}

// TestExportedSeries_PlatformProvisionOutcome is #1083's acceptance
// criterion: enabling the platform group with a wired PlatformSources
// emits containarium.platform.provision.attempts/.failures/
// .duration_seconds_sum, one point per operation, with the exact
// cumulative values the snapshot reports — including a zero-failure
// operation (delete), which must still appear as an explicit 0 point,
// not be silently absent.
func TestExportedSeries_PlatformProvisionOutcome(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, &fakePlatformSources{provision: sampleProvisionSnapshot()}, sampleLabels())
	pts := flattenPoints(t, rm)
	byNameOp := pointsByNameAndOperation(pts)

	wantAttempts := map[string]int64{"create": 10, "delete": 4}
	for op, want := range wantAttempts {
		p, ok := byNameOp[MetricPlatformProvisionAttempts][op]
		if !ok {
			t.Fatalf("missing %s{operation=%q}", MetricPlatformProvisionAttempts, op)
		}
		if p.ival != want {
			t.Errorf("%s{operation=%q} = %d, want %d", MetricPlatformProvisionAttempts, op, p.ival, want)
		}
	}

	wantFailures := map[string]int64{"create": 2, "delete": 0}
	for op, want := range wantFailures {
		p, ok := byNameOp[MetricPlatformProvisionFailures][op]
		if !ok {
			t.Fatalf("missing %s{operation=%q} — a zero-failure operation must still emit an explicit 0 point", MetricPlatformProvisionFailures, op)
		}
		if p.ival != want {
			t.Errorf("%s{operation=%q} = %d, want %d", MetricPlatformProvisionFailures, op, p.ival, want)
		}
	}

	wantDuration := map[string]float64{"create": 55.5, "delete": 8.0}
	for op, want := range wantDuration {
		p, ok := byNameOp[MetricPlatformProvisionDurationSecondsSum][op]
		if !ok {
			t.Fatalf("missing %s{operation=%q}", MetricPlatformProvisionDurationSecondsSum, op)
		}
		if p.fval != want {
			t.Errorf("%s{operation=%q} = %v, want %v", MetricPlatformProvisionDurationSecondsSum, op, p.fval, want)
		}
	}
}

// TestExportedSeries_PlatformGroup_ProvisionZeroWhenNotWired guards the
// "not wired yet" default for the provisioning series specifically: a
// PlatformSources whose ProvisionStats returns the zero value (as an
// older adapter or a minimal fake might) must not panic and must not
// fabricate an operation the snapshot didn't report.
func TestExportedSeries_PlatformGroup_ProvisionZeroWhenNotWired(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, &fakePlatformSources{}, sampleLabels())
	pts := flattenPoints(t, rm)
	for _, p := range pts {
		switch p.name {
		case MetricPlatformProvisionAttempts, MetricPlatformProvisionFailures, MetricPlatformProvisionDurationSecondsSum:
			t.Errorf("provisioning series %q emitted a point from a zero-value ProvisionSnapshot", p.name)
		}
	}
}

// TestNoTenantLabels_ProvisionSeries locks in #1083's cardinality
// acceptance criterion: the provisioning series carry exactly
// backend_id/hostname/region/operation and nothing else.
func TestNoTenantLabels_ProvisionSeries(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, &fakePlatformSources{provision: sampleProvisionSnapshot()}, sampleLabels())
	all := flattenPoints(t, rm)

	var pts []point
	for _, p := range all {
		switch p.name {
		case MetricPlatformProvisionAttempts, MetricPlatformProvisionFailures, MetricPlatformProvisionDurationSecondsSum:
			pts = append(pts, p)
		}
	}
	if len(pts) == 0 {
		t.Fatal("no provisioning series emitted")
	}

	allowed := map[string]string{
		LabelBackendID: "backend-xyz",
		LabelHostname:  "host-1",
		LabelRegion:    "us-central1",
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
			if key == LabelOperation {
				continue // value asserted by TestExportedSeries_PlatformProvisionOutcome
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
		if !seen[LabelOperation] {
			t.Errorf("series %q missing required label %q", p.name, LabelOperation)
		}
	}
}

// sampleConnectivitySnapshot is a representative peer snapshot for the
// tests below: one healthy peer, one unhealthy — so both tunnel.state
// values (1 and 0) and a partial peers.connected count are exercised in
// one fixture.
func sampleConnectivitySnapshot() []PeerState {
	return []PeerState{
		{ID: "byoc-host-a", Healthy: true},
		{ID: "byoc-host-b", Healthy: false},
	}
}

// pointsByNameAndPeer indexes flattened points by (series name, peer_id
// label value), the connectivity-series analog of pointsByNameAndClass /
// pointsByNameAndOperation. Points with no peer_id label (peers.connected)
// are indexed under the empty string.
func pointsByNameAndPeer(pts []point) map[string]map[string]point {
	out := map[string]map[string]point{}
	for _, p := range pts {
		peerID, _ := p.attrs.Value(attribute.Key(LabelPeerID))
		if out[p.name] == nil {
			out[p.name] = map[string]point{}
		}
		out[p.name][peerID.AsString()] = p
	}
	return out
}

// TestExportedSeries_PlatformConnectivity is #1084's acceptance
// criterion: enabling the platform group with a wired PlatformSources
// emits containarium.platform.peers.connected as the count of healthy
// peers, and containarium.platform.tunnel.state as one 0/1 point per
// registered peer, keyed by peer_id.
func TestExportedSeries_PlatformConnectivity(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, &fakePlatformSources{peers: sampleConnectivitySnapshot()}, sampleLabels())
	pts := flattenPoints(t, rm)
	byNamePeer := pointsByNameAndPeer(pts)

	connected, ok := byNamePeer[MetricPlatformPeersConnected][""]
	if !ok {
		t.Fatalf("missing %s", MetricPlatformPeersConnected)
	}
	if connected.ival != 1 {
		t.Errorf("%s = %d, want 1 (one healthy peer of two)", MetricPlatformPeersConnected, connected.ival)
	}

	wantTunnelState := map[string]int64{"byoc-host-a": 1, "byoc-host-b": 0}
	for peerID, want := range wantTunnelState {
		p, ok := byNamePeer[MetricPlatformTunnelState][peerID]
		if !ok {
			t.Fatalf("missing %s{peer_id=%q} — an unhealthy peer must still emit an explicit 0 point", MetricPlatformTunnelState, peerID)
		}
		if p.ival != want {
			t.Errorf("%s{peer_id=%q} = %d, want %d", MetricPlatformTunnelState, peerID, p.ival, want)
		}
	}
}

// TestTunnelState_FlipsOnHealthChange locks in the issue's literal
// acceptance criterion at the collector level: a peer flipping from
// healthy to unhealthy (and back) between two ticks flips its
// tunnel.state point accordingly, and peers.connected moves with it.
// The real end-to-end timing (a stopped tunnel reflected within 2 export
// intervals) is a live property of the peer-pool health check + export
// cadence, not reproducible in a unit test — this pins the collector's
// half of that contract: it always reports whatever PlatformSources
// currently says, with no caching or debouncing of its own.
func TestTunnelState_FlipsOnHealthChange(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	src := &fakePlatformSources{peers: []PeerState{{ID: "byoc-host-a", Healthy: true}}}

	reader := sdkmetric.NewManualReader()
	c := NewCollector(CollectorOptions{Sources: &fakeSources{sr: sampleResources()}, PlatformSources: src, Labels: sampleLabels(), Groups: []pb.CloudMetricsGroup{platform}})
	mp, err := c.buildMeterProvider(reader)
	if err != nil {
		t.Fatalf("buildMeterProvider: %v", err)
	}
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect (tick 1): %v", err)
	}
	byNamePeer := pointsByNameAndPeer(flattenPoints(t, rm))
	if p := byNamePeer[MetricPlatformTunnelState]["byoc-host-a"]; p.ival != 1 {
		t.Fatalf("tick 1: tunnel.state = %d, want 1 (healthy)", p.ival)
	}
	if p := byNamePeer[MetricPlatformPeersConnected][""]; p.ival != 1 {
		t.Fatalf("tick 1: peers.connected = %d, want 1", p.ival)
	}

	// Tunnel drops.
	src.peers = []PeerState{{ID: "byoc-host-a", Healthy: false}}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect (tick 2): %v", err)
	}
	byNamePeer = pointsByNameAndPeer(flattenPoints(t, rm))
	if p := byNamePeer[MetricPlatformTunnelState]["byoc-host-a"]; p.ival != 0 {
		t.Fatalf("tick 2: tunnel.state = %d, want 0 (dropped)", p.ival)
	}
	if p := byNamePeer[MetricPlatformPeersConnected][""]; p.ival != 0 {
		t.Fatalf("tick 2: peers.connected = %d, want 0", p.ival)
	}

	// Tunnel reconnects.
	src.peers = []PeerState{{ID: "byoc-host-a", Healthy: true}}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect (tick 3): %v", err)
	}
	byNamePeer = pointsByNameAndPeer(flattenPoints(t, rm))
	if p := byNamePeer[MetricPlatformTunnelState]["byoc-host-a"]; p.ival != 1 {
		t.Fatalf("tick 3: tunnel.state = %d, want 1 (reconnected)", p.ival)
	}
	if p := byNamePeer[MetricPlatformPeersConnected][""]; p.ival != 1 {
		t.Fatalf("tick 3: peers.connected = %d, want 1", p.ival)
	}
}

// TestExportedSeries_PlatformGroup_ConnectivityZeroWhenNotWired guards
// the zero-peers default: a PlatformSources whose Peers() returns nil
// (an older adapter, or a backend with no registered peers) must not
// panic. peers.connected is a scalar summary — unlike the per-key
// provisioning series, there is no key to fabricate or omit — so it
// still emits an explicit 0; tunnel.state has no peer to report and
// emits nothing.
func TestExportedSeries_PlatformGroup_ConnectivityZeroWhenNotWired(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, &fakePlatformSources{}, sampleLabels())
	pts := flattenPoints(t, rm)
	byNamePeer := pointsByNameAndPeer(pts)

	connected, ok := byNamePeer[MetricPlatformPeersConnected][""]
	if !ok {
		t.Fatalf("missing %s — must still emit an explicit 0 with zero peers", MetricPlatformPeersConnected)
	}
	if connected.ival != 0 {
		t.Errorf("%s = %d, want 0", MetricPlatformPeersConnected, connected.ival)
	}

	for _, p := range pts {
		if p.name == MetricPlatformTunnelState {
			t.Errorf("tunnel.state emitted a point %+v with zero registered peers", p)
		}
	}
}

// TestNoTenantLabels_ConnectivitySeries locks in #1084's cardinality
// acceptance criterion: peers.connected carries exactly backend_id/
// hostname/region (no peer_id — it is a backend-wide scalar);
// tunnel.state carries exactly backend_id/hostname/region/peer_id, and
// peer_id is always the enrolled host name passed in by PlatformSources,
// never an org/tenant identifier.
func TestNoTenantLabels_ConnectivitySeries(t *testing.T) {
	platform := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{platform}, &fakeSources{sr: sampleResources()}, &fakePlatformSources{peers: sampleConnectivitySnapshot()}, sampleLabels())
	all := flattenPoints(t, rm)

	forbidden := []string{"org", "org_id", "tenant", "tenant_id", "username", "user", "uuid", "route", "method", "path"}
	baseAllowed := map[string]string{
		LabelBackendID: "backend-xyz",
		LabelHostname:  "host-1",
		LabelRegion:    "us-central1",
	}
	validPeerIDs := map[string]bool{"byoc-host-a": true, "byoc-host-b": true}

	var sawConnected, sawTunnel bool
	for _, p := range all {
		switch p.name {
		case MetricPlatformPeersConnected:
			sawConnected = true
		case MetricPlatformTunnelState:
			sawTunnel = true
		default:
			continue
		}

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
			if key == LabelPeerID {
				if p.name == MetricPlatformPeersConnected {
					t.Errorf("%s carries peer_id label — it is a backend-wide scalar", MetricPlatformPeersConnected)
				}
				if !validPeerIDs[kv.Value.AsString()] {
					t.Errorf("%s peer_id = %q, want one of the enrolled peer IDs the fixture passed in", p.name, kv.Value.AsString())
				}
				continue
			}
			if wantVal, ok := baseAllowed[key]; !ok {
				t.Errorf("series %q carries non-allowlisted label %q", p.name, key)
			} else if kv.Value.AsString() != wantVal {
				t.Errorf("series %q label %q = %q, want %q", p.name, key, kv.Value.AsString(), wantVal)
			}
		}
		for want := range baseAllowed {
			if !seen[want] {
				t.Errorf("series %q missing allowlisted label %q", p.name, want)
			}
		}
		if p.name == MetricPlatformTunnelState && !seen[LabelPeerID] {
			t.Errorf("series %q missing required label %q", p.name, LabelPeerID)
		}
	}
	if !sawConnected {
		t.Fatal("no peers.connected series emitted")
	}
	if !sawTunnel {
		t.Fatal("no tunnel.state series emitted")
	}
}

// sampleContainerMetrics is a representative two-container fixture for
// the #1071 container-series tests below.
func sampleContainerMetrics() map[string]*pb.ContainerMetrics {
	return map[string]*pb.ContainerMetrics{
		"alice-container": {
			Name:             "alice-container",
			CpuUsageSeconds:  120,
			MemoryUsageBytes: 256 << 20,
			DiskUsageBytes:   2 << 30,
			NetworkRxBytes:   1000,
			NetworkTxBytes:   500,
		},
		"bob-container": {
			Name:             "bob-container",
			CpuUsageSeconds:  30,
			MemoryUsageBytes: 128 << 20,
			DiskUsageBytes:   1 << 30,
			NetworkRxBytes:   200,
			NetworkTxBytes:   100,
		},
	}
}

// containerMetricNames is the complete #1071 per-container instrument
// allowlist, used to filter the always-on heartbeat (and, in these
// container-only-group tests, nothing else) out of flattened points.
var containerMetricNames = map[string]bool{
	MetricContainerCPUUsageSeconds:  true,
	MetricContainerMemoryUsageBytes: true,
	MetricContainerDiskUsageBytes:   true,
	MetricContainerNetworkRxBytes:   true,
	MetricContainerNetworkTxBytes:   true,
}

// pointsByNameAndContainer indexes flattened points by (series name,
// container_name label value), the container-series analog of
// pointsByNameAndOperation / pointsByNameAndPeer.
func pointsByNameAndContainer(pts []point) map[string]map[string]point {
	out := map[string]map[string]point{}
	for _, p := range pts {
		name, _ := p.attrs.Value(attribute.Key(LabelContainerName))
		if out[p.name] == nil {
			out[p.name] = map[string]point{}
		}
		out[p.name][name.AsString()] = p
	}
	return out
}

// TestExportedSeries_ContainerGolden is #1071's acceptance criterion:
// enabling the container group with a wired Sources emits all five
// per-container series, one point per running container, with the exact
// values AllContainerMetrics reports.
func TestExportedSeries_ContainerGolden(t *testing.T) {
	containerGroup := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{containerGroup}, &fakeSources{containers: sampleContainerMetrics()}, nil, sampleLabels())
	pts := flattenPoints(t, rm)
	byNameContainer := pointsByNameAndContainer(pts)

	type want struct{ cpu, mem, disk, rx, tx int64 }
	wants := map[string]want{
		"alice-container": {cpu: 120, mem: 256 << 20, disk: 2 << 30, rx: 1000, tx: 500},
		"bob-container":   {cpu: 30, mem: 128 << 20, disk: 1 << 30, rx: 200, tx: 100},
	}

	for containerName, w := range wants {
		checks := []struct {
			metric string
			want   int64
		}{
			{MetricContainerCPUUsageSeconds, w.cpu},
			{MetricContainerMemoryUsageBytes, w.mem},
			{MetricContainerDiskUsageBytes, w.disk},
			{MetricContainerNetworkRxBytes, w.rx},
			{MetricContainerNetworkTxBytes, w.tx},
		}
		for _, c := range checks {
			p, ok := byNameContainer[c.metric][containerName]
			if !ok {
				t.Errorf("missing %s{container_name=%q}", c.metric, containerName)
				continue
			}
			if p.ival != c.want {
				t.Errorf("%s{container_name=%q} = %d, want %d", c.metric, containerName, p.ival, c.want)
			}
		}
	}

	var total int
	for metricName, byContainer := range byNameContainer {
		if containerMetricNames[metricName] {
			total += len(byContainer)
		}
	}
	if total != 10 {
		t.Errorf("got %d container-series points, want 10 (2 containers x 5 series)", total)
	}
}

// TestDeletedContainerSeriesStop is the design doc's explicit acceptance
// criterion: a container that disappears from AllContainerMetrics (i.e.
// was deleted) stops emitting at the very next observation — collection
// re-enumerates live containers every tick, so there is no separate
// deletion-tracking state to get stale.
func TestDeletedContainerSeriesStop(t *testing.T) {
	containerGroup := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER
	src := &fakeSources{containers: sampleContainerMetrics()}

	reader := sdkmetric.NewManualReader()
	c := NewCollector(CollectorOptions{Sources: src, Labels: sampleLabels(), Groups: []pb.CloudMetricsGroup{containerGroup}})
	mp, err := c.buildMeterProvider(reader)
	if err != nil {
		t.Fatalf("buildMeterProvider: %v", err)
	}
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect (tick 1): %v", err)
	}
	byNameContainer := pointsByNameAndContainer(flattenPoints(t, rm))
	if _, ok := byNameContainer[MetricContainerCPUUsageSeconds]["bob-container"]; !ok {
		t.Fatal("tick 1: expected bob-container present before deletion")
	}

	// bob-container is deleted: the next tick's AllContainerMetrics no
	// longer reports it.
	src.containers = map[string]*pb.ContainerMetrics{
		"alice-container": sampleContainerMetrics()["alice-container"],
	}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect (tick 2): %v", err)
	}
	byNameContainer = pointsByNameAndContainer(flattenPoints(t, rm))
	for metricName := range containerMetricNames {
		if _, ok := byNameContainer[metricName]["bob-container"]; ok {
			t.Errorf("tick 2: %s still reports deleted container bob-container", metricName)
		}
		if _, ok := byNameContainer[metricName]["alice-container"]; !ok {
			t.Errorf("tick 2: %s missing still-live container alice-container", metricName)
		}
	}
}

// TestNoTenantLabels_ContainerSeries locks in #1071's cardinality
// acceptance criterion: container series carry exactly backend_id +
// container_name — deliberately narrower than the host/platform series'
// backend_id/hostname/region, per the design doc's label table.
func TestNoTenantLabels_ContainerSeries(t *testing.T) {
	containerGroup := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{containerGroup}, &fakeSources{containers: sampleContainerMetrics()}, nil, sampleLabels())
	all := flattenPoints(t, rm)

	var pts []point
	for _, p := range all {
		if containerMetricNames[p.name] {
			pts = append(pts, p)
		}
	}
	if len(pts) == 0 {
		t.Fatal("no container series emitted")
	}

	allowed := map[string]string{LabelBackendID: "backend-xyz"}
	forbidden := []string{
		"org", "org_id", "tenant", "tenant_id", "username", "user", "uuid", "route", "method", "path",
		// Container series are deliberately narrower than host/platform:
		// no hostname/region.
		LabelHostname, LabelRegion,
	}

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
			if key == LabelContainerName {
				continue // value asserted by TestExportedSeries_ContainerGolden
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
		if !seen[LabelContainerName] {
			t.Errorf("series %q missing required label %q", p.name, LabelContainerName)
		}
	}
}

// TestContainerGroup_SourcesErrorSkipsTickWithoutPanic mirrors the host
// series' TestSourceErrorSkipsTickWithoutPanic: an AllContainerMetrics
// error is skipped cleanly for that tick — no panic, no stale points —
// without suppressing the Sources-independent heartbeat.
func TestContainerGroup_SourcesErrorSkipsTickWithoutPanic(t *testing.T) {
	containerGroup := pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER
	rm := collectGroupsOnce(t, []pb.CloudMetricsGroup{containerGroup}, &fakeSources{containersErr: errors.New("incus unavailable")}, nil, sampleLabels())
	pts := flattenPoints(t, rm)

	for _, p := range pts {
		if containerMetricNames[p.name] {
			t.Errorf("expected no container series on an AllContainerMetrics error, got %q", p.name)
		}
	}
	heartbeatOf(t, pts) // heartbeat still present; fails if absent.
}
