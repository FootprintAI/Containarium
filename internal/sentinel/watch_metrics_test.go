package sentinel

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// #3485: a --watch-spot-vm target's preemptions were only in the journal and
// the opt-in webhook. These tests pin the per-target series on /metrics and on
// the --metrics-export path.

func newWatchMetricsManager(ids ...string) (*Manager, map[string]*fakeRecoveryProvider) {
	m := NewManager(Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}, &fakeRecoveryProvider{})
	providers := map[string]*fakeRecoveryProvider{}
	for _, id := range ids {
		p := &fakeRecoveryProvider{status: StatusRunning}
		providers[id] = p
		m.AddWatchOnlyBackend(id, p)
	}
	return m, providers
}

func TestRenderMetrics_NoWatchTargetsEmitsNoWatchSeries(t *testing.T) {
	m, _ := newWatchMetricsManager()
	out := m.renderMetrics(1, 0)
	for _, unwanted := range []string{"sentinel_watch_target_down", `backend="`} {
		if strings.Contains(out, unwanted) {
			t.Errorf("no watch targets, but output contains %q\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "sentinel_preempted_total 0\n") {
		t.Errorf("primary series must stay unlabeled\n%s", out)
	}
}

func TestRenderMetrics_WatchTargetsCountIndependently(t *testing.T) {
	m, providers := newWatchMetricsManager("host-a", "host-b")
	ctx := context.Background()
	a, b := m.watchOnly[0], m.watchOnly[1]

	// host-a is preempted by event and is still down; host-b is untouched.
	providers["host-a"].status = StatusTerminated
	m.handleWatchOnlyEvent(ctx, a, VMEvent{Type: EventPreempted, Timestamp: time.Unix(1700000000, 0)})
	m.diagnoseAndRecoverWatchOnly(ctx, b)

	out := m.renderMetrics(1, 0)
	for _, want := range []string{
		`sentinel_preempted_total{backend="host-a"} 1`,
		`sentinel_recovered_total{backend="host-a"} 0`,
		`sentinel_watch_target_down{backend="host-a"} 1`,
		`sentinel_watch_target_last_preemption_timestamp_seconds{backend="host-a"} 1700000000`,
		`sentinel_preempted_total{backend="host-b"} 0`,
		`sentinel_watch_target_down{backend="host-b"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, `last_preemption_timestamp_seconds{backend="host-b"}`) {
		t.Errorf("a target never preempted must not report a last-preemption time\n%s", out)
	}
	if n := strings.Count(out, "# TYPE sentinel_preempted_total"); n != 1 {
		t.Errorf("TYPE line for sentinel_preempted_total appears %d times, want 1", n)
	}

	// host-a comes back: down drops to 0, recovered moves once.
	providers["host-a"].status = StatusRunning
	m.diagnoseAndRecoverWatchOnly(ctx, a)
	out = m.renderMetrics(1, 0)
	for _, want := range []string{
		`sentinel_preempted_total{backend="host-a"} 1`,
		`sentinel_recovered_total{backend="host-a"} 1`,
		`sentinel_watch_target_down{backend="host-a"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("after recovery, missing %q\n%s", want, out)
		}
	}
}

// A preemption found only by the status poll (#3377) counts like an event.
func TestRenderMetrics_StatusPollPreemptionIsCounted(t *testing.T) {
	m, providers := newWatchMetricsManager("host-a")
	wb := m.watchOnly[0]
	ctx := context.Background()
	m.diagnoseAndRecoverWatchOnly(ctx, wb)

	providers["host-a"].status = StatusTerminated
	wb.lastStatusCheck = time.Now().Add(-2 * watchOnlyStatusPollInterval)
	m.maybeRetryWatchOnlyRecovery(ctx, wb)

	out := m.renderMetrics(1, 0)
	for _, want := range []string{
		`sentinel_preempted_total{backend="host-a"} 1`,
		`sentinel_watch_target_down{backend="host-a"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
}

func watchPoints(t *testing.T, md *metricdata.Metrics) map[string]int64 {
	t.Helper()
	var dps []metricdata.DataPoint[int64]
	switch d := md.Data.(type) {
	case metricdata.Sum[int64]:
		dps = d.DataPoints
	case metricdata.Gauge[int64]:
		dps = d.DataPoints
	default:
		t.Fatalf("%s is %T", md.Name, md.Data)
	}
	got := map[string]int64{}
	for _, dp := range dps {
		if v, ok := dp.Attributes.Value("backend"); ok {
			got[v.AsString()] = dp.Value
		}
	}
	return got
}

func TestMetricsExport_WatchTargetsCarryABackendAttribute(t *testing.T) {
	m, providers := newWatchMetricsManager("host-a", "host-b")
	ctx := context.Background()
	providers["host-a"].status = StatusTerminated
	m.handleWatchOnlyEvent(ctx, m.watchOnly[0], VMEvent{Type: EventPreempted, Timestamp: time.Unix(1700000000, 0)})

	ms := collectOnce(t, m, "sentinel-test")

	pre := findMetric(ms, metricSentinelPreempted)
	if pre == nil {
		t.Fatalf("missing %s", metricSentinelPreempted)
	}
	if got := watchPoints(t, pre); got["host-a"] != 1 || got["host-b"] != 0 || len(got) != 2 {
		t.Errorf("preempted per backend = %v, want host-a:1 host-b:0", got)
	}
	// The primary's unlabeled datapoint is still there alongside them.
	if s := pre.Data.(metricdata.Sum[int64]); len(s.DataPoints) != 3 {
		t.Errorf("preempted has %d datapoints, want primary + 2 targets", len(s.DataPoints))
	}

	rec := findMetric(ms, metricSentinelRecovered)
	if rec == nil || len(watchPoints(t, rec)) != 2 {
		t.Errorf("recovered must carry a datapoint per target: %+v", rec)
	}

	down := findMetric(ms, metricSentinelWatchTargetDown)
	if down == nil {
		t.Fatalf("missing %s", metricSentinelWatchTargetDown)
	}
	if got := watchPoints(t, down); got["host-a"] != 1 || got["host-b"] != 0 {
		t.Errorf("down per backend = %v, want host-a:1 host-b:0", got)
	}

	last := findMetric(ms, metricSentinelWatchTargetLastPreempt)
	if last == nil {
		t.Fatalf("missing %s", metricSentinelWatchTargetLastPreempt)
	}
	if got := watchPoints(t, last); got["host-a"] != 1700000000 || len(got) != 1 {
		t.Errorf("last preemption = %v, want only host-a:1700000000", got)
	}
}

func TestMetricsExport_NoWatchTargetsAddsNoSeries(t *testing.T) {
	m, _ := newWatchMetricsManager()
	ms := collectOnce(t, m, "sentinel-test")
	if md := findMetric(ms, metricSentinelWatchTargetDown); md != nil {
		if len(watchPoints(t, md)) != 0 {
			t.Errorf("no targets, but %s has datapoints", md.Name)
		}
	}
	// Unchanged single-datapoint primary counter.
	if got := sumValue(t, findMetric(ms, metricSentinelPreempted)); got != 0 {
		t.Errorf("primary preempted = %d, want 0", got)
	}
}
