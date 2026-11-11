package metrics

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// auditAnchorCollector is a collector on a manual reader, with only the
// instruments initialised.
func auditAnchorCollector(t *testing.T) (*Collector, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	c := &Collector{
		config:   CollectorConfig{LocalBackendID: "b1"},
		provider: sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)),
		ctx:      context.Background(),
	}
	if err := c.initInstruments(); err != nil {
		t.Fatal(err)
	}
	return c, reader
}

// auditAnchorPoints reads the degraded gauge and the refusals counter; ok is
// false for a metric with no data point.
func auditAnchorPoints(t *testing.T, reader *sdkmetric.ManualReader) (degraded int64, degradedOK bool, refusals int64, refusalsOK bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "containarium.audit.anchor.degraded":
				g := m.Data.(metricdata.Gauge[int64])
				if len(g.DataPoints) > 0 {
					degraded, degradedOK = g.DataPoints[0].Value, true
				}
			case "containarium.audit.anchor.refusals":
				s := m.Data.(metricdata.Sum[int64])
				if !s.IsMonotonic {
					t.Error("containarium.audit.anchor.refusals is not a monotonic counter")
				}
				if len(s.DataPoints) > 0 {
					refusals, refusalsOK = s.DataPoints[0].Value, true
				}
			}
		}
	}
	return degraded, degradedOK, refusals, refusalsOK
}

// #3549: the gauge follows the anchor's refused state on every tick, and the
// counter carries the cumulative refusals without counting one twice.
func TestAuditAnchorMetrics(t *testing.T) {
	c, reader := auditAnchorCollector(t)
	var (
		degraded bool
		refusals int64
	)
	c.SetAuditAnchorFunc(func() (bool, int64) { return degraded, refusals })

	c.recordAuditAnchor()
	if d, ok, _, rok := auditAnchorPoints(t, reader); !ok || d != 0 || rok {
		t.Fatalf("anchoring: degraded=%d (emitted %v), refusals emitted %v; want 0 and no refusals", d, ok, rok)
	}

	degraded, refusals = true, 3
	c.recordAuditAnchor()
	if d, ok, r, rok := auditAnchorPoints(t, reader); !ok || d != 1 || !rok || r != 3 {
		t.Fatalf("refused: degraded=%d (emitted %v), refusals=%d (emitted %v); want 1 and 3", d, ok, r, rok)
	}

	// Same cumulative count on the next tick: nothing new is added.
	c.recordAuditAnchor()
	if _, _, r, _ := auditAnchorPoints(t, reader); r != 3 {
		t.Fatalf("refusals = %d after a tick with no new refusal, want 3", r)
	}

	degraded, refusals = false, 5
	c.recordAuditAnchor()
	if d, _, r, _ := auditAnchorPoints(t, reader); d != 0 || r != 5 {
		t.Fatalf("recovered: degraded=%d refusals=%d, want 0 and 5", d, r)
	}
}

// Without a source (audit logging off) neither metric is emitted.
func TestAuditAnchorMetrics_NoSourceEmitsNothing(t *testing.T) {
	c, reader := auditAnchorCollector(t)
	c.recordAuditAnchor()
	if _, ok, _, rok := auditAnchorPoints(t, reader); ok || rok {
		t.Fatalf("emitted degraded=%v refusals=%v with no source set", ok, rok)
	}
}
