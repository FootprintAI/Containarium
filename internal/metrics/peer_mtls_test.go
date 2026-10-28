package metrics

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func peerMTLSValue(t *testing.T, enabled bool, set bool) (int64, bool) {
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
	if set {
		c.SetPeerMTLSFunc(func() bool { return enabled })
	}
	c.recordPeerMTLS()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "containarium.peer.mtls.enabled" {
				continue
			}
			g := m.Data.(metricdata.Gauge[int64])
			return g.DataPoints[0].Value, true
		}
	}
	return 0, false
}

func TestPeerMTLSGauge(t *testing.T) {
	if v, ok := peerMTLSValue(t, true, true); !ok || v != 1 {
		t.Fatalf("enabled: got %d,%v want 1", v, ok)
	}
	if v, ok := peerMTLSValue(t, false, true); !ok || v != 0 {
		t.Fatalf("disabled: got %d,%v want 0", v, ok)
	}
	if _, ok := peerMTLSValue(t, false, false); ok {
		t.Fatal("no hook set must emit nothing")
	}
}
