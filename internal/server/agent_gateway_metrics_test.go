package server

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/footprintai/containarium/internal/modelgateway"
)

// TestGatewayOTLPSink_EmitsTokenCounters wires a manual-reader MeterProvider as
// the global, builds the sink, records one usage, and asserts the token counters
// carry the right value + per-tenant attribution (#674 increment 3).
func TestGatewayOTLPSink_EmitsTokenCounters(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	sink, err := newGatewayOTLPSink()
	if err != nil {
		t.Fatalf("newGatewayOTLPSink: %v", err)
	}
	sink.RecordUsage("acme", "s1", "anthropic", modelgateway.Usage{
		Model: "claude-test", InputTokens: 12, OutputTokens: 4, CachedTokens: 2,
	})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]int64{
		"model_gateway.calls":         1,
		"model_gateway.input_tokens":  12,
		"model_gateway.output_tokens": 4,
		"model_gateway.cached_tokens": 2,
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
				for _, dp := range sum.DataPoints {
					got[m.Name] = dp.Value
					// Attribution must be present for billing rollups.
					if m.Name == "model_gateway.input_tokens" {
						assertAttr(t, dp, "tenant", "acme")
						assertAttr(t, dp, "skill", "s1")
						assertAttr(t, dp, "provider", "anthropic")
						assertAttr(t, dp, "model", "claude-test")
					}
				}
			}
		}
	}
	for name, wantVal := range want {
		if got[name] != wantVal {
			t.Errorf("%s = %d, want %d", name, got[name], wantVal)
		}
	}
}

func assertAttr(t *testing.T, dp metricdata.DataPoint[int64], key, want string) {
	t.Helper()
	v, ok := dp.Attributes.Value(attribute.Key(key))
	if !ok || v.AsString() != want {
		t.Errorf("attribute %s = %q (present=%v), want %q", key, v.AsString(), ok, want)
	}
}
