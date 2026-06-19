package server

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"

	"github.com/footprintai/containarium/internal/modelgateway"
)

// gatewayOTLPSink is the model-gateway's metering→billing writer (#674
// increment 3): it implements modelgateway.UsageSink by emitting per-tenant /
// skill / provider / model token counters through the daemon's OTel meter, so
// model-call usage flows the same pipeline as every other metric (OTLP →
// VictoriaMetrics → dashboards / billing). The in-memory Meter still backs
// /__gateway/usage for a live readout; this is the durable, aggregatable side.
//
// Uses the GLOBAL meter provider: when monitoring is enabled it exports; when
// not, the global is a no-op provider and every Add is a cheap no-op — so the
// sink is always safe to wire.
type gatewayOTLPSink struct {
	calls  otelmetric.Int64Counter
	input  otelmetric.Int64Counter
	output otelmetric.Int64Counter
	cached otelmetric.Int64Counter
}

// newGatewayOTLPSink builds the counters from the global OTel meter. Returns an
// error only if instrument creation fails (it shouldn't for a valid provider);
// the caller logs and falls back to in-memory-only metering.
func newGatewayOTLPSink() (*gatewayOTLPSink, error) {
	meter := otel.GetMeterProvider().Meter("containarium")
	calls, err := meter.Int64Counter("model_gateway.calls",
		otelmetric.WithDescription("Model-gateway calls brokered, by tenant/skill/provider/model"))
	if err != nil {
		return nil, err
	}
	input, err := meter.Int64Counter("model_gateway.input_tokens",
		otelmetric.WithDescription("Model-gateway input tokens"), otelmetric.WithUnit("{token}"))
	if err != nil {
		return nil, err
	}
	output, err := meter.Int64Counter("model_gateway.output_tokens",
		otelmetric.WithDescription("Model-gateway output tokens"), otelmetric.WithUnit("{token}"))
	if err != nil {
		return nil, err
	}
	cached, err := meter.Int64Counter("model_gateway.cached_tokens",
		otelmetric.WithDescription("Model-gateway cached (prompt-cache) tokens"), otelmetric.WithUnit("{token}"))
	if err != nil {
		return nil, err
	}
	return &gatewayOTLPSink{calls: calls, input: input, output: output, cached: cached}, nil
}

// RecordUsage emits one call + its token counts, attributed for per-tenant
// billing rollups. Skipped attributes (empty skill/model) are omitted so the
// series cardinality stays bounded.
func (s *gatewayOTLPSink) RecordUsage(tenant, skill, provider string, u modelgateway.Usage) {
	attrs := []attribute.KeyValue{
		attribute.String("tenant", tenant),
		attribute.String("provider", provider),
	}
	if skill != "" {
		attrs = append(attrs, attribute.String("skill", skill))
	}
	if u.Model != "" {
		attrs = append(attrs, attribute.String("model", u.Model))
	}
	set := otelmetric.WithAttributes(attrs...)
	ctx := context.Background()
	s.calls.Add(ctx, 1, set)
	if u.InputTokens > 0 {
		s.input.Add(ctx, u.InputTokens, set)
	}
	if u.OutputTokens > 0 {
		s.output.Add(ctx, u.OutputTokens, set)
	}
	if u.CachedTokens > 0 {
		s.cached.Add(ctx, u.CachedTokens, set)
	}
}

// compile-time assertion: gatewayOTLPSink satisfies modelgateway.UsageSink.
var _ modelgateway.UsageSink = (*gatewayOTLPSink)(nil)
