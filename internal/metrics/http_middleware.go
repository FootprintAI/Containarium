package metrics

import (
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/footprintai/containarium/internal/httpx"
)

// HTTPMetricsMiddleware wraps an HTTP handler to record request metrics
func HTTPMetricsMiddleware(next http.Handler, provider *sdkmetric.MeterProvider) http.Handler {
	if provider == nil {
		return next
	}

	meter := provider.Meter("containarium.api")

	requestsTotal, err := meter.Int64Counter("containarium.api.requests_total",
		otelmetric.WithDescription("Total number of HTTP requests"))
	if err != nil {
		return next
	}

	requestDuration, err := meter.Float64Histogram("containarium.api.request_duration_seconds",
		otelmetric.WithDescription("HTTP request duration in seconds"),
		otelmetric.WithUnit("s"),
		otelmetric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
	)
	if err != nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// httpx.StatusWriter captures the status and, through Unwrap,
		// keeps the real writer's Flusher reachable for server-streaming
		// responses (#2773).
		rw := httpx.NewStatusWriter(w)

		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()

		attrs := otelmetric.WithAttributes(
			attribute.String("method", r.Method),
			attribute.String("route", r.URL.Path),
			attribute.String("status_code", fmt.Sprintf("%d", rw.StatusCode)),
		)

		requestsTotal.Add(r.Context(), 1, attrs)
		requestDuration.Record(r.Context(), duration, attrs)
	})
}
