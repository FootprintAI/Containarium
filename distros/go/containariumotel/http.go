package containariumotel

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
)

// HTTPMiddleware wraps next with the standard OTel HTTP server
// instrumentation, plus Containarium's opinionated defaults. It's
// otelhttp.NewHandler under the hood — the value of re-exporting
// it here is discoverability (one import path for the distro) and
// the few defaults pre-applied.
//
//	mux := http.NewServeMux()
//	mux.Handle("/api", containariumotel.HTTPMiddleware(myAPIHandler))
//
// Pass additional otelhttp.Option values to override defaults
// (operation name formatter, span name, filter functions). User
// options follow ours in the slice, so they win on conflict.
func HTTPMiddleware(next http.Handler, opts ...otelhttp.Option) http.Handler {
	defaults := []otelhttp.Option{
		otelhttp.WithMeterProvider(otel.GetMeterProvider()),
		otelhttp.WithTracerProvider(otel.GetTracerProvider()),
		otelhttp.WithMessageEvents(otelhttp.ReadEvents, otelhttp.WriteEvents),
	}
	return otelhttp.NewHandler(next, "containarium-http-server",
		append(defaults, opts...)...)
}
