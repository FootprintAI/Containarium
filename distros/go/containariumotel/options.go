package containariumotel

import "time"

// Option configures Init. Pass options to Init like:
//
//	containariumotel.Init(ctx,
//	    containariumotel.WithServiceName("payment-api"),
//	    containariumotel.WithMetricInterval(10*time.Second),
//	)
type Option func(*options)

type options struct {
	serviceName    string
	endpointURL    string
	extraAttrs     map[string]string
	metricInterval time.Duration
	metricTimeout  time.Duration
}

// defaultOptions match the central collector / sidecar batch settings
// (5s tick, 10s timeout) so app-side and platform-side timing aren't
// fighting each other.
func defaultOptions() options {
	return options{
		metricInterval: 5 * time.Second,
		metricTimeout:  10 * time.Second,
	}
}

// WithServiceName overrides OTEL_SERVICE_NAME only when env is unset.
// Explicit env always wins — matches the Python distro's setdefault
// behavior. Use this to give a generic library a sensible default
// without stomping on operator-set env.
func WithServiceName(name string) Option {
	return func(o *options) { o.serviceName = name }
}

// WithExtraAttrs merges additional resource attributes at precedence
// layer 5 (above env, below the defended distro stamp). Useful for
// per-deployment attrs that aren't worth a dedicated env var, e.g.
// region or cluster name.
func WithExtraAttrs(attrs map[string]string) Option {
	return func(o *options) { o.extraAttrs = attrs }
}

// WithEndpoint overrides OTEL_EXPORTER_OTLP_METRICS_ENDPOINT (or its
// non-metrics-specific fallback). Accepts a full URL including scheme
// and path; otlpmetrichttp.WithEndpointURL handles parsing.
//
// Useful when the caller talks to a backend with a non-default
// metrics ingest path — VictoriaMetrics' `/opentelemetry/api/v1/push`
// is the canonical example. Most apps should leave this unset and
// configure via OTEL_EXPORTER_OTLP_ENDPOINT instead.
func WithEndpoint(url string) Option {
	return func(o *options) { o.endpointURL = url }
}

// WithMetricInterval sets the periodic export tick. Default 5s.
func WithMetricInterval(d time.Duration) Option {
	return func(o *options) { o.metricInterval = d }
}

// WithMetricTimeout sets the per-export timeout. Default 10s.
func WithMetricTimeout(d time.Duration) Option {
	return func(o *options) { o.metricTimeout = d }
}
