package sentinel

import (
	"context"
	"fmt"
	"math"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/footprintai/containarium/internal/metrics/cloudexport"
)

// Sentinel metrics export (#1358).
//
// #1351 put process-health series on /metrics and #1358's first half added the
// failover series, but nothing scrapes that endpoint — and nothing on the spot
// VM can. The bundled monitoring stack (VictoriaMetrics + vmalert +
// Alertmanager) runs in a container ON the backend, so it dies with the very
// outage worth observing. That is the same argument observability.go already
// makes for why the sentinel owns the preemption signal; it applies just as
// well to the sentinel's own health.
//
// So the always-on sentinel pushes to Cloud Monitoring itself. Push, not
// scrape: it needs no inbound firewall rule for the internal-only binary-server
// port, and it keeps reporting while the backend is gone.
//
// Only the Sink is reused from the daemon's export path. The
// CloudExportCollector itself is daemon-shaped — its Sources interface wants
// per-container metrics and container counts, it is constructed from
// ContainerServer config the sentinel has no equivalent of, and its instrument
// names are a deliberately allowlisted set gated by a golden test. Threading
// the sentinel through all of that would mean a proto enum change and a much
// larger blast radius than a self-contained meter here.
//
// COST SURFACE. Custom metrics are billed per ingested sample. At the 60s
// floor this is 7 fixed series per sentinel plus one per backend
// (backend_healthy) — roughly 11 series/minute on a sentinel fronting four
// backends. Additions belong in this list, deliberately, for the same
// review-gate reason the daemon's allowlist exists.

const (
	metricSentinelState          = "containarium.sentinel.state"
	metricSentinelPreempted      = "containarium.sentinel.preempted_total"
	metricSentinelRecovered      = "containarium.sentinel.recovered_total"
	metricSentinelFailover       = "containarium.sentinel.failover_total"
	metricSentinelBackendHealthy = "containarium.sentinel.backend_healthy"
	metricSentinelRSS            = "containarium.sentinel.process.resident_memory_bytes"
	metricSentinelGoroutines     = "containarium.sentinel.process.goroutines"
	metricSentinelOpenFDs        = "containarium.sentinel.process.open_fds"

	// sentinelMeterName is the instrumentation scope for these series.
	sentinelMeterName = "github.com/footprintai/containarium/internal/sentinel"
)

// MetricsExportOptions configures the sentinel's push exporter.
type MetricsExportOptions struct {
	// Exporter is the OTel SDK exporter to push through — in production a
	// cloudexport Sink's NewExporter result. Required.
	Exporter sdkmetric.Exporter

	// Resource tags every series with the provider's monitored-resource
	// identity (gce_instance on GCP). Optional; nil falls back to the SDK
	// default, which still exports but loses the per-instance association.
	Resource *resource.Resource

	// SentinelID distinguishes one sentinel's series from another's. Without
	// it two sentinels' timeseries collide into one meaningless line.
	SentinelID string

	// IntervalSeconds is the requested cadence, clamped up to the billing
	// floor.
	IntervalSeconds int32
}

// clampExportInterval enforces the same per-sample billing floor the daemon's
// collector uses. One policy, not two.
func clampExportInterval(seconds int32) int32 {
	if seconds < cloudexport.MinIntervalSeconds {
		return cloudexport.MinIntervalSeconds
	}
	return seconds
}

// StartMetricsExport begins pushing the sentinel's series and returns a stop
// function that flushes and shuts the pipeline down.
func StartMetricsExport(m *Manager, opts MetricsExportOptions) (func(context.Context) error, error) {
	if m == nil {
		return nil, fmt.Errorf("metrics export: nil manager")
	}
	if opts.Exporter == nil {
		return nil, fmt.Errorf("metrics export: no exporter configured — nothing to push to")
	}

	interval := time.Duration(clampExportInterval(opts.IntervalSeconds)) * time.Second
	reader := sdkmetric.NewPeriodicReader(opts.Exporter, sdkmetric.WithInterval(interval))

	providerOpts := []sdkmetric.Option{sdkmetric.WithReader(reader)}
	if opts.Resource != nil {
		providerOpts = append(providerOpts, sdkmetric.WithResource(opts.Resource))
	}
	provider := sdkmetric.NewMeterProvider(providerOpts...)

	if err := registerSentinelInstruments(provider.Meter(sentinelMeterName), m, opts.SentinelID); err != nil {
		// Shut the provider down rather than leaking its reader goroutine on
		// a registration failure.
		_ = provider.Shutdown(context.Background())
		return nil, fmt.Errorf("metrics export: %w", err)
	}

	return provider.Shutdown, nil
}

// registerSentinelInstruments wires the observable instruments to the
// Manager. Split out so tests can drive the real registration through a
// ManualReader without an exporter or a network.
//
// All instruments are observable (async): every value is "read the current
// state at collection time", which is exactly what an async callback is for,
// and it keeps the hot paths (health checks, failover) free of metric writes.
func registerSentinelInstruments(meter metric.Meter, m *Manager, sentinelID string) error {
	state, err := meter.Int64ObservableGauge(metricSentinelState,
		metric.WithDescription("Backend serving state: 1 proxy (up), 0 maintenance (down)."))
	if err != nil {
		return err
	}
	preempted, err := meter.Int64ObservableCounter(metricSentinelPreempted,
		metric.WithDescription("Total spot-VM preemption events observed."))
	if err != nil {
		return err
	}
	recovered, err := meter.Int64ObservableCounter(metricSentinelRecovered,
		metric.WithDescription("Total returns to proxy after an outage."))
	if err != nil {
		return err
	}
	failover, err := meter.Int64ObservableCounter(metricSentinelFailover,
		metric.WithDescription("Total primary-backend failovers, including those absorbed without entering maintenance."))
	if err != nil {
		return err
	}
	backendHealthy, err := meter.Int64ObservableGauge(metricSentinelBackendHealthy,
		metric.WithDescription("Per-backend health as seen by the sentinel: 1 healthy, 0 unhealthy."))
	if err != nil {
		return err
	}
	rss, err := meter.Int64ObservableGauge(metricSentinelRSS,
		metric.WithDescription("Sentinel process resident set size."),
		metric.WithUnit("By"))
	if err != nil {
		return err
	}
	goroutines, err := meter.Int64ObservableGauge(metricSentinelGoroutines,
		metric.WithDescription("Goroutines in the sentinel process."))
	if err != nil {
		return err
	}
	openFDs, err := meter.Int64ObservableGauge(metricSentinelOpenFDs,
		metric.WithDescription("Open file descriptors in the sentinel process."))
	if err != nil {
		return err
	}

	base := []attribute.KeyValue{attribute.String("sentinel", sentinelID)}
	baseSet := metric.WithAttributes(base...)

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		stateVal := int64(0)
		if m.CurrentState() == StateProxy {
			stateVal = 1
		}
		o.ObserveInt64(state, stateVal, baseSet)
		o.ObserveInt64(preempted, int64(m.PreemptCount()), baseSet)
		o.ObserveInt64(recovered, int64(m.RecoveredCount()), baseSet)
		o.ObserveInt64(failover, m.FailoverCount(), baseSet)

		for id, healthy := range m.BackendHealthSnapshot() {
			v := int64(0)
			if healthy {
				v = 1
			}
			o.ObserveInt64(backendHealthy, v, metric.WithAttributes(
				append(append([]attribute.KeyValue{}, base...), attribute.String("backend", id))...))
		}

		rt := collectRuntimeStats()
		o.ObserveInt64(goroutines, int64(rt.Goroutines), baseSet)

		// Absent, not zero, when /proc is unreadable — the same rule as the
		// /metrics rendering (#1351). A zero would read as "this process uses
		// no memory" and silence the alert this exists to enable, and unlike
		// the text endpoint that zero would be persisted in Cloud Monitoring
		// forever.
		if ps := readProcStats(); ps.Available {
			o.ObserveInt64(rss, safeInt64(ps.RSSBytes), baseSet)
			if ps.OpenFDs > 0 {
				o.ObserveInt64(openFDs, safeInt64(ps.OpenFDs), baseSet)
			}
		}
		return nil
	}, state, preempted, recovered, failover, backendHealthy, rss, goroutines, openFDs)

	return err
}

// safeInt64 converts a uint64 counter to the int64 the OTel API takes,
// saturating rather than wrapping.
//
// Guarded rather than suppressing gosec's G115: a value above 2^63 would wrap
// to a NEGATIVE observation, and a negative resident-memory datapoint
// persisted in Cloud Monitoring is worse than a clamped one — it would break
// any alert expression built on the series. Real RSS and fd counts are nowhere
// near this, which is exactly why the wrap would be baffling if it ever
// happened.
func safeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}
