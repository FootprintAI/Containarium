package cloudexport

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/footprintai/containarium/internal/metrics/platformstats"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// meterName is the instrumentation scope all exported host series are
// recorded under.
const meterName = "github.com/footprintai/containarium/internal/metrics/cloudexport"

// MinIntervalSeconds is the hard floor on the export cadence. Custom
// metrics are billed per ingested sample, so a misconfigured or hostile
// sub-minute interval must not be honored — the collector clamps up to
// this floor regardless of what config asks for.
const MinIntervalSeconds = 60

// Instrument names — the complete, allowlisted host-series set for
// #1070. Additions require touching this list (and its golden test),
// which is exactly the cost-surface review gate the design doc asks for.
const (
	MetricCPULoad1m      = "containarium.host.cpu.load_1m"
	MetricCPULoad5m      = "containarium.host.cpu.load_5m"
	MetricCPULoad15m     = "containarium.host.cpu.load_15m"
	MetricMemoryUsed     = "containarium.host.memory.used_bytes"
	MetricMemoryTotal    = "containarium.host.memory.total_bytes"
	MetricDiskUsed       = "containarium.host.disk.used_bytes"
	MetricDiskTotal      = "containarium.host.disk.total_bytes"
	MetricContainerCount = "containarium.host.container.count"

	// MetricHeartbeat is the liveness/up series (#1072): a constant 1
	// emitted every export interval while the daemon runs. It is the
	// out-of-band dead-man signal — a metric-absence alert policy in the
	// cloud provider's monitoring fires when this series stops arriving,
	// catching the failure class (host or daemon dead / network-
	// partitioned) that host-local alerting cannot report on because it
	// fate-shares with the host.
	MetricHeartbeat = "containarium.export.heartbeat"

	// MetricPlatformAPIRequests / MetricPlatformAPIErrors are the
	// platform group's API-health series (#1082): cumulative counts of
	// completed API calls (native gRPC + REST-via-grpc-gateway, both
	// converge on the same interceptor), by coarse code_class. Requests
	// counts every completed call; errors counts only the client_error
	// and server_error classes.
	MetricPlatformAPIRequests = "containarium.platform.api.requests"
	MetricPlatformAPIErrors   = "containarium.platform.api.errors"
)

// Label keys — the complete allowlist. No org/tenant identifier ever
// appears here; the labels are fixed daemon identity set once at
// construction, so a Sources implementation has no channel to inject a
// tenant label through the numeric snapshot it returns.
const (
	LabelBackendID = "backend_id"
	LabelHostname  = "hostname"
	LabelRegion    = "region"
	// LabelDaemonVersion tags the heartbeat series only (not the host
	// series) with the daemon build, so a dead-man alert makes clear which
	// version stopped reporting.
	LabelDaemonVersion = "daemon_version"
	// LabelCodeClass tags the platform API series with their coarse
	// outcome bucket (platformstats.CodeClass) — the deliberately small,
	// fixed-cardinality dimension the design uses instead of a raw route
	// or gRPC code, which would blow up the billed cost surface.
	LabelCodeClass = "code_class"
)

// Labels is the fixed identity stamped on every exported series. These
// are host-level facts (which backend, which machine, which region, which
// daemon build), not per-tick data — so they live on the collector, not
// in Sources. Not every series carries every field: the host series use
// backend_id/hostname/region; the heartbeat uses backend_id/hostname/
// daemon_version.
type Labels struct {
	BackendID     string
	Hostname      string
	Region        string
	DaemonVersion string
}

// attributeSet is the host-series label set (backend_id, hostname,
// region).
func (l Labels) attributeSet() attribute.Set {
	return attribute.NewSet(
		attribute.String(LabelBackendID, l.BackendID),
		attribute.String(LabelHostname, l.Hostname),
		attribute.String(LabelRegion, l.Region),
	)
}

// heartbeatAttributeSet is the heartbeat label set (backend_id, hostname,
// daemon_version) — deliberately distinct from the host-series set: the
// dead-man alert cares which daemon build went silent, not which region.
func (l Labels) heartbeatAttributeSet() attribute.Set {
	return attribute.NewSet(
		attribute.String(LabelBackendID, l.BackendID),
		attribute.String(LabelHostname, l.Hostname),
		attribute.String(LabelDaemonVersion, l.DaemonVersion),
	)
}

// platformAttributeSet is the platform API-health label set (backend_id,
// hostname, region, code_class) — the host-series identity plus the
// per-point outcome class.
func (l Labels) platformAttributeSet(class platformstats.CodeClass) attribute.Set {
	return attribute.NewSet(
		attribute.String(LabelBackendID, l.BackendID),
		attribute.String(LabelHostname, l.Hostname),
		attribute.String(LabelRegion, l.Region),
		attribute.String(LabelCodeClass, string(class)),
	)
}

// CollectorOptions are the construction inputs for a CloudExportCollector.
type CollectorOptions struct {
	// Sources is the seam over the daemon's metric collection. Required.
	Sources Sources
	// PlatformSources is the read-side seam over platform-domain facts
	// (#1082/#1083/#1084). Optional — nil means the platform group, if
	// enabled, registers no instruments (the same "reserved" behavior
	// container/platform had before any of those issues landed), rather
	// than erroring.
	PlatformSources PlatformSources
	// Exporter is the OTel SDK metric exporter to push batches through
	// (a provider Sink's NewExporter result in production, a fake in
	// tests). Required.
	Exporter sdkmetric.Exporter
	// Resource tags every series with the provider's monitored-resource
	// identity (e.g. gce_instance from the GCP detector). Optional; nil
	// falls back to the SDK default resource.
	Resource *resource.Resource
	// Labels is the fixed backend_id/hostname/region identity.
	Labels Labels
	// IntervalSeconds is the requested export cadence. Clamped up to
	// MinIntervalSeconds; <= 0 uses MinIntervalSeconds.
	IntervalSeconds int32
	// Groups selects which independently-enableable series groups this
	// collector registers (#1081). Normalized at construction: an empty
	// selection resolves to [HOST], so a collector built from a v0.60.0
	// config exports exactly the #1070 host series.
	Groups []pb.CloudMetricsGroup
}

// healthState is the collector's live export health, surfaced through
// GetMetricsExport. Guarded by its own mutex because it is written from
// the PeriodicReader's background goroutine and read from RPC handlers.
type healthState struct {
	mu             sync.Mutex
	lastSuccessAt  time.Time
	lastError      string
	exportFailures int64
}

func (h *healthState) recordSuccess(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSuccessAt = now
	h.lastError = ""
}

func (h *healthState) recordFailure(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.exportFailures++
	h.lastError = err.Error()
}

func (h *healthState) snapshot() (lastSuccessAt time.Time, lastError string, failures int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastSuccessAt, h.lastError, h.exportFailures
}

// healthExporter decorates the real exporter to record per-batch
// success/failure into the shared healthState. It never changes the
// exporter's own error behavior — the OTel SDK still logs and drops on
// its own terms; this only observes the outcome so GetMetricsExport can
// report real numbers.
type healthExporter struct {
	sdkmetric.Exporter
	health *healthState
	now    func() time.Time
}

func (h *healthExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	err := h.Exporter.Export(ctx, rm)
	if err != nil {
		h.health.recordFailure(err)
	} else {
		h.health.recordSuccess(h.now())
	}
	return err
}

// CloudExportCollector owns a dedicated OTel MeterProvider + a
// PeriodicReader wired to one provider exporter, and registers exactly
// the allowlisted host-series instruments as async gauges pulling from
// Sources. It is deliberately a second, separate pipeline from the
// daemon's internal Collector: the exported instrument set is the billed
// cost surface, and keeping it isolated makes that surface explicit and
// reviewable in one file.
type CloudExportCollector struct {
	sources         Sources
	platformSources PlatformSources
	exporter        sdkmetric.Exporter
	resource        *resource.Resource
	labels          Labels
	interval        time.Duration
	groups          []pb.CloudMetricsGroup
	health          *healthState

	mu      sync.Mutex
	mp      *sdkmetric.MeterProvider
	started bool
}

// NewCollector builds an unstarted CloudExportCollector. Call Start to
// begin periodic export and Stop to tear it down; both are idempotent.
func NewCollector(opts CollectorOptions) *CloudExportCollector {
	interval := time.Duration(opts.IntervalSeconds) * time.Second
	if floor := MinIntervalSeconds * time.Second; interval < floor {
		interval = floor
	}
	return &CloudExportCollector{
		sources:         opts.Sources,
		platformSources: opts.PlatformSources,
		exporter:        opts.Exporter,
		resource:        opts.Resource,
		labels:          opts.Labels,
		interval:        interval,
		groups:          NormalizeGroups(opts.Groups),
		health:          &healthState{},
	}
}

// Start begins periodic export. Idempotent: a second call while running
// is a no-op. The MeterProvider it stands up is entirely separate from
// the daemon's internal metrics pipeline.
func (c *CloudExportCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}

	reader := sdkmetric.NewPeriodicReader(
		&healthExporter{Exporter: c.exporter, health: c.health, now: time.Now},
		sdkmetric.WithInterval(c.interval),
	)
	mp, err := c.buildMeterProvider(reader)
	if err != nil {
		return err
	}
	c.mp = mp
	c.started = true
	return nil
}

// Stop tears down the MeterProvider (final flush + reader shutdown) and
// halts emission. Idempotent: a call while already stopped is a no-op.
func (c *CloudExportCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return nil
	}
	mp := c.mp
	c.mp = nil
	c.started = false
	if mp == nil {
		return nil
	}
	return mp.Shutdown(ctx)
}

// ForceFlush triggers an immediate collection + export outside the
// periodic cadence. Used by tests to observe a tick without waiting a
// full interval; a no-op when the collector is stopped.
func (c *CloudExportCollector) ForceFlush(ctx context.Context) error {
	c.mu.Lock()
	mp := c.mp
	c.mu.Unlock()
	if mp == nil {
		return nil
	}
	return mp.ForceFlush(ctx)
}

// Health reports the live export health for GetMetricsExport.
func (c *CloudExportCollector) Health() (lastSuccessAt time.Time, lastError string, exportFailures int64) {
	return c.health.snapshot()
}

// buildMeterProvider stands up the MeterProvider on the given reader and
// registers the allowlisted instruments with a single multi-instrument
// callback. Factored out (unexported) so unit tests can drive it with a
// ManualReader and assert the exact series/label set the callback emits.
func (c *CloudExportCollector) buildMeterProvider(reader sdkmetric.Reader) (*sdkmetric.MeterProvider, error) {
	mpOpts := []sdkmetric.Option{sdkmetric.WithReader(reader)}
	if c.resource != nil {
		mpOpts = append(mpOpts, sdkmetric.WithResource(c.resource))
	}
	mp := sdkmetric.NewMeterProvider(mpOpts...)
	for _, g := range c.groups {
		if err := registerGroupInstruments(mp, g, c.sources, c.platformSources, c.labels); err != nil {
			return nil, err
		}
	}
	if err := registerHeartbeatInstrument(mp, c.labels); err != nil {
		return nil, err
	}
	return mp, nil
}

// registerGroupInstruments registers exactly the instruments belonging
// to one metric group (#1081). This is the single dispatch point new
// groups plug into: host registers the #1070 allowlist; container is
// still reserved (per-container series land in #1071); platform
// registers the #1082 API-health series when a PlatformSources is
// wired, and nothing otherwise (#1083/#1084 add more platform series to
// the same dispatch). Groups are normalized before they reach here, so
// UNSPECIFIED never arrives; an unknown value is a programming error.
//
// Note the heartbeat is deliberately NOT a group: it is registered
// unconditionally by buildMeterProvider alongside (and independent of)
// whatever groups are enabled, because the dead-man signal must never be
// gated by group selection or a Sources error (see
// registerHeartbeatInstrument).
func registerGroupInstruments(mp *sdkmetric.MeterProvider, group pb.CloudMetricsGroup, sources Sources, platformSources PlatformSources, labels Labels) error {
	switch group {
	case pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_HOST:
		return registerHostInstruments(mp, sources, labels)
	case pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_CONTAINER:
		// Reserved: per-container series land in #1071/#1072.
		return nil
	case pb.CloudMetricsGroup_CLOUD_METRICS_GROUP_PLATFORM:
		if platformSources == nil {
			// Not wired (e.g. an older daemon build, or a test that
			// doesn't need it) — deliberate zero-series opt-in, same as
			// the pre-#1082 "reserved" behavior, never an error.
			return nil
		}
		return registerPlatformInstruments(mp, platformSources, labels)
	default:
		return fmt.Errorf("cloudexport: unregisterable metric group %v", group)
	}
}

// registerPlatformInstruments creates the platform group's API-health
// counters (#1082) and wires one callback that pulls a single
// APISnapshot per tick and observes both series, one point per
// code_class. Counters, not gauges: OTel async-counter semantics expect
// the current cumulative total on every observation (platformstats.Stats
// already accumulates for the daemon's lifetime), which is exactly what
// APISnapshot reports.
func registerPlatformInstruments(mp *sdkmetric.MeterProvider, sources PlatformSources, labels Labels) error {
	meter := mp.Meter(meterName)

	requests, err := meter.Int64ObservableCounter(MetricPlatformAPIRequests,
		metric.WithDescription("Cumulative count of completed API requests (gRPC + REST-via-gateway), by coarse outcome class."))
	if err != nil {
		return err
	}
	apiErrors, err := meter.Int64ObservableCounter(MetricPlatformAPIErrors,
		metric.WithDescription("Cumulative count of completed API requests that resulted in a client or server error, by coarse outcome class."))
	if err != nil {
		return err
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o metric.Observer) error {
			snap := sources.APIStats()
			for class, n := range snap.RequestsByClass {
				o.ObserveInt64(requests, n, metric.WithAttributeSet(labels.platformAttributeSet(class)))
			}
			for class, n := range snap.ErrorsByClass {
				o.ObserveInt64(apiErrors, n, metric.WithAttributeSet(labels.platformAttributeSet(class)))
			}
			return nil
		},
		requests, apiErrors,
	)
	return err
}

// registerHeartbeatInstrument creates the heartbeat/up gauge (#1072) and
// wires a callback that observes a constant 1 on every tick, deliberately
// in its OWN callback with no dependency on Sources. That independence is
// the dead-man contract: the series is present iff the daemon is alive and
// its export pipeline is delivering to the cloud, so its absence means
// exactly one thing — the host or daemon died (or was partitioned from the
// provider). A transient Sources error (incus briefly unavailable) skips
// the host series for that tick but must not suppress the heartbeat, or an
// incus hiccup would masquerade as backend death and page the operator.
// For the same reason the heartbeat is not modeled as a metric group: it
// accompanies every collector regardless of which groups are enabled.
func registerHeartbeatInstrument(mp *sdkmetric.MeterProvider, labels Labels) error {
	meter := mp.Meter(meterName)
	heartbeat, err := meter.Int64ObservableGauge(MetricHeartbeat,
		metric.WithDescription("Liveness heartbeat: constant 1 emitted every export interval while the daemon runs. Absence is the dead-man signal for a metric-absence alert policy."))
	if err != nil {
		return err
	}
	observeOpt := metric.WithAttributeSet(labels.heartbeatAttributeSet())
	_, err = meter.RegisterCallback(
		func(ctx context.Context, o metric.Observer) error {
			o.ObserveInt64(heartbeat, 1, observeOpt)
			return nil
		},
		heartbeat,
	)
	return err
}

// registerHostInstruments creates the eight allowlisted host gauges and
// wires one callback that pulls a single SystemResources snapshot per
// tick and observes all of them under the fixed label set. On a Sources
// error the callback logs and returns nil — the tick is skipped with no
// observations (so no stale series), never a panic.
func registerHostInstruments(mp *sdkmetric.MeterProvider, sources Sources, labels Labels) error {
	meter := mp.Meter(meterName)

	load1, err := meter.Float64ObservableGauge(MetricCPULoad1m,
		metric.WithDescription("Host 1-minute load average."))
	if err != nil {
		return err
	}
	load5, err := meter.Float64ObservableGauge(MetricCPULoad5m,
		metric.WithDescription("Host 5-minute load average."))
	if err != nil {
		return err
	}
	load15, err := meter.Float64ObservableGauge(MetricCPULoad15m,
		metric.WithDescription("Host 15-minute load average."))
	if err != nil {
		return err
	}
	memUsed, err := meter.Int64ObservableGauge(MetricMemoryUsed,
		metric.WithUnit("By"), metric.WithDescription("Host memory used, in bytes."))
	if err != nil {
		return err
	}
	memTotal, err := meter.Int64ObservableGauge(MetricMemoryTotal,
		metric.WithUnit("By"), metric.WithDescription("Host memory total, in bytes."))
	if err != nil {
		return err
	}
	diskUsed, err := meter.Int64ObservableGauge(MetricDiskUsed,
		metric.WithUnit("By"), metric.WithDescription("Host disk used, in bytes."))
	if err != nil {
		return err
	}
	diskTotal, err := meter.Int64ObservableGauge(MetricDiskTotal,
		metric.WithUnit("By"), metric.WithDescription("Host disk total, in bytes."))
	if err != nil {
		return err
	}
	containerCount, err := meter.Int64ObservableGauge(MetricContainerCount,
		metric.WithUnit("{container}"), metric.WithDescription("Number of containers on the host."))
	if err != nil {
		return err
	}

	attrSet := labels.attributeSet()
	observeOpt := metric.WithAttributeSet(attrSet)

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o metric.Observer) error {
			sr, err := sources.SystemResources(ctx)
			if err != nil {
				// Skip this tick: log and emit nothing. Never panic,
				// never crash the daemon, never touch the internal
				// VM pipeline.
				log.Printf("[cloudexport] skipping export tick: SystemResources: %v", err)
				return nil
			}
			if sr == nil {
				log.Printf("[cloudexport] skipping export tick: nil SystemResources")
				return nil
			}
			o.ObserveFloat64(load1, sr.CPULoad1Min, observeOpt)
			o.ObserveFloat64(load5, sr.CPULoad5Min, observeOpt)
			o.ObserveFloat64(load15, sr.CPULoad15Min, observeOpt)
			o.ObserveInt64(memUsed, sr.MemoryUsedBytes, observeOpt)
			o.ObserveInt64(memTotal, sr.MemoryTotalBytes, observeOpt)
			o.ObserveInt64(diskUsed, sr.DiskUsedBytes, observeOpt)
			o.ObserveInt64(diskTotal, sr.DiskTotalBytes, observeOpt)
			o.ObserveInt64(containerCount, sr.ContainerCount, observeOpt)
			return nil
		},
		load1, load5, load15, memUsed, memTotal, diskUsed, diskTotal, containerCount,
	)
	return err
}
