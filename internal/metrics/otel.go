package metrics

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/footprintai/containarium/distros/go/containariumotel"
	"github.com/footprintai/containarium/internal/reqrate"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// CollectorConfig holds configuration for the OTel metrics collector
// PeerMetrics represents metrics from a peer backend container.
type PeerMetrics struct {
	ContainerName    string
	BackendID        string
	CPUUsageSeconds  int64
	MemoryUsageBytes int64
	DiskUsageBytes   int64
	NetworkRxBytes   int64
	NetworkTxBytes   int64
	ProcessCount     int64
}

// PeerSystemMetrics represents system-level metrics from a peer backend.
type PeerSystemMetrics struct {
	BackendID         string
	TotalCPUs         int64
	TotalMemoryBytes  int64
	UsedMemoryBytes   int64
	TotalDiskBytes    int64
	UsedDiskBytes     int64
	CPULoad1Min       float64
	CPULoad5Min       float64
	CPULoad15Min      float64
	ContainersRunning int64
	ContainersStopped int64
}

// PeerBackendHealth represents the health status of a backend instance.
type PeerBackendHealth struct {
	BackendID string
	Healthy   bool
	LastSeen  time.Time
}

// PeerMetricsFetcher fetches container and system metrics from peer backends.
type PeerMetricsFetcher interface {
	// FetchPeerMetrics returns container metrics from all healthy peers.
	FetchPeerMetrics(authToken string) []PeerMetrics
	// FetchPeerSystemMetrics returns system metrics from all healthy peers.
	FetchPeerSystemMetrics(authToken string) []PeerSystemMetrics
	// FetchPeerHealth returns health status of all peer backends.
	FetchPeerHealth() []PeerBackendHealth
}

type CollectorConfig struct {
	// VictoriaMetricsURL is the base URL for Victoria Metrics (e.g., "http://10.100.0.x:8428")
	VictoriaMetricsURL string

	// CollectionInterval is how often to collect metrics (default 30s)
	CollectionInterval time.Duration

	// ServiceName is the OTel service name (default "containarium")
	ServiceName string

	// LocalBackendID is this daemon's backend ID (used as backend.id label on local metrics)
	LocalBackendID string
}

// DefaultCollectorConfig returns a default collector configuration
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		CollectionInterval: 30 * time.Second,
		ServiceName:        "containarium",
	}
}

// Collector collects system and container metrics via OpenTelemetry
type Collector struct {
	config      CollectorConfig
	incusClient *incus.Client
	provider    *sdkmetric.MeterProvider
	shutdownFn  containariumotel.ShutdownFunc

	// System metric instruments
	systemCPUCount   otelmetric.Int64Gauge
	systemMemTotal   otelmetric.Int64Gauge
	systemMemUsed    otelmetric.Int64Gauge
	systemDiskTotal  otelmetric.Int64Gauge
	systemDiskUsed   otelmetric.Int64Gauge
	systemCPULoad1m  otelmetric.Float64Gauge
	systemCPULoad5m  otelmetric.Float64Gauge
	systemCPULoad15m otelmetric.Float64Gauge

	// Container metric instruments
	containerCPUUsage     otelmetric.Int64Gauge
	containerMemUsage     otelmetric.Int64Gauge
	containerDiskUsage    otelmetric.Int64Gauge
	containerNetRx        otelmetric.Int64Gauge
	containerNetTx        otelmetric.Int64Gauge
	containerProcessCount otelmetric.Int64Gauge
	containerRequestRate  otelmetric.Float64Gauge

	// Aggregate instruments
	containersRunning otelmetric.Int64Gauge
	containersStopped otelmetric.Int64Gauge

	// Backend health instruments
	backendHealthy otelmetric.Int64Gauge

	ctx         context.Context
	cancel      context.CancelFunc
	peerFetcher PeerMetricsFetcher
}

// NewCollector creates a new OTel metrics collector
func NewCollector(config CollectorConfig, incusClient *incus.Client) (*Collector, error) {
	if config.VictoriaMetricsURL == "" {
		return nil, fmt.Errorf("VictoriaMetricsURL is required")
	}
	if config.CollectionInterval == 0 {
		config.CollectionInterval = 30 * time.Second
	}
	if config.ServiceName == "" {
		config.ServiceName = "containarium"
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Dogfood the Go distro for SDK setup (Phase 7 of the rollout
	// plan). The distro composes the resource per the standard
	// precedence + adds the defended containarium.distro stamp;
	// otlpmetrichttp.WithEndpointURL handles VictoriaMetrics' custom
	// ingest path under WithEndpoint.
	vmURL := stripProtocol(config.VictoriaMetricsURL)
	shutdownFn, err := containariumotel.Init(ctx,
		containariumotel.WithServiceName(config.ServiceName),
		containariumotel.WithEndpoint(fmt.Sprintf("http://%s/opentelemetry/api/v1/push", vmURL)),
		containariumotel.WithMetricInterval(config.CollectionInterval),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("init telemetry distro: %w", err)
	}

	// Pull the concrete *sdkmetric.MeterProvider back out of the
	// global so existing call sites (pentest.NewManager, Meter()
	// callers below) keep working without a wider refactor.
	provider, ok := otel.GetMeterProvider().(*sdkmetric.MeterProvider)
	if !ok {
		cancel()
		return nil, fmt.Errorf("global MeterProvider is not *sdkmetric.MeterProvider (got %T)", otel.GetMeterProvider())
	}

	c := &Collector{
		config:      config,
		incusClient: incusClient,
		provider:    provider,
		shutdownFn:  shutdownFn,
		ctx:         ctx,
		cancel:      cancel,
	}

	if err := c.initInstruments(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to init instruments: %w", err)
	}

	return c, nil
}

// initInstruments creates the OTel metric instruments
func (c *Collector) initInstruments() error {
	meter := c.provider.Meter("containarium")

	var err error

	// System metrics
	c.systemCPUCount, err = meter.Int64Gauge("system.cpu.count",
		otelmetric.WithDescription("Number of CPU cores"))
	if err != nil {
		return err
	}

	c.systemMemTotal, err = meter.Int64Gauge("system.memory.total_bytes",
		otelmetric.WithDescription("Total system memory in bytes"),
		otelmetric.WithUnit("By"))
	if err != nil {
		return err
	}

	c.systemMemUsed, err = meter.Int64Gauge("system.memory.used_bytes",
		otelmetric.WithDescription("Used system memory in bytes"),
		otelmetric.WithUnit("By"))
	if err != nil {
		return err
	}

	c.systemDiskTotal, err = meter.Int64Gauge("system.disk.total_bytes",
		otelmetric.WithDescription("Total disk space in bytes"),
		otelmetric.WithUnit("By"))
	if err != nil {
		return err
	}

	c.systemDiskUsed, err = meter.Int64Gauge("system.disk.used_bytes",
		otelmetric.WithDescription("Used disk space in bytes"),
		otelmetric.WithUnit("By"))
	if err != nil {
		return err
	}

	c.systemCPULoad1m, err = meter.Float64Gauge("system.cpu.load_1m",
		otelmetric.WithDescription("CPU load average (1 minute)"))
	if err != nil {
		return err
	}

	c.systemCPULoad5m, err = meter.Float64Gauge("system.cpu.load_5m",
		otelmetric.WithDescription("CPU load average (5 minutes)"))
	if err != nil {
		return err
	}

	c.systemCPULoad15m, err = meter.Float64Gauge("system.cpu.load_15m",
		otelmetric.WithDescription("CPU load average (15 minutes)"))
	if err != nil {
		return err
	}

	// Container metrics
	c.containerCPUUsage, err = meter.Int64Gauge("container.cpu.usage_seconds",
		otelmetric.WithDescription("Container CPU usage in seconds"),
		otelmetric.WithUnit("s"))
	if err != nil {
		return err
	}

	c.containerMemUsage, err = meter.Int64Gauge("container.memory.usage_bytes",
		otelmetric.WithDescription("Container memory usage in bytes"),
		otelmetric.WithUnit("By"))
	if err != nil {
		return err
	}

	c.containerDiskUsage, err = meter.Int64Gauge("container.disk.usage_bytes",
		otelmetric.WithDescription("Container disk usage in bytes"),
		otelmetric.WithUnit("By"))
	if err != nil {
		return err
	}

	c.containerNetRx, err = meter.Int64Gauge("container.network.rx_bytes",
		otelmetric.WithDescription("Container network bytes received"),
		otelmetric.WithUnit("By"))
	if err != nil {
		return err
	}

	c.containerNetTx, err = meter.Int64Gauge("container.network.tx_bytes",
		otelmetric.WithDescription("Container network bytes transmitted"),
		otelmetric.WithUnit("By"))
	if err != nil {
		return err
	}

	c.containerProcessCount, err = meter.Int64Gauge("container.process.count",
		otelmetric.WithDescription("Number of running processes in container"))
	if err != nil {
		return err
	}

	// Request-rate plane (#231): edge-measured HTTP requests/sec per container.
	// → VM series container_request_rate{container_id=...}, the same join key
	// the bytes plane uses, consumed by the cloud's RequestRatePanel. Recorded
	// only when access-log aggregation is enabled (see RecordRequestRates and
	// docs/REQUEST-RATE-PLANE-DESIGN.md); the instrument is created
	// unconditionally so the wiring slice has nothing to bootstrap.
	c.containerRequestRate, err = meter.Float64Gauge("container.request_rate",
		otelmetric.WithDescription("Container HTTP requests per second (edge-measured)"),
		otelmetric.WithUnit("1/s"))
	if err != nil {
		return err
	}

	// Aggregate metrics
	c.containersRunning, err = meter.Int64Gauge("containarium.containers.running",
		otelmetric.WithDescription("Number of running containers"))
	if err != nil {
		return err
	}

	c.containersStopped, err = meter.Int64Gauge("containarium.containers.stopped",
		otelmetric.WithDescription("Number of stopped containers"))
	if err != nil {
		return err
	}

	c.backendHealthy, err = meter.Int64Gauge("containarium.backend.healthy",
		otelmetric.WithDescription("Backend health status (1=healthy, 0=unhealthy)"))
	if err != nil {
		return err
	}

	return nil
}

// Start begins the metrics collection loop
func (c *Collector) Start() {
	go c.collectLoop()
	log.Printf("OTel metrics collector started (interval: %v, target: %s)", c.config.CollectionInterval, c.config.VictoriaMetricsURL)
}

// collectLoop runs the collection ticker
func (c *Collector) collectLoop() {
	// Collect immediately on start
	c.collect()

	ticker := time.NewTicker(c.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

// collect gathers and records all metrics
func (c *Collector) collect() {
	ctx := c.ctx

	// Collect system metrics (local)
	localAttrs := otelmetric.WithAttributes(
		attribute.String("backend.id", c.config.LocalBackendID),
	)
	sysRes, err := c.incusClient.GetSystemResources()
	if err != nil {
		log.Printf("Warning: failed to collect system metrics: %v", err)
	} else {
		c.systemCPUCount.Record(ctx, int64(sysRes.TotalCPUs), localAttrs)
		c.systemMemTotal.Record(ctx, sysRes.TotalMemoryBytes, localAttrs)
		c.systemMemUsed.Record(ctx, sysRes.UsedMemoryBytes, localAttrs)
		c.systemDiskTotal.Record(ctx, sysRes.TotalDiskBytes, localAttrs)
		c.systemDiskUsed.Record(ctx, sysRes.UsedDiskBytes, localAttrs)
		c.systemCPULoad1m.Record(ctx, sysRes.CPULoad1Min, localAttrs)
		c.systemCPULoad5m.Record(ctx, sysRes.CPULoad5Min, localAttrs)
		c.systemCPULoad15m.Record(ctx, sysRes.CPULoad15Min, localAttrs)
	}

	// Record local backend health (always healthy if collecting)
	c.backendHealthy.Record(ctx, 1, localAttrs)

	// Record peer backend health
	if c.peerFetcher != nil {
		for _, ph := range c.peerFetcher.FetchPeerHealth() {
			peerAttrs := otelmetric.WithAttributes(
				attribute.String("backend.id", ph.BackendID),
			)
			var val int64
			if ph.Healthy {
				val = 1
			}
			c.backendHealthy.Record(ctx, val, peerAttrs)
		}
	}

	// Collect system metrics from peers
	if c.peerFetcher != nil {
		for _, ps := range c.peerFetcher.FetchPeerSystemMetrics("") {
			peerAttrs := otelmetric.WithAttributes(
				attribute.String("backend.id", ps.BackendID),
			)
			c.systemCPUCount.Record(ctx, ps.TotalCPUs, peerAttrs)
			c.systemMemTotal.Record(ctx, ps.TotalMemoryBytes, peerAttrs)
			c.systemMemUsed.Record(ctx, ps.UsedMemoryBytes, peerAttrs)
			c.systemDiskTotal.Record(ctx, ps.TotalDiskBytes, peerAttrs)
			c.systemDiskUsed.Record(ctx, ps.UsedDiskBytes, peerAttrs)
			c.systemCPULoad1m.Record(ctx, ps.CPULoad1Min, peerAttrs)
			c.systemCPULoad5m.Record(ctx, ps.CPULoad5Min, peerAttrs)
			c.systemCPULoad15m.Record(ctx, ps.CPULoad15Min, peerAttrs)
			c.containersRunning.Record(ctx, ps.ContainersRunning, peerAttrs)
			c.containersStopped.Record(ctx, ps.ContainersStopped, peerAttrs)
		}
	}

	// List containers and collect per-container metrics
	containers, err := c.incusClient.ListContainers()
	if err != nil {
		log.Printf("Warning: failed to list containers for metrics: %v", err)
		return
	}

	var running, stopped int64
	for _, ct := range containers {
		if ct.State == "Running" {
			// Only count user containers for aggregate stats
			if !ct.Role.IsCoreRole() {
				running++
			}

			// Collect per-container metrics for ALL containers (core + user)
			metrics, err := c.incusClient.GetContainerMetrics(ct.Name)
			if err != nil {
				continue
			}

			attrSet := []attribute.KeyValue{
				attribute.String("container.name", ct.Name),
				attribute.String("backend.id", c.config.LocalBackendID),
			}
			// Stamp the cloud container UUID as container.id when this box is a
			// cloud-managed tenant. The cloud's MetricsService scopes tenant
			// queries with {container_id="<uuid>"} (dots→underscores: the OTLP
			// container.id attr becomes the container_id VM label), so without
			// it the cloud can't join these per-container infra series
			// (cpu/mem/disk/network) to a tenant and its history panels stay
			// empty (#231). The value is the cloud_container_id container label
			// — the same source container_ips.json reads (#536); see
			// cloudContainerIDLabel in internal/server. Absent on standalone /
			// non-cloud boxes, so it's omitted rather than emitted empty.
			if cid := ct.Labels["cloud_container_id"]; cid != "" {
				attrSet = append(attrSet, attribute.String("container.id", cid))
			}
			attrs := otelmetric.WithAttributes(attrSet...)

			c.containerCPUUsage.Record(ctx, metrics.CPUUsageSeconds, attrs)
			c.containerMemUsage.Record(ctx, metrics.MemoryUsageBytes, attrs)
			c.containerDiskUsage.Record(ctx, metrics.DiskUsageBytes, attrs)
			c.containerNetRx.Record(ctx, metrics.NetworkRxBytes, attrs)
			c.containerNetTx.Record(ctx, metrics.NetworkTxBytes, attrs)
			c.containerProcessCount.Record(ctx, int64(metrics.ProcessCount), attrs)
		} else {
			// Only count user containers for aggregate stats
			if !ct.Role.IsCoreRole() {
				stopped++
			}
		}
	}

	c.containersRunning.Record(ctx, running, localAttrs)
	c.containersStopped.Record(ctx, stopped, localAttrs)

	// Collect metrics from peer backends
	if c.peerFetcher != nil {
		peerMetrics := c.peerFetcher.FetchPeerMetrics("")
		if len(peerMetrics) > 0 {
			log.Printf("[metrics] collected %d metrics from peer backends", len(peerMetrics))
		}
		for _, pm := range peerMetrics {
			attrs := otelmetric.WithAttributes(
				attribute.String("container.name", pm.ContainerName),
				attribute.String("backend.id", pm.BackendID),
			)
			c.containerCPUUsage.Record(ctx, pm.CPUUsageSeconds, attrs)
			c.containerMemUsage.Record(ctx, pm.MemoryUsageBytes, attrs)
			c.containerDiskUsage.Record(ctx, pm.DiskUsageBytes, attrs)
			c.containerNetRx.Record(ctx, pm.NetworkRxBytes, attrs)
			c.containerNetTx.Record(ctx, pm.NetworkTxBytes, attrs)
			c.containerProcessCount.Record(ctx, pm.ProcessCount, attrs)
		}
	}
}

// RecordRequestRates records edge-measured per-container request rates
// (container.request_rate) for one collection tick. The collector calls this
// only when access-log aggregation is enabled (CONTAINARIUM_ACCESS_LOG=1, a
// later wiring slice — see docs/REQUEST-RATE-PLANE-DESIGN.md); until then it
// has no callers and the plane stays dark.
//
// Samples carry their own container.id (the cloud_container_id, empty on
// standalone boxes) so the VM series joins to a tenant exactly like the bytes
// plane; backend.id is this daemon's, since the aggregator runs against the
// local edge.
func (c *Collector) RecordRequestRates(samples []reqrate.Sample) {
	for _, s := range samples {
		attrSet := []attribute.KeyValue{
			attribute.String("container.name", s.ContainerName),
			attribute.String("backend.id", c.config.LocalBackendID),
		}
		if s.ContainerID != "" {
			attrSet = append(attrSet, attribute.String("container.id", s.ContainerID))
		}
		c.containerRequestRate.Record(c.ctx, s.RequestsPerSec, otelmetric.WithAttributes(attrSet...))
	}
}

// SetPeerFetcher sets the peer metrics fetcher for collecting metrics from peer backends.
func (c *Collector) SetPeerFetcher(fetcher PeerMetricsFetcher) {
	c.peerFetcher = fetcher
}

// Stop shuts down the collector
func (c *Collector) Stop() {
	c.cancel()
	if c.shutdownFn != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := c.shutdownFn(shutdownCtx); err != nil {
			log.Printf("Warning: failed to shutdown OTel provider: %v", err)
		}
	}
	log.Printf("OTel metrics collector stopped")
}

// MeterProvider returns the OTel MeterProvider for use by HTTP middleware
func (c *Collector) MeterProvider() *sdkmetric.MeterProvider {
	return c.provider
}

// stripProtocol removes http:// or https:// from a URL
func stripProtocol(url string) string {
	if len(url) > 8 && url[:8] == "https://" {
		return url[8:]
	}
	if len(url) > 7 && url[:7] == "http://" {
		return url[7:]
	}
	return url
}
