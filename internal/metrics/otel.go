package metrics

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/footprintai/containarium/internal/incus"
)

// CollectorConfig holds configuration for the OTel metrics collector
type CollectorConfig struct {
	// VictoriaMetricsURL is the base URL for Victoria Metrics (e.g., "http://10.100.0.x:8428")
	VictoriaMetricsURL string

	// CollectionInterval is how often to collect metrics (default 30s)
	CollectionInterval time.Duration

	// ServiceName is the OTel service name (default "containarium")
	ServiceName string
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

	// System metric instruments
	systemCPUCount    otelmetric.Int64Gauge
	systemMemTotal    otelmetric.Int64Gauge
	systemMemUsed     otelmetric.Int64Gauge
	systemDiskTotal   otelmetric.Int64Gauge
	systemDiskUsed    otelmetric.Int64Gauge
	systemCPULoad1m   otelmetric.Float64Gauge
	systemCPULoad5m   otelmetric.Float64Gauge
	systemCPULoad15m  otelmetric.Float64Gauge

	// Container metric instruments
	containerCPUUsage     otelmetric.Int64Gauge
	containerMemUsage     otelmetric.Int64Gauge
	containerDiskUsage    otelmetric.Int64Gauge
	containerNetRx        otelmetric.Int64Gauge
	containerNetTx        otelmetric.Int64Gauge
	containerProcessCount otelmetric.Int64Gauge

	// Aggregate instruments
	containersRunning otelmetric.Int64Gauge
	containersStopped otelmetric.Int64Gauge

	ctx    context.Context
	cancel context.CancelFunc
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

	// Create OTLP/HTTP exporter targeting Victoria Metrics
	endpoint := config.VictoriaMetricsURL
	// Strip protocol for otlpmetrichttp (it adds its own)
	endpoint = stripProtocol(endpoint)

	exporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(endpoint),
		otlpmetrichttp.WithURLPath("/opentelemetry/api/v1/push"),
		otlpmetrichttp.WithInsecure(),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service name
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
		),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create MeterProvider with periodic reader
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(config.CollectionInterval),
		)),
		sdkmetric.WithResource(res),
	)

	c := &Collector{
		config:      config,
		incusClient: incusClient,
		provider:    provider,
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

	// Collect system metrics
	sysRes, err := c.incusClient.GetSystemResources()
	if err != nil {
		log.Printf("Warning: failed to collect system metrics: %v", err)
	} else {
		c.systemCPUCount.Record(ctx, int64(sysRes.TotalCPUs))
		c.systemMemTotal.Record(ctx, sysRes.TotalMemoryBytes)
		c.systemMemUsed.Record(ctx, sysRes.UsedMemoryBytes)
		c.systemDiskTotal.Record(ctx, sysRes.TotalDiskBytes)
		c.systemDiskUsed.Record(ctx, sysRes.UsedDiskBytes)
		c.systemCPULoad1m.Record(ctx, sysRes.CPULoad1Min)
		c.systemCPULoad5m.Record(ctx, sysRes.CPULoad5Min)
		c.systemCPULoad15m.Record(ctx, sysRes.CPULoad15Min)
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

			attrs := otelmetric.WithAttributes(
				attribute.String("container.name", ct.Name),
			)

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

	c.containersRunning.Record(ctx, running)
	c.containersStopped.Record(ctx, stopped)
}

// Stop shuts down the collector
func (c *Collector) Stop() {
	c.cancel()
	if c.provider != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := c.provider.Shutdown(shutdownCtx); err != nil {
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
