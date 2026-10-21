package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/footprintai/containarium/internal/metrics"
	"github.com/footprintai/containarium/internal/poolcapacity"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// Per-pool storage capacity gauges (#2823). Like the bridge-DNS gauges, the
// OTel names use dots and VictoriaMetrics stores them with underscores; the
// built-in rules query the *Series spellings (pinned by a test).
const (
	storagePoolUsedName    = "storage_pool.used_bytes"
	storagePoolTotalName   = "storage_pool.total_bytes"
	storagePoolUsedSeries  = "storage_pool_used_bytes"
	storagePoolTotalSeries = "storage_pool_total_bytes"

	storagePoolInterval    = 60 * time.Second
	storagePoolReadTimeout = 10 * time.Second
)

type storagePoolRecorder struct {
	backendID   string
	used, total otelmetric.Int64Gauge
}

func newStoragePoolRecorder(provider *sdkmetric.MeterProvider, backendID string) (*storagePoolRecorder, error) {
	meter := provider.Meter("containarium.storagepool")
	used, err := meter.Int64Gauge(storagePoolUsedName, otelmetric.WithUnit("By"),
		otelmetric.WithDescription("Bytes used in an Incus storage pool, as Incus reports it"))
	if err != nil {
		return nil, fmt.Errorf("storage pool metrics: %w", err)
	}
	total, err := meter.Int64Gauge(storagePoolTotalName, otelmetric.WithUnit("By"),
		otelmetric.WithDescription("Usable size of an Incus storage pool, as Incus reports it"))
	if err != nil {
		return nil, fmt.Errorf("storage pool metrics: %w", err)
	}
	return &storagePoolRecorder{backendID: backendID, used: used, total: total}, nil
}

// record is the monitor's OnSample hook.
func (r *storagePoolRecorder) record(samples []poolcapacity.Sample) {
	ctx := context.Background()
	for _, s := range samples {
		attrs := otelmetric.WithAttributes(
			attribute.String("pool", s.Name),
			attribute.String("backend.id", r.backendID),
		)
		r.used.Record(ctx, s.UsedBytes, attrs)
		r.total.Record(ctx, s.TotalBytes, attrs)
	}
}

// startStoragePoolMonitor runs the pool capacity monitor on every daemon, so
// the WARN log exists even where no metrics pipeline is configured. mc may be
// nil (no gauges then). Reads go through their own bounded client and never
// through GET /1.0/resources (#2325).
func startStoragePoolMonitor(ctx context.Context, mc *metrics.Collector, backendID string) {
	client, err := incus.NewWithSocketAndTimeout(incus.DefaultSocketPath, storagePoolReadTimeout)
	if err != nil {
		log.Printf("Warning: storage pool capacity monitor disabled: %v", err)
		return
	}
	opts := poolcapacity.Options{Timeout: storagePoolReadTimeout}
	if mc != nil {
		rec, err := newStoragePoolRecorder(mc.MeterProvider(), backendID)
		if err != nil {
			log.Printf("Warning: storage pool metrics disabled: %v", err)
		} else {
			opts.OnSample = rec.record
		}
	}
	go poolcapacity.New(client.StoragePoolUsages, opts).Run(ctx, storagePoolInterval)
}

// storagePoolAlertRules is the vmalert group for pool fill, built from the
// series constants and thresholds and appended to DefaultAlertRules.
func storagePoolAlertRules() string {
	return fmt.Sprintf(`
  - name: storage_pool_alerts
    interval: 60s
    rules:
      - alert: StoragePoolFillWarning
        expr: %[1]s / %[2]s * 100 >= %[3]d
        for: 10m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "Storage pool {{ $labels.pool }} is filling up"
          description: "Incus storage pool {{ $labels.pool }} is {{ $value | printf \"%%.1f\" }}%% full (>= %[3]d%%). Free space now: prune snapshots or images, or grow the pool."

      - alert: StoragePoolNearlyFull
        expr: %[1]s / %[2]s * 100 >= %[4]d
        for: 2m
        labels:
          severity: critical
          source: default
        annotations:
          summary: "Storage pool {{ $labels.pool }} is nearly full"
          description: "Incus storage pool {{ $labels.pool }} is {{ $value | printf \"%%.1f\" }}%% full (>= %[4]d%%). When it fills, every container on it, core Postgres included, stops writing. Act now."
`, storagePoolUsedSeries, storagePoolTotalSeries, poolcapacity.WarnPercent, poolcapacity.CritPercent)
}
