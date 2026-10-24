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

	// ZFS-only (#2853): what Incus does not expose. Recorded only for a pool
	// whose `zpool list` answered, and the fragmentation one only when zpool
	// reported it.
	storagePoolZpoolCapacityName   = "storage_pool.zpool_capacity_percent"
	storagePoolFragmentationName   = "storage_pool.fragmentation_percent"
	storagePoolZpoolCapacitySeries = "storage_pool_zpool_capacity_percent"
	storagePoolFragmentationSeries = "storage_pool_fragmentation_percent"

	storagePoolInterval    = 60 * time.Second
	storagePoolReadTimeout = 10 * time.Second
)

type storagePoolRecorder struct {
	backendID           string
	used, total         otelmetric.Int64Gauge
	zpoolCap, zpoolFrag otelmetric.Int64Gauge
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
	zcap, err := meter.Int64Gauge(storagePoolZpoolCapacityName, otelmetric.WithUnit("%"),
		otelmetric.WithDescription("A ZFS pool's capacity as zpool list reports it (ZFS pools only; slop space included, unlike used/total)"))
	if err != nil {
		return nil, fmt.Errorf("storage pool metrics: %w", err)
	}
	zfrag, err := meter.Int64Gauge(storagePoolFragmentationName, otelmetric.WithUnit("%"),
		otelmetric.WithDescription("A ZFS pool's free-space fragmentation as zpool list reports it (ZFS pools only)"))
	if err != nil {
		return nil, fmt.Errorf("storage pool metrics: %w", err)
	}
	return &storagePoolRecorder{backendID: backendID, used: used, total: total, zpoolCap: zcap, zpoolFrag: zfrag}, nil
}

// record is the monitor's OnSample hook: this daemon's own pools.
func (r *storagePoolRecorder) record(samples []poolcapacity.Sample) {
	for _, s := range samples {
		r.recordOne(r.backendID, s.StoragePoolUsage)
	}
}

// recordPeer records a peer backend's pools, read from its forwarded
// GetSystemInfo, under the peer's backend id.
func (r *storagePoolRecorder) recordPeer(backendID string, pools []incus.StoragePoolUsage) {
	for _, p := range pools {
		r.recordOne(backendID, p)
	}
}

func (r *storagePoolRecorder) recordOne(backendID string, p incus.StoragePoolUsage) {
	attrs := otelmetric.WithAttributes(attribute.String("pool", p.Name), attribute.String("backend.id", backendID))
	r.used.Record(context.Background(), p.UsedBytes, attrs)
	r.total.Record(context.Background(), p.TotalBytes, attrs)
	if z := p.Zpool; z != nil {
		r.zpoolCap.Record(context.Background(), z.CapacityPercent, attrs)
		if z.FragmentationKnown {
			r.zpoolFrag.Record(context.Background(), z.FragmentationPercent, attrs)
		}
	}
}

// startStoragePoolMonitor runs the pool capacity monitor on every daemon, so
// the WARN log exists even where no metrics pipeline is configured. mc may be
// nil (no gauges then); when set, peers' pools are recorded too. Reads go
// through their own bounded client and never through GET /1.0/resources
// (#2325). Returns nil when the monitor could not start.
func startStoragePoolMonitor(ctx context.Context, mc *metrics.Collector, backendID string) *poolcapacity.Monitor {
	client, err := incus.NewWithSocketAndTimeout(incus.DefaultSocketPath, storagePoolReadTimeout)
	if err != nil {
		log.Printf("Warning: storage pool capacity monitor disabled: %v", err)
		return nil
	}
	opts := poolcapacity.Options{Timeout: storagePoolReadTimeout}
	if mc != nil {
		rec, err := newStoragePoolRecorder(mc.MeterProvider(), backendID)
		if err != nil {
			log.Printf("Warning: storage pool metrics disabled: %v", err)
		} else {
			opts.OnSample = rec.record
			mc.SetPeerStoragePoolHook(rec.recordPeer)
		}
	}
	// ZFS pools also get zpool's raw capacity and fragmentation (#2853), each
	// read under its own short deadline so a hung zpool never delays the tick.
	m := poolcapacity.New(poolcapacity.WithZpool(client.StoragePoolUsages, poolcapacity.ExecRunner, poolcapacity.ZpoolDeadline), opts)
	go m.Run(ctx, storagePoolInterval)
	return m
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
