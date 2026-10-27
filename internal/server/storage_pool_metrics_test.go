package server

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/footprintai/containarium/internal/poolcapacity"
	"github.com/footprintai/containarium/pkg/core/incus"
)

func TestStoragePoolRecorder_PerPoolGauges(t *testing.T) {
	rd := metric.NewManualReader()
	rec, err := newStoragePoolRecorder(metric.NewMeterProvider(metric.WithReader(rd)), "backend-a")
	if err != nil {
		t.Fatal(err)
	}
	rec.record([]poolcapacity.Sample{
		{StoragePoolUsage: incus.StoragePoolUsage{Name: "p1", UsedBytes: 96, TotalBytes: 100}},
		{StoragePoolUsage: incus.StoragePoolUsage{Name: "p2", UsedBytes: 5, TotalBytes: 100}},
	})

	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{} // "<instrument>/<pool>" -> value
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				continue
			}
			for _, dp := range g.DataPoints {
				pool, _ := dp.Attributes.Value(attribute.Key("pool"))
				if b, _ := dp.Attributes.Value(attribute.Key("backend.id")); b.AsString() != "backend-a" {
					t.Errorf("%s missing backend.id label: %v", m.Name, dp.Attributes)
				}
				got[m.Name+"/"+pool.AsString()] = dp.Value
			}
		}
	}
	want := map[string]int64{
		storagePoolUsedName + "/p1": 96, storagePoolTotalName + "/p1": 100,
		storagePoolUsedName + "/p2": 5, storagePoolTotalName + "/p2": 100,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all %v)", k, got[k], v, got)
		}
	}
}

func TestStoragePoolAlertRules(t *testing.T) {
	for otel, series := range map[string]string{
		storagePoolUsedName:  storagePoolUsedSeries,
		storagePoolTotalName: storagePoolTotalSeries,
	} {
		if strings.ReplaceAll(otel, ".", "_") != series {
			t.Errorf("series %q does not match instrument %q", series, otel)
		}
	}
	rules, err := parseDefaultAlertRules()
	if err != nil {
		t.Fatalf("DefaultAlertRules no longer parses: %v", err)
	}
	want := map[string]struct {
		severity, threshold string
	}{
		"StoragePoolFillWarning": {"warning", ">= 85"},
		"StoragePoolNearlyFull":  {"critical", ">= 95"},
	}
	seen := 0
	for _, r := range rules {
		w, ok := want[r.GetName()]
		if !ok {
			continue
		}
		seen++
		for _, s := range []string{storagePoolUsedSeries, storagePoolTotalSeries, w.threshold} {
			if !strings.Contains(r.GetExpr(), s) {
				t.Errorf("%s expr %q lacks %q", r.GetName(), r.GetExpr(), s)
			}
		}
		if r.GetSeverity() != w.severity {
			t.Errorf("%s severity = %q, want %q", r.GetName(), r.GetSeverity(), w.severity)
		}
		if r.GetLabels()["source"] != "default" || r.GetAnnotations()["description"] == "" {
			t.Errorf("%s needs source=default and a description", r.GetName())
		}
	}
	if seen != len(want) {
		t.Errorf("found %d of %d storage pool rules in DefaultAlertRules", seen, len(want))
	}
}

// A peer's pools are recorded under the peer's backend id.
func TestStoragePoolRecorder_PeerBackendLabel(t *testing.T) {
	rd := metric.NewManualReader()
	rec, err := newStoragePoolRecorder(metric.NewMeterProvider(metric.WithReader(rd)), "local")
	if err != nil {
		t.Fatal(err)
	}
	rec.recordPeer("peer-a", []incus.StoragePoolUsage{{Name: "p1", UsedBytes: 96, TotalBytes: 100}})
	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			for _, dp := range m.Data.(metricdata.Gauge[int64]).DataPoints {
				n++
				if b, _ := dp.Attributes.Value(attribute.Key("backend.id")); b.AsString() != "peer-a" {
					t.Errorf("%s backend.id = %q, want peer-a", m.Name, b.AsString())
				}
			}
		}
	}
	if n != 2 {
		t.Errorf("got %d data points, want 2 (used + total)", n)
	}
}

// #2853: the ZFS-only gauges are recorded for the pools that have zpool
// numbers, under the same labels, and fragmentation only when zpool gave one.
func TestStoragePoolRecorder_ZpoolGauges(t *testing.T) {
	rd := metric.NewManualReader()
	rec, err := newStoragePoolRecorder(metric.NewMeterProvider(metric.WithReader(rd)), "backend-a")
	if err != nil {
		t.Fatal(err)
	}
	rec.record([]poolcapacity.Sample{
		{StoragePoolUsage: incus.StoragePoolUsage{Name: "z1", UsedBytes: 1, TotalBytes: 100,
			Zpool: &incus.ZpoolStat{CapacityPercent: 41, FragmentationPercent: 17, FragmentationKnown: true}}},
		{StoragePoolUsage: incus.StoragePoolUsage{Name: "z2", UsedBytes: 1, TotalBytes: 100,
			Zpool: &incus.ZpoolStat{CapacityPercent: 9}}}, // fragmentation not available
		{StoragePoolUsage: incus.StoragePoolUsage{Name: "plain", UsedBytes: 1, TotalBytes: 100}}, // not ZFS
	})

	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				continue
			}
			for _, dp := range g.DataPoints {
				pool, _ := dp.Attributes.Value(attribute.Key("pool"))
				if b, _ := dp.Attributes.Value(attribute.Key("backend.id")); b.AsString() != "backend-a" {
					t.Errorf("%s missing backend.id label: %v", m.Name, dp.Attributes)
				}
				got[m.Name+"/"+pool.AsString()] = dp.Value
			}
		}
	}
	want := map[string]int64{
		storagePoolZpoolCapacityName + "/z1": 41, storagePoolFragmentationName + "/z1": 17,
		storagePoolZpoolCapacityName + "/z2": 9,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all %v)", k, got[k], v, got)
		}
	}
	for _, absent := range []string{storagePoolFragmentationName + "/z2", storagePoolZpoolCapacityName + "/plain", storagePoolFragmentationName + "/plain"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s was recorded although zpool gave no number for it", absent)
		}
	}
	if strings.ReplaceAll(storagePoolFragmentationName, ".", "_") != storagePoolFragmentationSeries ||
		strings.ReplaceAll(storagePoolZpoolCapacityName, ".", "_") != storagePoolZpoolCapacitySeries {
		t.Error("the Series spellings do not match the instrument names")
	}
}
