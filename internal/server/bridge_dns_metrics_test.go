package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/footprintai/containarium/internal/bridgedns"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// collectGauges returns the int64 gauge values the provider currently holds,
// keyed by OTel instrument name.
func collectGauges(t *testing.T, rd *metric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok || len(g.DataPoints) == 0 {
				continue
			}
			out[m.Name] = g.DataPoints[len(g.DataPoints)-1].Value
		}
	}
	return out
}

func TestBridgeDNSRecorder(t *testing.T) {
	pass := time.Unix(1_700_000_000, 0)
	applied := time.Unix(1_699_999_000, 0)
	for _, tc := range []struct {
		name string
		st   bridgedns.Status
		want map[string]int64
	}{
		{"pending: nothing recorded", bridgedns.Status{}, map[string]int64{}},
		{"in sync", bridgedns.Status{InSync: true, LastPass: pass, DriftCount: 2, LastApplied: applied},
			map[string]int64{bridgeDNSInSyncName: 1, bridgeDNSDriftPassesName: 2, bridgeDNSLastPassName: pass.Unix(), bridgeDNSLastAppliedName: applied.Unix()}},
		{"degraded", bridgedns.Status{InSync: false, LastPass: pass, LastError: "boom"},
			map[string]int64{bridgeDNSInSyncName: 0, bridgeDNSDriftPassesName: 0, bridgeDNSLastPassName: pass.Unix()}},
		{"absent by opt-out is not out of sync", bridgedns.Status{Absent: true, LastPass: pass},
			map[string]int64{bridgeDNSDriftPassesName: 0, bridgeDNSLastPassName: pass.Unix()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rd := metric.NewManualReader()
			rec, err := newBridgeDNSRecorder(metric.NewMeterProvider(metric.WithReader(rd)))
			if err != nil {
				t.Fatal(err)
			}
			rec.record(tc.st)
			got := collectGauges(t, rd)
			if len(got) != len(tc.want) {
				t.Fatalf("series = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
				}
			}
		})
	}
}

// Drift counted by the reconciler reaches the gauge across passes, and a
// failing pass still records (in_sync 0, fresh pass timestamp).
func TestBridgeDNSRecorder_FollowsReconciler(t *testing.T) {
	rd := metric.NewManualReader()
	rec, _ := newBridgeDNSRecorder(metric.NewMeterProvider(metric.WithReader(rd)))
	be := &metricsBridgeBackend{ip: "10.0.0.5", current: "stale"}
	r := bridgedns.NewReconciler(be, bridgedns.Config{
		Bridge: "incusbr0", CaddyContainer: "core-caddy",
		Render: func(ip string) string { return "addr=" + ip },
		OnPass: rec.record,
	})
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := collectGauges(t, rd); got[bridgeDNSInSyncName] != 1 || got[bridgeDNSDriftPassesName] != 1 {
		t.Fatalf("after repair: %v, want in_sync=1 drift_passes=1", got)
	}
	be.current = "stale again"
	_ = r.ReconcileOnce(context.Background())
	if got := collectGauges(t, rd); got[bridgeDNSDriftPassesName] != 2 {
		t.Errorf("drift_passes = %d, want 2", got[bridgeDNSDriftPassesName])
	}
	be.getErr = context.DeadlineExceeded
	_ = r.ReconcileOnce(context.Background())
	if got := collectGauges(t, rd); got[bridgeDNSInSyncName] != 0 {
		t.Errorf("failed pass: in_sync = %d, want 0", got[bridgeDNSInSyncName])
	}
}

type metricsBridgeBackend struct {
	ip, current string
	getErr      error
}

func (f *metricsBridgeBackend) GetContainer(string) (*incus.ContainerInfo, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &incus.ContainerInfo{State: "Running", IPAddress: f.ip}, nil
}
func (f *metricsBridgeBackend) GetNetworkConfigValue(string, string) (string, error) {
	return f.current, nil
}
func (f *metricsBridgeBackend) SetNetworkConfigValue(_, _, v string) error { f.current = v; return nil }

// The rule expressions and the recorder share one set of names, and the
// OTel name maps onto the stored series name by dots → underscores.
func TestBridgeDNSAlertRules(t *testing.T) {
	for otel, series := range map[string]string{
		bridgeDNSInSyncName:      bridgeDNSInSyncSeries,
		bridgeDNSDriftPassesName: bridgeDNSDriftPassesSeries,
		bridgeDNSLastPassName:    bridgeDNSLastPassSeries,
		bridgeDNSLastAppliedName: bridgeDNSLastAppliedSeries,
	} {
		if strings.ReplaceAll(otel, ".", "_") != series {
			t.Errorf("series %q does not match instrument %q", series, otel)
		}
	}

	rules, err := parseDefaultAlertRules()
	if err != nil {
		t.Fatalf("DefaultAlertRules no longer parses: %v", err)
	}
	want := map[string]struct{ series, severity string }{
		"BridgeDNSOutOfSync":       {bridgeDNSInSyncSeries, "critical"},
		"BridgeDNSReconcilerStale": {bridgeDNSLastPassSeries, "warning"},
		"BridgeDNSDriftRepeating":  {bridgeDNSDriftPassesSeries, "warning"},
	}
	seen := 0
	for _, r := range rules {
		w, ok := want[r.GetName()]
		if !ok {
			continue
		}
		seen++
		if !strings.Contains(r.GetExpr(), w.series) {
			t.Errorf("%s expr %q does not query %s", r.GetName(), r.GetExpr(), w.series)
		}
		if r.GetSeverity() != w.severity {
			t.Errorf("%s severity = %q, want %q", r.GetName(), r.GetSeverity(), w.severity)
		}
		if r.GetAnnotations()["summary"] == "" || r.GetAnnotations()["description"] == "" {
			t.Errorf("%s needs summary and description annotations", r.GetName())
		}
		if r.GetLabels()["source"] != "default" {
			t.Errorf("%s source label = %q, want default", r.GetName(), r.GetLabels()["source"])
		}
	}
	if seen != len(want) {
		t.Errorf("found %d of %d bridge DNS rules in DefaultAlertRules", seen, len(want))
	}
	// Every default rule, new or old, must carry source=default.
	if got := strings.Count(DefaultAlertRules, "source: default"); got != strings.Count(DefaultAlertRules, "- alert:") {
		t.Errorf("%d rules but %d carry source: default", strings.Count(DefaultAlertRules, "- alert:"), got)
	}
}
