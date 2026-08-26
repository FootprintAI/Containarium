package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// toProtoMetrics is the last hop before the wire. A field dropped here reaches
// every consumer — REST, gRPC, the MCP get_metrics tool, and peer-forwarded
// responses — as a zero, which for the throttling counters reads as
// "not reported" and silently restores the #1573 blind spot.
func TestToProtoMetricsCarriesEveryField(t *testing.T) {
	in := &incus.ContainerMetrics{
		Name:             "alice-container",
		CPUUsageSeconds:  1234,
		MemoryUsageBytes: 2048,
		MemoryLimitBytes: 4096,
		DiskUsageBytes:   8192,
		NetworkRxBytes:   16,
		NetworkTxBytes:   32,
		ProcessCount:     7,
		CPUNrPeriods:     40031,
		CPUNrThrottled:   12847,
		CPUThrottledUsec: 98765432,
	}

	got := toProtoMetrics(in)

	checks := []struct {
		field string
		got   int64
		want  int64
	}{
		{"CpuUsageSeconds", got.CpuUsageSeconds, 1234},
		{"MemoryUsageBytes", got.MemoryUsageBytes, 2048},
		{"MemoryPeakBytes", got.MemoryPeakBytes, 4096},
		{"DiskUsageBytes", got.DiskUsageBytes, 8192},
		{"NetworkRxBytes", got.NetworkRxBytes, 16},
		{"NetworkTxBytes", got.NetworkTxBytes, 32},
		{"CpuNrPeriods", got.CpuNrPeriods, 40031},
		{"CpuNrThrottled", got.CpuNrThrottled, 12847},
		{"CpuThrottledUsec", got.CpuThrottledUsec, 98765432},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.field, c.got, c.want)
		}
	}
	if got.Name != "alice-container" {
		t.Errorf("Name = %q, want %q", got.Name, "alice-container")
	}
	if got.ProcessCount != 7 {
		t.Errorf("ProcessCount = %d, want 7", got.ProcessCount)
	}
}

// A box whose runtime reports no throttling signal must come back as zeros
// rather than inventing a value — the MCP layer renders that as
// "not reported", which is a different claim from "not throttled".
func TestToProtoMetricsLeavesUnreportedThrottlingAtZero(t *testing.T) {
	got := toProtoMetrics(&incus.ContainerMetrics{Name: "bob-container", CPUUsageSeconds: 5})

	if got.CpuNrPeriods != 0 || got.CpuNrThrottled != 0 || got.CpuThrottledUsec != 0 {
		t.Errorf("unreported throttling should stay zero, got periods %d, throttled %d, usec %d",
			got.CpuNrPeriods, got.CpuNrThrottled, got.CpuThrottledUsec)
	}
}
