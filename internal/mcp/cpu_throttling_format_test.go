package mcp

import (
	"strings"
	"testing"
)

func TestFormatCPUThrottling(t *testing.T) {
	tests := []struct {
		name    string
		metrics ContainerMetrics
		want    string
	}{
		{
			// The case the whole feature exists for: usage looks low, and this
			// line is what says the box is hitting its ceiling rather than idling.
			name: "heavily throttled box",
			metrics: ContainerMetrics{
				CPUNrPeriods: 40031, CPUNrThrottled: 12847, CPUThrottledUsec: 98765432,
			},
			want: "   CPU Throttling: 12847/40031 periods (32.1%), 98.8s throttled\n",
		},
		{
			// Signal present, value zero — a real "not throttled" finding, which
			// must read differently from "nothing was measured".
			name: "unthrottled box with a live signal",
			metrics: ContainerMetrics{
				CPUNrPeriods: 8123, CPUNrThrottled: 0, CPUThrottledUsec: 0,
			},
			want: "   CPU Throttling: 0/8123 periods (0.0%), 0.0s throttled\n",
		},
		{
			name:    "no signal available",
			metrics: ContainerMetrics{},
			want:    "   CPU Throttling: not reported\n",
		},
		{
			name: "no periods but stale counters — still no signal, no divide by zero",
			metrics: ContainerMetrics{
				CPUNrPeriods: 0, CPUNrThrottled: 5, CPUThrottledUsec: 100,
			},
			want: "   CPU Throttling: not reported\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatCPUThrottling(tt.metrics); got != tt.want {
				t.Errorf("formatCPUThrottling()\n got = %q\nwant = %q", got, tt.want)
			}
		})
	}
}

// A throttled box and an idle box must not render identically — that
// indistinguishability is the defect #1573 records.
func TestFormatCPUThrottlingDistinguishesThrottledFromIdle(t *testing.T) {
	throttled := formatCPUThrottling(ContainerMetrics{
		CPUNrPeriods: 1000, CPUNrThrottled: 900, CPUThrottledUsec: 5_000_000,
	})
	idle := formatCPUThrottling(ContainerMetrics{
		CPUNrPeriods: 1000, CPUNrThrottled: 0, CPUThrottledUsec: 0,
	})

	if throttled == idle {
		t.Fatal("throttled and idle boxes render identically — the whole point of #1573 is that they must not")
	}
	if !strings.Contains(throttled, "90.0%") {
		t.Errorf("throttled box should surface its throttled share, got %q", throttled)
	}
}
