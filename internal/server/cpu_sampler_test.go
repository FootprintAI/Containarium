package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/metrics"
	"github.com/footprintai/containarium/internal/threatdetect"
)

// TestCPUSamplerDeltas pins the sampler's delta rules (#2635): the first
// reading of a container is dropped (no delta), a steady counter yields its
// rate in cores, a counter that went backwards (restart) is dropped, a
// non-advancing clock is dropped, and a container that disappears starts
// over.
func TestCPUSamplerDeltas(t *testing.T) {
	t0 := time.Unix(1_760_140_800, 0)
	reading := func(name string, usage int64) metrics.ContainerCPUReading {
		return metrics.ContainerCPUReading{Name: name, IPAddress: "10.0.0.5", CPULimit: "250m", CPUUsageSeconds: usage}
	}
	type tick struct {
		at       time.Time
		readings []metrics.ContainerCPUReading
		want     []float64 // cores of emitted samples, in order; nil = no call
	}
	cases := []struct {
		name  string
		ticks []tick
	}{
		{"first sample dropped, then steady 2.0 cores", []tick{
			{t0, []metrics.ContainerCPUReading{reading("box", 100)}, nil},
			{t0.Add(30 * time.Second), []metrics.ContainerCPUReading{reading("box", 160)}, []float64{2.0}},
			{t0.Add(60 * time.Second), []metrics.ContainerCPUReading{reading("box", 220)}, []float64{2.0}},
		}},
		{"counter reset on restart is dropped", []tick{
			{t0, []metrics.ContainerCPUReading{reading("box", 1000)}, nil},
			{t0.Add(30 * time.Second), []metrics.ContainerCPUReading{reading("box", 5)}, nil},
			{t0.Add(60 * time.Second), []metrics.ContainerCPUReading{reading("box", 20)}, []float64{0.5}},
		}},
		{"clock skew guarded", []tick{
			{t0, []metrics.ContainerCPUReading{reading("box", 100)}, nil},
			{t0, []metrics.ContainerCPUReading{reading("box", 130)}, nil},
			{t0.Add(-time.Second), []metrics.ContainerCPUReading{reading("box", 140)}, nil},
		}},
		{"vanished container starts over", []tick{
			{t0, []metrics.ContainerCPUReading{reading("box", 100)}, nil},
			{t0.Add(30 * time.Second), nil, nil},
			{t0.Add(60 * time.Second), []metrics.ContainerCPUReading{reading("box", 400)}, nil},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got [][]threatdetect.CPUSample
			s := NewCPUSampler(func(samples []threatdetect.CPUSample) { got = append(got, samples) })
			for i, tk := range tc.ticks {
				got = nil
				s.Observe(tk.at, tk.readings)
				if tk.want == nil {
					if len(got) != 0 {
						t.Fatalf("tick %d: emitted %+v, want nothing", i, got)
					}
					continue
				}
				if len(got) != 1 || len(got[0]) != len(tk.want) {
					t.Fatalf("tick %d: emitted %+v, want %d samples", i, got, len(tk.want))
				}
				for j, w := range tk.want {
					smp := got[0][j]
					if smp.Cores != w || smp.Container != "box" || smp.At != tk.at {
						t.Errorf("tick %d sample %d = %+v, want %v cores at %v", i, j, smp, w, tk.at)
					}
					if smp.IP != netip.MustParseAddr("10.0.0.5") || smp.LimitCores != 0.25 {
						t.Errorf("tick %d sample %d ip/limit = %v/%v, want 10.0.0.5/0.25", i, j, smp.IP, smp.LimitCores)
					}
				}
			}
		})
	}
}

func TestCPUSampler_NoLimitAndBadIP(t *testing.T) {
	t0 := time.Unix(0, 0)
	var got []threatdetect.CPUSample
	s := NewCPUSampler(func(samples []threatdetect.CPUSample) { got = samples })
	s.Observe(t0, []metrics.ContainerCPUReading{{Name: "a", IPAddress: "", CPUUsageSeconds: 0}, {Name: "b", IPAddress: "not-an-ip", CPUUsageSeconds: 0}})
	s.Observe(t0.Add(10*time.Second), []metrics.ContainerCPUReading{{Name: "a", IPAddress: "", CPUUsageSeconds: 10}, {Name: "b", IPAddress: "not-an-ip", CPUUsageSeconds: 10}})
	if len(got) != 2 {
		t.Fatalf("got %+v, want two samples", got)
	}
	for _, smp := range got {
		if smp.LimitCores != 0 || smp.IP.IsValid() || smp.Cores != 1 {
			t.Errorf("sample %+v, want unlimited, invalid IP, 1 core", smp)
		}
	}
}
