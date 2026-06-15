package capabilities

import (
	"testing"
	"time"
)

func TestMeasuredClass(t *testing.T) {
	cases := []struct {
		name string
		f    HostFacts
		want string
	}{
		{"gpu beats core count", HostFacts{GPUAvailable: true, CPUCores: 4}, ClassGPU},
		{"large cpu", HostFacts{CPUCores: 32}, ClassCPULarge},
		{"exactly threshold is large", HostFacts{CPUCores: cpuLargeCoreThreshold}, ClassCPULarge},
		{"small cpu", HostFacts{CPUCores: 4}, ClassCPUSmall},
		{"zero cores small", HostFacts{}, ClassCPUSmall},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MeasuredClass(tc.f); got != tc.want {
				t.Fatalf("MeasuredClass = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestComputeClassReconciliation(t *testing.T) {
	cases := []struct {
		name        string
		f           HostFacts
		wantClass   string
		wantConsist bool
	}{
		{"empty reported is consistent", HostFacts{CPUCores: 4}, ClassCPUSmall, true},
		{"exact match", HostFacts{GPUAvailable: true, ReportedClass: "gpu"}, ClassGPU, true},
		{"reported names bucket", HostFacts{GPUAvailable: true, ReportedClass: "gpu-spot"}, ClassGPU, true},
		{"case insensitive", HostFacts{CPUCores: 32, ReportedClass: "CPU-Large"}, ClassCPULarge, true},
		{"drift: reported gpu but cpu-only", HostFacts{CPUCores: 4, ReportedClass: "gpu"}, ClassCPUSmall, false},
		{"drift: reported small but large", HostFacts{CPUCores: 64, ReportedClass: "tiny"}, ClassCPULarge, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Compute(tc.f)
			if p.MeasuredClass != tc.wantClass {
				t.Fatalf("MeasuredClass = %q, want %q", p.MeasuredClass, tc.wantClass)
			}
			if p.ClassConsistent != tc.wantConsist {
				t.Fatalf("ClassConsistent = %v, want %v", p.ClassConsistent, tc.wantConsist)
			}
		})
	}
}

func TestComputeCarriesFields(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	f := HostFacts{
		CPUCores:         8,
		CPUModel:         "Test CPU",
		TotalMemoryBytes: 1 << 34,
		TotalDiskBytes:   1 << 40,
		Region:           "region-a",
		ReportedClass:    "cpu-small",
		Benchmark:        Benchmark{CPUOpsPerSec: 100, MemBytesPerSec: 200, DurationMs: 5},
		Now:              now,
	}
	p := Compute(f)
	if p.CPUModel != "Test CPU" || p.Region != "region-a" || p.TotalMemoryBytes != 1<<34 {
		t.Fatalf("fields not carried: %+v", p)
	}
	if !p.ProfiledAt.Equal(now) {
		t.Fatalf("ProfiledAt = %v, want %v", p.ProfiledAt, now)
	}
	if p.Benchmark.CPUOpsPerSec != 100 {
		t.Fatalf("benchmark not carried: %+v", p.Benchmark)
	}
}

func TestStoreRecordAndCurrent(t *testing.T) {
	s := NewStore()
	if _, ok := s.Current(); ok {
		t.Fatalf("fresh store must report no profile")
	}
	p := s.Record(HostFacts{CPUCores: 4, Now: time.Now()})
	if p.MeasuredClass != ClassCPUSmall {
		t.Fatalf("recorded class = %q", p.MeasuredClass)
	}
	got, ok := s.Current()
	if !ok {
		t.Fatalf("Current must report a profile after Record")
	}
	if got.MeasuredClass != ClassCPUSmall {
		t.Fatalf("Current class = %q", got.MeasuredClass)
	}
	// Current returns a copy: mutating it must not affect the store.
	got.MeasuredClass = "mutated"
	again, _ := s.Current()
	if again.MeasuredClass != ClassCPUSmall {
		t.Fatalf("store mutated through returned copy: %q", again.MeasuredClass)
	}
}
