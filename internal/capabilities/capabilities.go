// Package capabilities turns a backend's host system info, GPU passthrough
// probe, and a bounded CPU/memory micro-benchmark into an explicit capability
// profile recorded at join. The control plane reads the profile through the
// backend surface (ListBackends) to place work by measured hardware class
// rather than by a self-reported class alone, and to detect a backend whose
// measured class drifts from what it reports.
//
// The compute is pure (no proto, no Incus dependency) so it is unit-testable in
// isolation; the server gathers the inputs and maps the result onto the wire
// type. A small concurrent Store holds the last-recorded profile per daemon.
// See #681.
package capabilities

import (
	"strings"
	"sync"
	"time"
)

// Hardware-class buckets. Coarse on purpose — the control plane refines
// placement from the raw figures; these only give a stable label to reconcile
// the self-reported class against. Generic capacity wording only.
const (
	ClassGPU      = "gpu"
	ClassCPULarge = "cpu-large"
	ClassCPUSmall = "cpu-small"
)

// cpuLargeCoreThreshold is the core count at or above which a CPU-only backend
// is classed "cpu-large". Below it, "cpu-small".
const cpuLargeCoreThreshold = 16

// Benchmark mirrors container.BenchmarkResult but stays free of any other
// package dependency so the profile compute is self-contained.
type Benchmark struct {
	CPUOpsPerSec   int64
	MemBytesPerSec int64
	DurationMs     int64
}

// HostFacts is the snapshot the profile compute consumes. The caller (the
// daemon) gathers it from SystemInfo (CPU cores, RAM, disk), the GPU
// passthrough probe (model/driver/available), the micro-benchmark, the region,
// and the self-reported class.
type HostFacts struct {
	CPUCores         int32
	CPUModel         string
	TotalMemoryBytes int64
	TotalDiskBytes   int64

	GPUModel         string
	GPUDriverVersion string
	GPUAvailable     bool

	Region        string
	ReportedClass string

	Benchmark Benchmark

	// Now is injected so callers/tests can pin the recorded timestamp.
	Now time.Time
}

// Profile is the computed capability profile. It mirrors pb.CapabilityProfile
// but carries no proto dependency; the server maps it onto the wire type.
type Profile struct {
	CPUCores         int32
	CPUModel         string
	TotalMemoryBytes int64
	TotalDiskBytes   int64

	GPUModel         string
	GPUDriverVersion string
	GPUAvailable     bool

	Region          string
	ReportedClass   string
	MeasuredClass   string
	ClassConsistent bool

	Benchmark  Benchmark
	ProfiledAt time.Time
}

// MeasuredClass derives the coarse hardware-class bucket from the facts: any
// usable GPU makes it a GPU backend; otherwise core count splits large from
// small.
func MeasuredClass(f HostFacts) string {
	if f.GPUAvailable {
		return ClassGPU
	}
	if f.CPUCores >= cpuLargeCoreThreshold {
		return ClassCPULarge
	}
	return ClassCPUSmall
}

// classConsistent reports whether the measured class is consistent with the
// self-reported one. An empty reported class is treated as consistent (the
// operator declared nothing to reconcile against). The comparison is
// case-insensitive and substring-tolerant so a reported "gpu-pool" reconciles
// against measured "gpu".
func classConsistent(reported, measured string) bool {
	r := strings.ToLower(strings.TrimSpace(reported))
	if r == "" {
		return true
	}
	m := strings.ToLower(strings.TrimSpace(measured))
	if r == m {
		return true
	}
	// A reported class that names the measured bucket (e.g. "gpu-spot" vs
	// "gpu", "cpu-large-pool" vs "cpu-large") is consistent.
	return strings.Contains(r, m) || strings.Contains(m, r)
}

// Compute derives the profile from a HostFacts snapshot. Pure: no I/O.
func Compute(f HostFacts) Profile {
	measured := MeasuredClass(f)
	return Profile{
		CPUCores:         f.CPUCores,
		CPUModel:         f.CPUModel,
		TotalMemoryBytes: f.TotalMemoryBytes,
		TotalDiskBytes:   f.TotalDiskBytes,
		GPUModel:         f.GPUModel,
		GPUDriverVersion: f.GPUDriverVersion,
		GPUAvailable:     f.GPUAvailable,
		Region:           f.Region,
		ReportedClass:    f.ReportedClass,
		MeasuredClass:    measured,
		ClassConsistent:  classConsistent(f.ReportedClass, measured),
		Benchmark:        f.Benchmark,
		ProfiledAt:       f.Now,
	}
}

// Store holds the per-daemon last-recorded profile. One per daemon; safe for
// concurrent use. Empty until the first profile is recorded.
type Store struct {
	mu      sync.RWMutex
	profile *Profile
}

// NewStore returns an empty store (nothing profiled yet).
func NewStore() *Store {
	return &Store{}
}

// Record computes and persists the profile from the given facts and returns
// it.
func (s *Store) Record(f HostFacts) Profile {
	p := Compute(f)
	s.mu.Lock()
	cp := p
	s.profile = &cp
	s.mu.Unlock()
	return p
}

// Current returns the last-recorded profile and whether one exists. The
// returned Profile is a copy, safe to mutate.
func (s *Store) Current() (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.profile == nil {
		return Profile{}, false
	}
	return *s.profile, true
}
