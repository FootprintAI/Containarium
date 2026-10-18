package server

import (
	"net/netip"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/metrics"
	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// CPUSampler turns the metrics collector's cumulative per-container
// CPUUsageSeconds into per-tick core rates for the threat-detection engine
// (#2635). It is a hook on the collector (Collector.SetCPUHook), so the
// mining-behavior rule adds no Incus polling of its own.
type CPUSampler struct {
	emit func([]threatdetect.CPUSample)

	mu   sync.Mutex
	prev map[string]cpuReading
}

type cpuReading struct {
	usage int64
	at    time.Time
}

// NewCPUSampler builds a sampler that hands each tick's samples to emit
// (typically Engine.OnCPU).
func NewCPUSampler(emit func([]threatdetect.CPUSample)) *CPUSampler {
	return &CPUSampler{emit: emit, prev: make(map[string]cpuReading)}
}

// Observe takes one collector tick's readings. A container's first reading
// is dropped (no delta), as are a counter that went backwards (container
// restart) and a clock that did not advance; the reading still becomes the
// new baseline. Containers missing from this tick are forgotten.
func (s *CPUSampler) Observe(at time.Time, readings []metrics.ContainerCPUReading) {
	s.mu.Lock()
	var out []threatdetect.CPUSample
	next := make(map[string]cpuReading, len(readings))
	for _, r := range readings {
		next[r.Name] = cpuReading{usage: r.CPUUsageSeconds, at: at}
		p, ok := s.prev[r.Name]
		if !ok {
			continue
		}
		dUsage, dWall := r.CPUUsageSeconds-p.usage, at.Sub(p.at)
		if dUsage < 0 || dWall <= 0 {
			continue
		}
		ip, _ := netip.ParseAddr(r.IPAddress) // invalid on parse failure: no flow will join
		out = append(out, threatdetect.CPUSample{
			Container:  r.Name,
			IP:         ip,
			Cores:      float64(dUsage) / dWall.Seconds(),
			LimitCores: incus.CommittedCores(r.CPULimit),
			At:         at,
		})
	}
	s.prev = next
	s.mu.Unlock()
	if len(out) > 0 && s.emit != nil {
		s.emit(out)
	}
}
