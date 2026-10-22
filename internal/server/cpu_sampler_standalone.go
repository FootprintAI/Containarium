package server

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/footprintai/containarium/internal/metrics"
	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// StandaloneCPUSampleInterval is the standalone CPU sampler's tick (#2645).
// It matches the metrics collector's default CollectionInterval, so the
// mining-behavior rule sees the same sample cadence whichever source feeds
// it.
const StandaloneCPUSampleInterval = 30 * time.Second

// CPU sampler sources reported on GetSentryStatus.cpu_sampler (#2645).
const (
	cpuSamplerSourceCollector  = "metrics-collector"
	cpuSamplerNotStartedStatus = "unavailable (not started)"
)

// cpuMetricsSource is the slice of the Incus client the standalone sampler
// reads: the container list (for state, IP and limits.cpu) and the
// per-container cumulative CPU counter. *incus.Client satisfies it.
type cpuMetricsSource interface {
	ListContainers() ([]incus.ContainerInfo, error)
	GetContainerMetrics(name string) (*incus.ContainerMetrics, error)
}

// cpuHookTarget is the metrics collector's CPU hook seam.
// *metrics.Collector satisfies it.
type cpuHookTarget interface {
	SetCPUHook(fn func(at time.Time, readings []metrics.ContainerCPUReading))
}

// StandaloneCPUSampler polls Incus for running containers' cumulative CPU
// counters on its own ticker and feeds them through the same CPUSampler
// delta path the metrics collector's hook uses (#2645). It runs only where
// no metrics collector does (no VictoriaMetrics target, e.g. BYOC hosts),
// never alongside it.
type StandaloneCPUSampler struct {
	src     cpuMetricsSource
	sampler *CPUSampler
	errors  atomic.Uint64
}

// NewStandaloneCPUSampler builds a standalone sampler over src that hands
// each tick's samples to emit (typically Engine.OnCPU).
func NewStandaloneCPUSampler(src cpuMetricsSource, emit func([]threatdetect.CPUSample)) *StandaloneCPUSampler {
	return &StandaloneCPUSampler{src: src, sampler: NewCPUSampler(emit)}
}

// Tick takes one reading of every running container at `at`: one
// GetContainerMetrics call per running container, none for stopped ones. A
// container whose metrics read fails is skipped for this tick (so its next
// good reading starts a fresh delta) and counted in Errors; a failed list
// skips the whole tick and is counted once.
func (s *StandaloneCPUSampler) Tick(at time.Time) {
	containers, err := s.src.ListContainers()
	if err != nil {
		s.errors.Add(1)
		log.Printf("Warning: standalone CPU sampler: list containers: %v", err)
		return
	}
	readings := make([]metrics.ContainerCPUReading, 0, len(containers))
	failed := 0
	for _, ct := range containers {
		if ct.State != "Running" {
			continue
		}
		m, err := s.src.GetContainerMetrics(ct.Name)
		if err != nil {
			failed++
			continue
		}
		readings = append(readings, metrics.ContainerCPUReading{
			Name:            ct.Name,
			IPAddress:       ct.IPAddress,
			CPULimit:        ct.CPU,
			CPUUsageSeconds: m.CPUUsageSeconds,
		})
	}
	if failed > 0 {
		s.errors.Add(uint64(failed))
		log.Printf("Warning: standalone CPU sampler: %d container metrics read(s) failed this tick", failed)
	}
	s.sampler.Observe(at, readings)
}

// Errors is the number of failed Incus reads since start.
func (s *StandaloneCPUSampler) Errors() uint64 { return s.errors.Load() }

// Run polls on every value from ticks, stamping each poll with the tick
// time, until ctx is done or ticks is closed.
func (s *StandaloneCPUSampler) Run(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case at, ok := <-ticks:
			if !ok {
				return
			}
			s.Tick(at)
		}
	}
}

// newTimeTicker is wireCPUSampler's production ticker.
func newTimeTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// wireCPUSampler picks the CPU sampler's source (#2645) and returns its
// status string for GetSentryStatus.cpu_sampler. With a metrics collector
// (non-nil collector) the sampler hooks its tick and nothing else starts —
// no Incus client, no ticker, so no double sampling. Without one it builds
// an Incus client via newSource and runs the standalone ticker until ctx is
// done; if the client cannot be built the sampler is unavailable and the
// reason is reported.
func wireCPUSampler(
	ctx context.Context,
	emit func([]threatdetect.CPUSample),
	collector cpuHookTarget,
	newSource func() (cpuMetricsSource, error),
	newTicker func(time.Duration) (<-chan time.Time, func()),
) string {
	if collector != nil {
		collector.SetCPUHook(NewCPUSampler(emit).Observe)
		return cpuSamplerSourceCollector
	}
	src, err := newSource()
	if err != nil {
		return fmt.Sprintf("unavailable (incus client unavailable: %v)", err)
	}
	ticks, stop := newTicker(StandaloneCPUSampleInterval)
	s := NewStandaloneCPUSampler(src, emit)
	go func() {
		defer stop()
		s.Run(ctx, ticks)
	}()
	return fmt.Sprintf("standalone (%s)", StandaloneCPUSampleInterval)
}
