package server

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/metrics"
	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeCPUSource is a fake Incus client for the standalone sampler (#2645):
// a fixed container list, a per-tick cumulative CPU counter per container,
// per-container errors, and a call counter on GetContainerMetrics.
type fakeCPUSource struct {
	containers []incus.ContainerInfo
	usage      map[string]int64 // current cumulative CPUUsageSeconds
	failing    map[string]bool
	listErr    error
	seq        map[string][]int64 // when set, each read pops the next counter value

	mu    sync.Mutex
	calls map[string]int
}

func (f *fakeCPUSource) ListContainers() ([]incus.ContainerInfo, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.containers, nil
}

func (f *fakeCPUSource) GetContainerMetrics(name string) (*incus.ContainerMetrics, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
	if f.failing[name] {
		return nil, errors.New("incus: boom")
	}
	if q := f.seq[name]; len(q) > 0 {
		f.seq[name] = q[1:]
		return &incus.ContainerMetrics{Name: name, CPUUsageSeconds: q[0]}, nil
	}
	return &incus.ContainerMetrics{Name: name, CPUUsageSeconds: f.usage[name]}, nil
}

func cpuBox(name, state, ip, cpu string) incus.ContainerInfo {
	return incus.ContainerInfo{Name: name, State: state, IPAddress: ip, CPU: cpu}
}

// TestStandaloneCPUSampler pins the standalone ticker's contract (#2645):
// deltas identical to the collector path for the same counter series, one
// metrics call per running container per tick, stopped containers never
// queried, and one container's Incus error skips only that container and is
// counted.
func TestStandaloneCPUSampler(t *testing.T) {
	t0 := time.Unix(1_760_140_800, 0)
	series := map[string][]int64{ // cumulative counter per tick
		"a": {100, 160, 220, 5, 20},
		"b": {0, 30, 60, 90, 120},
	}
	cases := []struct {
		name       string
		containers []incus.ContainerInfo
		failing    map[string]bool
		wantNames  []string // containers expected in emitted samples
		wantErrors uint64
		wantCalls  map[string]int
	}{
		{
			name:       "all running sampled, deltas match collector path",
			containers: []incus.ContainerInfo{cpuBox("a", "Running", "10.0.0.5", "250m"), cpuBox("b", "Running", "10.0.0.6", "2")},
			wantNames:  []string{"a", "b"},
			wantCalls:  map[string]int{"a": 5, "b": 5},
		},
		{
			name:       "stopped container never queried",
			containers: []incus.ContainerInfo{cpuBox("a", "Running", "10.0.0.5", "250m"), cpuBox("b", "Stopped", "", "2")},
			wantNames:  []string{"a"},
			wantCalls:  map[string]int{"a": 5},
		},
		{
			name:       "incus error on one container skips it, others sampled, error counted",
			containers: []incus.ContainerInfo{cpuBox("a", "Running", "10.0.0.5", "250m"), cpuBox("b", "Running", "10.0.0.6", "2")},
			failing:    map[string]bool{"b": true},
			wantNames:  []string{"a"},
			wantErrors: 5,
			wantCalls:  map[string]int{"a": 5, "b": 5},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeCPUSource{containers: tc.containers, usage: map[string]int64{}, failing: tc.failing}
			var standalone [][]threatdetect.CPUSample
			s := NewStandaloneCPUSampler(src, func(smp []threatdetect.CPUSample) { standalone = append(standalone, smp) })

			// Reference: the collector path, fed the same readings the
			// collector would build for the containers the standalone
			// sampler could read.
			var reference [][]threatdetect.CPUSample
			ref := NewCPUSampler(func(smp []threatdetect.CPUSample) { reference = append(reference, smp) })

			for i := range series["a"] {
				at := t0.Add(time.Duration(i) * StandaloneCPUSampleInterval)
				var readings []metrics.ContainerCPUReading
				for _, ct := range tc.containers {
					src.usage[ct.Name] = series[ct.Name][i]
					if ct.State == "Running" && !tc.failing[ct.Name] {
						readings = append(readings, metrics.ContainerCPUReading{Name: ct.Name, IPAddress: ct.IPAddress, CPULimit: ct.CPU, CPUUsageSeconds: series[ct.Name][i]})
					}
				}
				s.Tick(at)
				ref.Observe(at, readings)
			}

			if !reflect.DeepEqual(standalone, reference) {
				t.Fatalf("standalone samples differ from collector path:\n got  %+v\n want %+v", standalone, reference)
			}
			if len(standalone) == 0 {
				t.Fatal("no samples emitted")
			}
			seen := map[string]bool{}
			for _, batch := range standalone {
				for _, smp := range batch {
					seen[smp.Container] = true
				}
			}
			want := map[string]bool{}
			for _, n := range tc.wantNames {
				want[n] = true
			}
			if !reflect.DeepEqual(seen, want) {
				t.Errorf("sampled containers = %v, want %v", seen, want)
			}
			if got := s.Errors(); got != tc.wantErrors {
				t.Errorf("Errors() = %d, want %d", got, tc.wantErrors)
			}
			if !reflect.DeepEqual(src.calls, tc.wantCalls) {
				t.Errorf("GetContainerMetrics calls = %v, want %v (one per running container per tick)", src.calls, tc.wantCalls)
			}
		})
	}
}

func TestStandaloneCPUSampler_ListErrorCountedNoEmit(t *testing.T) {
	src := &fakeCPUSource{listErr: errors.New("incus down")}
	emitted := 0
	s := NewStandaloneCPUSampler(src, func([]threatdetect.CPUSample) { emitted++ })
	s.Tick(time.Unix(0, 0))
	s.Tick(time.Unix(30, 0))
	if emitted != 0 || s.Errors() != 2 {
		t.Errorf("emitted=%d errors=%d, want 0 emits and 2 errors", emitted, s.Errors())
	}
}

// TestStandaloneCPUSampler_RunUsesTicks drives Run with a fake clock (an
// injected tick channel): every tick is one poll, stamped with the tick time.
func TestStandaloneCPUSampler_RunUsesTicks(t *testing.T) {
	src := &fakeCPUSource{containers: []incus.ContainerInfo{cpuBox("a", "Running", "10.0.0.5", "")}, seq: map[string][]int64{"a": {0, 30}}}
	got := make(chan []threatdetect.CPUSample, 4)
	s := NewStandaloneCPUSampler(src, func(smp []threatdetect.CPUSample) { got <- smp })
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, ticks); close(done) }()
	t0 := time.Unix(1000, 0)
	ticks <- t0
	ticks <- t0.Add(StandaloneCPUSampleInterval)
	smp := <-got
	cancel()
	<-done
	if len(smp) != 1 || smp[0].Cores != 1.0 || !smp[0].At.Equal(t0.Add(StandaloneCPUSampleInterval)) {
		t.Fatalf("samples = %+v, want one 1.0-core sample at the second tick", smp)
	}
	if src.calls["a"] != 2 {
		t.Errorf("calls = %d, want 2", src.calls["a"])
	}
}

type fakeCPUHookTarget struct {
	hook func(time.Time, []metrics.ContainerCPUReading)
}

func (f *fakeCPUHookTarget) SetCPUHook(fn func(time.Time, []metrics.ContainerCPUReading)) {
	f.hook = fn
}

// TestWireCPUSampler pins the source choice (#2645): the collector when it
// runs (and then no ticker, no Incus client), the standalone ticker when it
// does not, and "unavailable (<reason>)" when neither can run.
func TestWireCPUSampler(t *testing.T) {
	cases := []struct {
		name          string
		collector     bool
		sourceErr     error
		wantStatus    string
		wantHook      bool
		wantTicker    bool
		wantSourceNew bool
	}{
		{"collector running: hook only, no ticker", true, nil, "metrics-collector", true, false, false},
		{"no collector: standalone ticker", false, nil, "standalone (30s)", false, true, true},
		{"no collector, no incus: unavailable", false, errors.New("socket missing"), "unavailable (incus client unavailable: socket missing)", false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var target *fakeCPUHookTarget
			var collector cpuHookTarget
			if tc.collector {
				target = &fakeCPUHookTarget{}
				collector = target
			}
			sourceNew, tickerStarted := false, false
			newSource := func() (cpuMetricsSource, error) {
				sourceNew = true
				if tc.sourceErr != nil {
					return nil, tc.sourceErr
				}
				return &fakeCPUSource{}, nil
			}
			newTicker := func(d time.Duration) (<-chan time.Time, func()) {
				tickerStarted = true
				if d != StandaloneCPUSampleInterval {
					t.Errorf("ticker interval = %v, want %v", d, StandaloneCPUSampleInterval)
				}
				return make(chan time.Time), func() {}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			got := wireCPUSampler(ctx, func([]threatdetect.CPUSample) {}, collector, newSource, newTicker)
			if got != tc.wantStatus {
				t.Errorf("status = %q, want %q", got, tc.wantStatus)
			}
			if tc.collector && (target.hook != nil) != tc.wantHook {
				t.Errorf("hook set = %v, want %v", target.hook != nil, tc.wantHook)
			}
			if tickerStarted != tc.wantTicker {
				t.Errorf("ticker started = %v, want %v", tickerStarted, tc.wantTicker)
			}
			if sourceNew != tc.wantSourceNew {
				t.Errorf("incus client constructed = %v, want %v", sourceNew, tc.wantSourceNew)
			}
		})
	}
}
