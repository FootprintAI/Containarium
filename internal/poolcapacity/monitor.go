// Package poolcapacity watches Incus storage-pool fill (#2823).
//
// A nearly full pool stops every container on the host from writing, core
// Postgres included, and the host-wide disk series (a sum over pools) can hide
// one full pool. The monitor reads each pool on a bounded tick, classifies it
// against fixed thresholds, logs on every level change (so a pool already past
// warn is logged at daemon start) and hands each sample to a metrics hook.
package poolcapacity

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Thresholds on used/total as Incus reports it. Fixed by decision on #2823;
// operators override them with custom alert rules. Incus' ZFS numbers exclude
// slop space (read from the driver, not verified on a live pool), so 95% here
// is roughly 92% of zpool capacity.
const (
	WarnPercent = 85
	CritPercent = 95
)

// Level is a pool's fill classification.
type Level int

const (
	LevelUnknown Level = iota // total not reported
	LevelOK
	LevelWarning
	LevelCritical
)

func (l Level) String() string {
	switch l {
	case LevelOK:
		return "ok"
	case LevelWarning:
		return "warning"
	case LevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Classify maps used/total onto a Level.
func Classify(used, total int64) Level {
	if total <= 0 {
		return LevelUnknown
	}
	switch pct := used * 100 / total; {
	case pct >= CritPercent:
		return LevelCritical
	case pct >= WarnPercent:
		return LevelWarning
	default:
		return LevelOK
	}
}

// Sample is one pool reading with its level.
type Sample struct {
	incus.StoragePoolUsage
	Level Level
}

// Snapshot is the last successful read.
type Snapshot struct {
	Pools []Sample
	At    time.Time
}

// Reader reads every pool's usage. incus.Client.StoragePoolUsages on a
// bounded client in production; a stub in tests.
type Reader func() ([]incus.StoragePoolUsage, error)

// Options configures a Monitor. Zero values take defaults.
type Options struct {
	Timeout  time.Duration                 // per-tick wait for a read; default 10s
	OnSample func([]Sample)                // called after every successful read
	Logf     func(format string, a ...any) // default log.Printf
}

// Monitor is safe for concurrent use.
type Monitor struct {
	read Reader
	opts Options

	mu       sync.Mutex
	levels   map[string]Level
	snap     Snapshot
	inflight chan struct{} // non-nil while a read is running
	failing  bool
}

// New builds a Monitor around read.
func New(read Reader, opts Options) *Monitor {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	return &Monitor{read: read, opts: opts, levels: map[string]Level{}}
}

// Run ticks immediately, then every interval, until ctx ends.
func (m *Monitor) Run(ctx context.Context, interval time.Duration) {
	m.Tick()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Tick()
		}
	}
}

// Tick runs one read, waiting at most Timeout. A read that is still running
// from an earlier tick is not stacked; a late result is applied when it lands.
func (m *Monitor) Tick() {
	m.mu.Lock()
	if m.inflight != nil {
		m.mu.Unlock()
		return
	}
	done := make(chan struct{})
	m.inflight = done
	m.mu.Unlock()

	go func() {
		pools, err := m.read()
		m.apply(pools, err)
		m.mu.Lock()
		m.inflight = nil
		m.mu.Unlock()
		close(done)
	}()

	timer := time.NewTimer(m.opts.Timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		m.markFailing("storage pool capacity: read did not answer within %v; keeping the last snapshot", m.opts.Timeout)
	}
}

// Snapshot returns the last successful read.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{Pools: append([]Sample(nil), m.snap.Pools...), At: m.snap.At}
}

func (m *Monitor) markFailing(format string, a ...any) {
	m.mu.Lock()
	first := !m.failing
	m.failing = true
	m.mu.Unlock()
	if first {
		m.opts.Logf(format, a...)
	}
}

func (m *Monitor) apply(pools []incus.StoragePoolUsage, err error) {
	if err != nil {
		m.markFailing("storage pool capacity: read failed: %v; keeping the last snapshot", err)
		return
	}
	samples := make([]Sample, 0, len(pools))
	m.mu.Lock()
	m.failing = false
	for _, p := range pools {
		s := Sample{StoragePoolUsage: p, Level: Classify(p.UsedBytes, p.TotalBytes)}
		samples = append(samples, s)
		prev, seen := m.levels[p.Name]
		m.levels[p.Name] = s.Level
		if prev == s.Level || (!seen && s.Level <= LevelOK) {
			continue
		}
		pct := float64(p.UsedBytes) * 100 / float64(p.TotalBytes)
		switch s.Level {
		case LevelCritical:
			m.opts.Logf("CRIT: storage pool %q (%s) is %.1f%% full (>= %d%%): containers on it, core services included, may stop writing", p.Name, p.Driver, pct, CritPercent)
		case LevelWarning:
			m.opts.Logf("WARN: storage pool %q (%s) is %.1f%% full (>= %d%%)", p.Name, p.Driver, pct, WarnPercent)
		case LevelOK:
			m.opts.Logf("storage pool %q (%s) is back below %d%% (%.1f%% full)", p.Name, p.Driver, WarnPercent, pct)
		}
	}
	m.snap = Snapshot{Pools: samples, At: time.Now()}
	m.mu.Unlock()
	if m.opts.OnSample != nil {
		m.opts.OnSample(samples)
	}
}
