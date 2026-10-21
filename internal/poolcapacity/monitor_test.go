package poolcapacity

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		used, total int64
		want        Level
	}{
		{0, 0, LevelUnknown},
		{849, 1000, LevelOK},
		{850, 1000, LevelWarning},
		{949, 1000, LevelWarning},
		{950, 1000, LevelCritical},
		{1000, 1000, LevelCritical},
	} {
		if got := Classify(tc.used, tc.total); got != tc.want {
			t.Errorf("Classify(%d, %d) = %v, want %v", tc.used, tc.total, got, tc.want)
		}
	}
}

// fakeSource is a stubbed pool reader: it returns pools/err, optionally after
// blocking until release is closed.
type fakeSource struct {
	mu      sync.Mutex
	pools   []incus.StoragePoolUsage
	err     error
	release chan struct{}
}

func (f *fakeSource) set(pools []incus.StoragePoolUsage, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pools, f.err = pools, err
}

func (f *fakeSource) read() ([]incus.StoragePoolUsage, error) {
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pools, f.err
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logSink) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

func pool(name string, used int64) incus.StoragePoolUsage {
	return incus.StoragePoolUsage{Name: name, Driver: "zfs", UsedBytes: used, TotalBytes: 100}
}

func newTestMonitor(src *fakeSource, logs *logSink, onSample func([]Sample)) *Monitor {
	return New(src.read, Options{Timeout: 50 * time.Millisecond, OnSample: onSample, Logf: logs.logf})
}

// A pool above warn produces the series and one WARN at the first read (the
// daemon start); below warn produces the series and no WARN.
func TestMonitor_WarnAndCritProduceSeriesAndLog(t *testing.T) {
	for _, tc := range []struct {
		used      int64
		wantLevel Level
		wantLog   string
	}{
		{50, LevelOK, ""},
		{90, LevelWarning, "WARN"},
		{96, LevelCritical, "CRIT"},
	} {
		t.Run(tc.wantLevel.String(), func(t *testing.T) {
			src := &fakeSource{pools: []incus.StoragePoolUsage{pool("p", tc.used)}}
			logs := &logSink{}
			var got []Sample
			m := newTestMonitor(src, logs, func(s []Sample) { got = s })
			m.Tick()

			if len(got) != 1 || got[0].Level != tc.wantLevel || got[0].UsedBytes != tc.used {
				t.Fatalf("samples = %+v, want one pool at %v", got, tc.wantLevel)
			}
			if tc.wantLog == "" {
				if len(logs.lines) != 0 {
					t.Errorf("below warn must not log, got %q", logs.lines)
				}
				return
			}
			if logs.count(tc.wantLog) != 1 {
				t.Errorf("want one %s line, got %q", tc.wantLog, logs.lines)
			}
		})
	}
}

// Logs on every level change, never twice at the same level.
func TestMonitor_LogsOnlyOnLevelChange(t *testing.T) {
	src := &fakeSource{}
	logs := &logSink{}
	m := newTestMonitor(src, logs, nil)
	for _, used := range []int64{90, 91, 92, 96, 97, 90, 10, 10} {
		src.set([]incus.StoragePoolUsage{pool("p", used)}, nil)
		m.Tick()
	}
	if w, c, ok := logs.count("WARN"), logs.count("CRIT"), logs.count("back below"); w != 2 || c != 1 || ok != 1 {
		t.Errorf("WARN=%d CRIT=%d recovered=%d, want 2/1/1; lines %q", w, c, ok, logs.lines)
	}
}

// A failing read keeps the last snapshot and logs once, not every tick.
func TestMonitor_FailingReadDegradesQuietly(t *testing.T) {
	src := &fakeSource{pools: []incus.StoragePoolUsage{pool("p", 96)}}
	logs := &logSink{}
	m := newTestMonitor(src, logs, nil)
	m.Tick()
	src.set(nil, errors.New("incus down"))
	m.Tick()
	m.Tick()
	if n := logs.count("read failed"); n != 1 {
		t.Errorf("want one read-failure line, got %d: %q", n, logs.lines)
	}
	snap := m.Snapshot()
	if len(snap.Pools) != 1 || snap.Pools[0].Level != LevelCritical {
		t.Errorf("snapshot after failures = %+v, want the last good critical pool", snap)
	}
}

// A hung read returns within the deadline, keeps the previous snapshot, does
// not stack a second read, and its late answer still lands.
func TestMonitor_SlowReadDoesNotBlock(t *testing.T) {
	src := &fakeSource{pools: []incus.StoragePoolUsage{pool("p", 10)}}
	logs := &logSink{}
	m := newTestMonitor(src, logs, nil)
	m.Tick()

	src.release = make(chan struct{})
	src.set([]incus.StoragePoolUsage{pool("p", 96)}, nil)
	start := time.Now()
	m.Tick()
	m.Tick() // previous read still in flight: skipped, not stacked
	if d := time.Since(start); d > time.Second {
		t.Fatalf("ticks blocked for %v on a hung read", d)
	}
	if lvl := m.Snapshot().Pools[0].Level; lvl != LevelOK {
		t.Errorf("snapshot during hang = %v, want previous OK", lvl)
	}
	if n := logs.count("did not answer"); n != 1 {
		t.Errorf("want one timeout line, got %d: %q", n, logs.lines)
	}

	close(src.release)
	deadline := time.Now().Add(2 * time.Second)
	for m.Snapshot().Pools[0].Level != LevelCritical {
		if time.Now().After(deadline) {
			t.Fatal("late read result never reached the snapshot")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
