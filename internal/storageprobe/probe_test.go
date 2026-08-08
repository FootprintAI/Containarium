package storageprobe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestClassify_UsesTheRatioNotTheAbsoluteNumber is the heart of #1210.
//
// The absolute latency of a single probe is not a health signal, and on the
// failure in #1206 it points the wrong way: the affected containers measured
// 17 ms at rest — faster than the physical host (46 ms) and faster than a busy
// ZFS backend (196 ms). Only the baseline-to-under-load ratio separates a
// healthy pool from one where tenants stall each other.
//
// The two rows below are the measured numbers from #1206, and they are the
// cases that must not be confused: the same 17 ms baseline classifies as
// severe against a real dirty-page load and as healthy against a tight-fsync
// load that never reproduced the stall.
func TestClassify_UsesTheRatioNotTheAbsoluteNumber(t *testing.T) {
	ms := func(d int) Result {
		return Result{Ops: 50, Total: time.Duration(d) * time.Millisecond}
	}

	tests := []struct {
		name        string
		baseline    Result
		underLoad   Result
		wantVerdict Verdict
		wantRatioGT float64
	}{
		{
			name:        "measured dir-driver stall from #1206 (17ms -> 11885ms)",
			baseline:    ms(17),
			underLoad:   ms(11885),
			wantVerdict: VerdictSevere,
			wantRatioGT: 600,
		},
		{
			name:      "the tight-fsync load that did NOT reproduce it (17ms -> 32ms)",
			baseline:  ms(17),
			underLoad: ms(32),
			// Must not be severe. A probe that flagged this would cry wolf on
			// every backend under any load at all.
			wantVerdict: VerdictIsolated,
		},
		{
			name:        "a real but moderate degradation",
			baseline:    ms(20),
			underLoad:   ms(200),
			wantVerdict: VerdictDegraded,
		},
		{
			name:      "an absolutely slow but stable pool is not a contention failure",
			baseline:  ms(196),
			underLoad: ms(210),
			// 196 ms is slower in absolute terms than the broken host's 17 ms.
			// Ratio is what matters, so this is healthy.
			wantVerdict: VerdictIsolated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.baseline, tt.underLoad)
			if got.Verdict != tt.wantVerdict {
				t.Errorf("Verdict = %v, want %v (ratio %.1f)", got.Verdict, tt.wantVerdict, got.Ratio)
			}
			if tt.wantRatioGT > 0 && got.Ratio < tt.wantRatioGT {
				t.Errorf("Ratio = %.1f, want > %.1f", got.Ratio, tt.wantRatioGT)
			}
		})
	}
}

// TestClassify_UnknownWhenBaselineIsUnusable guards the degenerate input. A
// zero baseline cannot produce a ratio, and reporting "isolated" for it would
// turn a failed measurement into a clean bill of health.
func TestClassify_UnknownWhenBaselineIsUnusable(t *testing.T) {
	for _, baseline := range []Result{
		{Ops: 0, Total: 0},
		{Ops: 50, Total: 0},
	} {
		got := Classify(baseline, Result{Ops: 50, Total: time.Second})
		if got.Verdict != VerdictUnknown {
			t.Errorf("baseline %+v: Verdict = %v, want VerdictUnknown", baseline, got.Verdict)
		}
	}
}

// TestRunLoad_GeneratesVolumeNotFsyncFrequency is the trap this package exists
// to avoid, asserted directly.
//
// From #1206: four tight fsync() loops writing 4 KiB barely moved the probe
// (32 ms), while eight workers doing 64 MiB buffered writes then one fsync
// produced the 11,885 ms stall. The trigger is co-tenant *dirty-page volume*.
// A load generator that syncs after every small write is a different workload
// that does not reproduce the bug, so pin the ratio of bytes written to syncs
// issued.
func TestRunLoad_GeneratesVolumeNotFsyncFrequency(t *testing.T) {
	w := &countingWriter{}
	ctx, cancel := context.WithCancel(context.Background())

	cfg := DefaultLoadConfig()
	// Stop after a few cycles rather than running for the default duration.
	cfg.Cycles = 3

	if err := runLoad(ctx, w, cfg); err != nil {
		t.Fatalf("runLoad: %v", err)
	}
	cancel()

	if w.syncs == 0 {
		t.Fatal("no fsync issued; the load never commits anything to the journal")
	}
	bytesPerSync := w.bytes / int64(w.syncs)
	const wantAtLeast = 32 << 20 // 32 MiB
	if bytesPerSync < wantAtLeast {
		t.Errorf("bytes per fsync = %d, want >= %d — this is the tight-fsync pattern that "+
			"failed to reproduce the stall in #1206", bytesPerSync, wantAtLeast)
	}
}

// TestRunLoad_StopsOnContextCancel proves the generator is interruptible. It
// runs against a live tenant's neighbours, so an operator must be able to stop
// it immediately rather than wait out a duration.
func TestRunLoad_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the first cycle

	cfg := DefaultLoadConfig()
	cfg.Cycles = 1_000_000 // would run effectively forever if cancel were ignored

	done := make(chan error, 1)
	go func() { done <- runLoad(ctx, &countingWriter{}, cfg) }()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("runLoad returned %v, want nil or context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runLoad ignored a cancelled context")
	}
}

// TestProbe_MeasuresAndCleansUp runs the real probe against a temp dir. The
// cleanup assertion matters because the probe runs inside a tenant's box: a
// probe that leaks its scratch file every invocation is a probe operators
// stop running.
func TestProbe_MeasuresAndCleansUp(t *testing.T) {
	dir := t.TempDir()

	res, err := Probe(dir, 16)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Ops != 16 {
		t.Errorf("Ops = %d, want 16", res.Ops)
	}
	if res.Total <= 0 {
		t.Errorf("Total = %v, want > 0", res.Total)
	}
	if res.PerOp() <= 0 {
		t.Errorf("PerOp() = %v, want > 0", res.PerOp())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, filepath.Join(dir, e.Name()))
		}
		t.Errorf("probe left files behind: %v", names)
	}
}

// TestProbe_RejectsNonPositiveOps keeps a caller from recording a meaningless
// zero-op "measurement" that Classify would then divide by.
func TestProbe_RejectsNonPositiveOps(t *testing.T) {
	if _, err := Probe(t.TempDir(), 0); err == nil {
		t.Error("expected an error for ops=0, got nil")
	}
}

// countingWriter records the write/sync pattern without touching disk.
type countingWriter struct {
	bytes int64
	syncs int
}

func (c *countingWriter) Write(p []byte) (int, error) { c.bytes += int64(len(p)); return len(p), nil }
func (c *countingWriter) Sync() error                 { c.syncs++; return nil }
func (c *countingWriter) Truncate(int64) error        { return nil }
