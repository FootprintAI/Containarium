package storageprobe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestClassify_SevereRequiresAbsoluteLatencyNotJustRatio guards against a
// ratio-only verdict, which real measurement showed mis-ranks a healthy host.
//
// A migrated backend under heavy load measured 15.6 ms idle → 318 ms under
// four busy co-tenants: a ratio of 20.4x, but 51x *better* in absolute terms
// than the backend #1206 was filed about (16,179 ms at half that load).
// Calling that `severe` puts a host where builds are fine in the same bucket
// as one where they stall for 20 seconds.
//
// The flaw is structural: a ratio has no scale. 20x on a 15 ms baseline is
// 318 ms; 20x on a 1,000 ms baseline is 20 s. Same ratio, different problem.
func TestClassify_SevereRequiresAbsoluteLatencyNotJustRatio(t *testing.T) {
	ms := func(d int) Result {
		return Result{Ops: 50, Total: time.Duration(d) * time.Millisecond}
	}

	tests := []struct {
		name        string
		baseline    Result
		underLoad   Result
		wantVerdict Verdict
	}{
		{
			// The case measured on the migrated host. High ratio, but
			// sub-second latency — an operator should not be paged for this.
			name:        "high ratio but sub-second latency is degraded, not severe",
			baseline:    ms(15),
			underLoad:   ms(350), // 23.3x ratio, 7 ms/op — comfortably past the ratio threshold
			wantVerdict: VerdictDegraded,
		},
		{
			// The original incident: high ratio AND multi-second latency.
			name:        "high ratio with multi-second latency stays severe",
			baseline:    ms(17),
			underLoad:   ms(11885),
			wantVerdict: VerdictSevere,
		},
		{
			// Absolute latency alone must not trigger severe either: a pool
			// that is uniformly slow but unaffected by neighbours is not a
			// contention failure, which is the whole point of the ratio.
			name:        "slow but stable stays isolated despite high absolute latency",
			baseline:    ms(9000),
			underLoad:   ms(9500),
			wantVerdict: VerdictIsolated,
		},
		{
			// Right at the ratio threshold with a large absolute number.
			name:        "threshold ratio with seconds-scale latency is severe",
			baseline:    ms(500),
			underLoad:   ms(10000),
			wantVerdict: VerdictSevere,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.baseline, tt.underLoad)
			if got.Verdict != tt.wantVerdict {
				t.Errorf("Verdict = %v, want %v (ratio %.1f, under-load %v)",
					got.Verdict, tt.wantVerdict, got.Ratio, tt.underLoad.PerOp())
			}
		})
	}
}

// The load mode's half of "both modes clean up their temp files even when
// interrupted" (#1210).
//
// TestRunLoad_StopsOnContextCancel above drives runLoad with a fake writer, so
// it proves the loop honours cancellation but says nothing about the file.
// Load is the exported entry point that actually creates one, and it runs
// inside a tenant's box: a load generator that leaves a multi-gigabyte scratch
// file behind every time it is interrupted is worse than one nobody runs.
func TestLoad_RemovesItsScratchFileWhenInterrupted(t *testing.T) {
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // interrupted before the first cycle

	cfg := DefaultLoadConfig()
	cfg.Cycles = 1_000_000

	if err := Load(ctx, dir, cfg); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Load returned %v, want nil or context.Canceled", err)
	}

	assertNoScratchFiles(t, dir)
}

// And on the ordinary path too, so the cleanup is not merely a cancellation
// side effect.
func TestLoad_RemovesItsScratchFileOnCompletion(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultLoadConfig()
	cfg.Cycles = 1 // finish immediately

	if err := Load(context.Background(), dir, cfg); err != nil {
		t.Fatalf("Load: %v", err)
	}

	assertNoScratchFiles(t, dir)
}

func assertNoScratchFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "containarium-storage-") {
			t.Errorf("scratch file %q was left behind; the probe runs inside a tenant's box "+
				"and one that leaks a file per invocation is one operators stop running", e.Name())
		}
	}
}
