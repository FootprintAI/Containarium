package container

import (
	"testing"
	"time"
)

// TestRunBenchmarkBounded shrinks the per-phase time budget so the test stays
// fast, and asserts the benchmark produces positive scores within the bound.
func TestRunBenchmarkBounded(t *testing.T) {
	origCPU, origMem, origBuf := benchmarkCPUBudget, benchmarkMemBudget, benchmarkMemBufBytes
	benchmarkCPUBudget = 20 * time.Millisecond
	benchmarkMemBudget = 20 * time.Millisecond
	benchmarkMemBufBytes = 1 << 20
	defer func() {
		benchmarkCPUBudget, benchmarkMemBudget, benchmarkMemBufBytes = origCPU, origMem, origBuf
	}()

	start := time.Now()
	r := RunBenchmark()
	elapsed := time.Since(start)

	if r.CPUOpsPerSec <= 0 {
		t.Errorf("CPUOpsPerSec must be positive, got %d", r.CPUOpsPerSec)
	}
	if r.MemBytesPerSec <= 0 {
		t.Errorf("MemBytesPerSec must be positive, got %d", r.MemBytesPerSec)
	}
	if r.DurationMs < 0 {
		t.Errorf("DurationMs must be non-negative, got %d", r.DurationMs)
	}
	// Bounded: total wall clock should be well under a second with the shrunk
	// budgets (allow generous slack for slow CI).
	if elapsed > 2*time.Second {
		t.Errorf("benchmark ran too long: %v", elapsed)
	}
}

func TestBenchMemZeroBuffer(t *testing.T) {
	if got := benchMem(10*time.Millisecond, 0); got != 0 {
		t.Fatalf("benchMem with zero buffer = %d, want 0", got)
	}
}
