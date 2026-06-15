package container

import (
	"time"
)

// Micro-benchmark tuning. Package vars (not consts) so tests can shrink the
// time budget to keep the suite fast while still exercising the loops.
var (
	// benchmarkCPUBudget / benchmarkMemBudget bound each phase's wall clock.
	// The whole benchmark is therefore bounded by their sum; both are short so
	// recording a profile at join stays cheap.
	benchmarkCPUBudget = 150 * time.Millisecond
	benchmarkMemBudget = 150 * time.Millisecond

	// benchmarkMemBufBytes is the size of the buffer the memory phase streams
	// through. Small enough to fit comfortably in cache-and-RAM on any host,
	// large enough that the copy/sum loop is memory- rather than loop-bound.
	benchmarkMemBufBytes = 4 << 20 // 4 MiB
)

// BenchmarkResult is the outcome of the bounded CPU/memory micro-benchmark.
// The scores are relative capacity/integrity signals (higher is faster), not
// absolute hardware specs — they let a profile confirm a backend's
// self-reported class is plausible. See #681.
type BenchmarkResult struct {
	// CPUOpsPerSec is integer-work iterations completed per second during the
	// bounded single-threaded CPU phase.
	CPUOpsPerSec int64

	// MemBytesPerSec is bytes per second moved through the bounded buffer
	// copy/sum loop.
	MemBytesPerSec int64

	// DurationMs is the total wall-clock time both phases took.
	DurationMs int64
}

// RunBenchmark runs a lightweight, time-bounded CPU and memory micro-benchmark
// and returns relative scores. It is pure Go (no external process, no GPU) so
// it runs on any backend, is safe to call at join time, and is bounded by the
// package time budgets above. It never blocks longer than benchmarkCPUBudget +
// benchmarkMemBudget plus a little loop slack.
func RunBenchmark() BenchmarkResult {
	start := time.Now()
	cpuOps := benchCPU(benchmarkCPUBudget)
	memBps := benchMem(benchmarkMemBudget, benchmarkMemBufBytes)
	return BenchmarkResult{
		CPUOpsPerSec:   cpuOps,
		MemBytesPerSec: memBps,
		DurationMs:     time.Since(start).Milliseconds(),
	}
}

// benchCPU runs a tight integer-work loop until the budget elapses and returns
// iterations completed per second. The loop body is deliberately simple
// integer arithmetic so the score tracks raw single-thread CPU throughput and
// is comparable across runs on the same host.
func benchCPU(budget time.Duration) int64 {
	start := time.Now()
	deadline := start.Add(budget)
	// Check the clock only every checkEvery iterations — time.Now() per
	// iteration would dominate the measurement.
	const checkEvery = 1 << 16
	var iters int64
	var acc uint64 = 1
	for {
		for i := 0; i < checkEvery; i++ {
			// A cheap, non-trivial mix the compiler can't fold away.
			acc = acc*6364136223846793005 + 1442695040888963407
			acc ^= acc >> 33
			iters++
		}
		if time.Now().After(deadline) {
			break
		}
	}
	// Keep acc live so the loop isn't optimized out.
	if acc == 0 {
		iters++
	}
	// Divide by the ACTUAL elapsed time, not the nominal budget: the loop
	// overruns the deadline by up to one checkEvery batch, and on a slow/noisy
	// host that overrun is significant — using budget.Seconds() would overstate
	// throughput exactly where accuracy matters for class-drift detection.
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return int64(float64(iters) / elapsed)
}

// benchMem streams a buffer through a copy+sum loop until the budget elapses
// and returns bytes per second moved. Each pass reads and writes the whole
// buffer, so the score tracks memory bandwidth rather than loop overhead.
func benchMem(budget time.Duration, bufBytes int) int64 {
	if bufBytes <= 0 {
		return 0
	}
	src := make([]byte, bufBytes)
	dst := make([]byte, bufBytes)
	for i := range src {
		src[i] = byte(i)
	}
	start := time.Now()
	deadline := start.Add(budget)
	var moved int64
	var sum uint64
	for {
		copy(dst, src)
		for _, b := range dst {
			sum += uint64(b)
		}
		// One pass reads src + writes dst + reads dst.
		moved += int64(bufBytes) * 3
		if time.Now().After(deadline) {
			break
		}
	}
	if sum == 0 {
		moved++
	}
	// Actual elapsed, not the nominal budget — the final pass overruns the
	// deadline (a whole buffer of work), which budget.Seconds() would ignore.
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return int64(float64(moved) / elapsed)
}
