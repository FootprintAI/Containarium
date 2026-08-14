package sentinel

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"syscall"
)

// Sentinel process-health metrics (#1351).
//
// The /metrics endpoint published four sentinel_* series describing the
// BACKEND's preemption state and nothing at all about the sentinel process
// itself. So when #1349 leaked ~18 MB/day for 27 consecutive days on the most
// availability-critical VM in the fleet, there was no series to graph and
// nothing to alert on: the first signal anyone got was the OOM kill, and it
// arrived on a hypervisor CPU graph pointing at the wrong resource.
//
// The argument that made preemption a sentinel-owned signal (#514 — the
// on-spot monitoring stack dies with the spot, so the always-on sentinel is
// the only thing that can report) applies unchanged to the sentinel's own
// process health. It was simply never extended that far.
//
// Names follow the Prometheus/client_golang conventions
// (process_resident_memory_bytes, go_goroutines, …) even though nothing here
// imports client_golang — the repo hand-rolls its exposition, and matching the
// standard names is what lets an off-the-shelf dashboard or alert rule work
// against this endpoint without translation.
//
// RSS is first among equals: the Go heap can look flat while RSS climbs
// (goroutine stacks, mmap'd regions, cgo), and RSS is what the OOM killer
// scores. A rule like
//
//	deriv(process_resident_memory_bytes[6h]) > 0
//
// sustained over a day would have opened #1349 around week one instead of at
// the outage.

// runtimeStats is what the Go runtime knows about itself. Portable.
type runtimeStats struct {
	Goroutines     int
	HeapAllocBytes uint64
	SysBytes       uint64
}

// procStats is what the OS knows about the process. Requires /proc, so it is
// Linux-only — Available is false everywhere else, and callers must then omit
// the series entirely rather than publish zeros.
type procStats struct {
	Available    bool
	RSSBytes     uint64
	VirtualBytes uint64
	OpenFDs      uint64
	MaxFDs       uint64
}

// collectRuntimeStats samples the Go runtime.
//
// Uses runtime/metrics rather than runtime.ReadMemStats: ReadMemStats stops
// the world, and this endpoint is on the request path of a process whose job
// is forwarding live traffic. runtime/metrics samples without a global pause.
func collectRuntimeStats() runtimeStats {
	const (
		heapObjects = "/memory/classes/heap/objects:bytes"
		totalMapped = "/memory/classes/total:bytes"
	)
	samples := []metrics.Sample{{Name: heapObjects}, {Name: totalMapped}}
	metrics.Read(samples)

	rt := runtimeStats{Goroutines: runtime.NumGoroutine()}
	for _, s := range samples {
		// KindBad means the runtime does not know this metric name (it can be
		// retired across Go versions). Leaving the field zero is right here:
		// unlike RSS, a zero heap number cannot mask a leak, because RSS is
		// the series alerts key on.
		if s.Value.Kind() != metrics.KindUint64 {
			continue
		}
		switch s.Name {
		case heapObjects:
			rt.HeapAllocBytes = s.Value.Uint64()
		case totalMapped:
			rt.SysBytes = s.Value.Uint64()
		}
	}
	return rt
}

// readProcStats reads process memory and fd counts from /proc.
//
// Returns Available=false on any platform without /proc, or if the read fails
// — the caller then omits those series. Deliberately not faked on non-Linux:
// a plausible-looking zero would be worse than an absent series.
func readProcStats() procStats {
	rss, virt, ok := readStatm()
	if !ok {
		return procStats{}
	}
	ps := procStats{Available: true, RSSBytes: rss, VirtualBytes: virt}
	if n, ok := countOpenFDs(); ok {
		ps.OpenFDs = n
	}
	if n, ok := maxOpenFDs(); ok {
		ps.MaxFDs = n
	}
	return ps
}

// readStatm parses /proc/self/statm, whose first two fields are total program
// size and resident set size, both in pages. Returns ok=false when the file is
// missing (any non-Linux platform) or malformed.
//
// No build tag: os.ReadFile simply fails on platforms without /proc, which is
// exactly the signal we want, and keeping one implementation means the
// non-Linux branch is the same code path in dev as in prod.
func readStatm() (rss, virt uint64, ok bool) {
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, 0, false
	}
	// Guard the int->uint64 conversion rather than suppressing G115. A
	// non-positive page size would wrap into an enormous multiplier and
	// publish nonsense byte counts, which is worse than reporting nothing —
	// the whole point of this endpoint is that its numbers can be trusted.
	pageSize := os.Getpagesize()
	if pageSize <= 0 {
		return 0, 0, false
	}
	return parseStatm(string(raw), uint64(pageSize))
}

// parseStatm splits the statm line. Pure and separate from the file read so
// the field order is testable on any platform — a skipped-on-macOS test would
// leave the riskiest part of this file unexercised until production.
//
// Field order is (size, resident, shared, text, lib, data, dt): index 0 is
// VIRTUAL, index 1 is RESIDENT. Transposing them would publish VSZ as
// process_resident_memory_bytes — in #1349's numbers, 2.7 GB instead of
// 565 MB — which points a leak hunt at the wrong quantity entirely.
func parseStatm(raw string, pageSize uint64) (rss, virt uint64, ok bool) {
	fields := strings.Fields(raw)
	if len(fields) < 2 || pageSize == 0 {
		return 0, 0, false
	}
	virtPages, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	rssPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return rssPages * pageSize, virtPages * pageSize, true
}

// countOpenFDs counts entries in /proc/self/fd.
func countOpenFDs() (uint64, bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	// The directory handle opened by ReadDir is itself one of the entries and
	// is already closed by the time we count; subtracting it would be wrong as
	// often as right, so report what is there. An fd-leak alert keys on the
	// trend, which an off-by-one does not affect.
	return uint64(len(entries)), true
}

// maxOpenFDs reports RLIMIT_NOFILE, so `process_open_fds / process_max_fds`
// is alertable. The unit sets LimitNOFILE=65536.
func maxOpenFDs() (uint64, bool) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, false
	}
	return uint64(lim.Cur), true
}

// renderProcessMetrics builds the Prometheus exposition for process health.
// Pure — takes both snapshots as arguments so tests can drive the
// /proc-unavailable branch on any platform.
func renderProcessMetrics(rt runtimeStats, ps procStats) string {
	var b bytes.Buffer

	gauge := func(name, help string, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
		fmt.Fprintf(&b, "%s %s\n", name, value)
	}

	gauge("go_goroutines", "Number of goroutines that currently exist.", strconv.Itoa(rt.Goroutines))
	gauge("go_memstats_heap_alloc_bytes", "Bytes of live heap objects.", formatMetricUint(rt.HeapAllocBytes))
	gauge("go_memstats_sys_bytes", "Total bytes of memory mapped from the OS.", formatMetricUint(rt.SysBytes))

	// Absent, not zero, when /proc is unreadable. A hard zero here would read
	// as "this process uses no memory" and silence the very alert this exists
	// to enable; an absent series is detectable with absent().
	if !ps.Available {
		fmt.Fprint(&b, "# process_* series omitted: /proc unavailable on this platform\n")
		return b.String()
	}

	gauge("process_resident_memory_bytes", "Resident set size in bytes.", formatMetricUint(ps.RSSBytes))
	gauge("process_virtual_memory_bytes", "Virtual memory size in bytes.", formatMetricUint(ps.VirtualBytes))
	if ps.OpenFDs > 0 {
		gauge("process_open_fds", "Number of open file descriptors.", formatMetricUint(ps.OpenFDs))
	}
	if ps.MaxFDs > 0 {
		gauge("process_max_fds", "Maximum number of open file descriptors (RLIMIT_NOFILE).", formatMetricUint(ps.MaxFDs))
	}
	return b.String()
}

// formatMetricUint renders a value the way Prometheus exposition expects:
// small integers bare ("65536"), large ones in exponent form
// ("5.791744e+08"), which is what client_golang emits and what every scraper
// parses as a float64 sample.
func formatMetricUint(v uint64) string {
	return strconv.FormatFloat(float64(v), 'g', -1, 64)
}
