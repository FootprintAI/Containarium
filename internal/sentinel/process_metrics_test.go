package sentinel

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// #1351: the sentinel's /metrics published four sentinel_* series and nothing
// about the process itself, so #1349's ~18 MB/day growth ran for 27 days with
// no series to graph and nothing to alert on. These tests pin the series that
// close that gap — above all resident memory, which is what the OOM killer
// actually acts on.

// fakeProcStats is a snapshot with recognisable values, so a test failure says
// which field got mis-rendered rather than just "some number is wrong".
func fakeProcStats() procStats {
	return procStats{
		Available:    true,
		RSSBytes:     565600 * 1024, // the anon-rss from #1349's OOM line
		VirtualBytes: 2753240 * 1024,
		OpenFDs:      37,
		MaxFDs:       65536, // LimitNOFILE from the unit
	}
}

func fakeRuntimeStats() runtimeStats {
	return runtimeStats{
		Goroutines:     42,
		HeapAllocBytes: 123456789,
		SysBytes:       987654321,
	}
}

func TestRenderProcessMetrics_PublishesLeakDetectionSeries(t *testing.T) {
	out := renderProcessMetrics(fakeRuntimeStats(), fakeProcStats())

	for _, want := range []string{
		// The series that would have caught #1349. RSS is first among equals:
		// the Go heap can look flat while RSS climbs (stacks, mmap, cgo), and
		// RSS is what the OOM killer scores.
		"# TYPE process_resident_memory_bytes gauge",
		"process_resident_memory_bytes 5.791744e+08",
		"# TYPE process_virtual_memory_bytes gauge",
		"process_virtual_memory_bytes 2.81931776e+09",
		// A goroutine leak is a common cause of a memory leak; an fd leak is
		// the other classic way this daemon dies (LimitNOFILE=65536).
		"# TYPE go_goroutines gauge",
		"go_goroutines 42",
		"# TYPE process_open_fds gauge",
		"process_open_fds 37",
		"# TYPE process_max_fds gauge",
		"process_max_fds 65536",
		// Heap detail, for telling "which kind of growth" once RSS moves.
		"# TYPE go_memstats_heap_alloc_bytes gauge",
		"go_memstats_heap_alloc_bytes 1.23456789e+08",
		"# TYPE go_memstats_sys_bytes gauge",
		"go_memstats_sys_bytes 9.87654321e+08",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("process metrics missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// TestRenderProcessMetrics_OmitsUnavailableProcSeries is the one that matters
// for correctness of alerting. /proc exists on the Linux hosts the sentinel
// runs on but not on a developer's macOS box. When the read fails the series
// must be ABSENT, never zero: a hard-coded
// `process_resident_memory_bytes 0` reads as "this process uses no memory",
// which silences exactly the alert this issue exists to enable. An absent
// series is detectable with absent(); a lying zero is not.
func TestRenderProcessMetrics_OmitsUnavailableProcSeries(t *testing.T) {
	out := renderProcessMetrics(fakeRuntimeStats(), procStats{Available: false})

	for _, unwanted := range []string{
		"process_resident_memory_bytes",
		"process_virtual_memory_bytes",
		"process_open_fds",
		"process_max_fds",
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("emitted %q with no /proc available — a zero here would silence the leak alert\n--- got ---\n%s", unwanted, out)
		}
	}

	// Runtime series come from the Go runtime and are portable, so they must
	// still be there — losing /proc must not cost us everything.
	if !strings.Contains(out, "go_goroutines 42") {
		t.Errorf("runtime series dropped along with the proc series\n--- got ---\n%s", out)
	}
}

// TestMetricsHandler_ExposesProcessHealth checks the real endpoint, not just
// the renderer — the series has to actually reach a scraper.
func TestMetricsHandler_ExposesProcessHealth(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	rec := httptest.NewRecorder()
	m.MetricsHandler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// The pre-existing preemption signal must survive this change.
	for _, want := range []string{"sentinel_preempted_total", "sentinel_state"} {
		if !strings.Contains(body, want) {
			t.Errorf("regression: %q no longer served\n--- got ---\n%s", want, body)
		}
	}

	// Runtime series are portable — required on every platform.
	for _, want := range []string{"go_goroutines", "go_memstats_heap_alloc_bytes", "go_memstats_sys_bytes"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q\n--- got ---\n%s", want, body)
		}
	}

	// Process series require /proc, i.e. the platform the sentinel deploys on.
	if runtime.GOOS == "linux" {
		for _, want := range []string{"process_resident_memory_bytes", "process_open_fds"} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %q on linux, where the sentinel actually runs\n--- got ---\n%s", want, body)
			}
		}
	}
}

// TestReadProcStats_RealProcess exercises the real /proc read on the platform
// that has it. Skipped elsewhere rather than faked, so a green run on macOS
// never implies this code path works.
func TestReadProcStats_RealProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("no /proc on %s — this path is only exercised on linux", runtime.GOOS)
	}
	ps := readProcStats()
	if !ps.Available {
		t.Fatal("readProcStats reported unavailable on linux")
	}
	if ps.RSSBytes == 0 {
		t.Error("RSS = 0; a running Go process has resident memory")
	}
	if ps.VirtualBytes < ps.RSSBytes {
		t.Errorf("virtual (%d) < resident (%d), which is impossible", ps.VirtualBytes, ps.RSSBytes)
	}
	if ps.OpenFDs == 0 {
		t.Error("open fds = 0; the test process has at least stdin/stdout/stderr")
	}
	if ps.MaxFDs != 0 && ps.OpenFDs > ps.MaxFDs {
		t.Errorf("open fds (%d) > max fds (%d)", ps.OpenFDs, ps.MaxFDs)
	}
}

func TestCollectRuntimeStats_ReportsLiveValues(t *testing.T) {
	rt := collectRuntimeStats()
	if rt.Goroutines < 1 {
		t.Errorf("goroutines = %d, want >= 1", rt.Goroutines)
	}
	if rt.HeapAllocBytes == 0 {
		t.Error("heap alloc = 0; this test binary has allocated")
	}
	if rt.SysBytes < rt.HeapAllocBytes {
		t.Errorf("sys (%d) < heap alloc (%d): total from the OS cannot be less than the live heap",
			rt.SysBytes, rt.HeapAllocBytes)
	}
}

// TestMetricsExpositionIsWellFormed guards the whole endpoint's format: every
// sample line must be preceded by a declared TYPE, or a scraper drops it.
// Cheap structural check, no parser dependency.
func TestMetricsExpositionIsWellFormed(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	rec := httptest.NewRecorder()
	m.MetricsHandler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	declared := map[string]bool{}
	var samples []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "# TYPE "):
			f := strings.Fields(line)
			if len(f) != 4 {
				t.Errorf("malformed TYPE line: %q", line)
				continue
			}
			declared[f[2]] = true
		case strings.HasPrefix(line, "#"): // HELP or comment
		default:
			f := strings.Fields(line)
			if len(f) != 2 {
				t.Errorf("malformed sample line: %q", line)
				continue
			}
			// Strip any label set: sentinel_backend_healthy{backend="gcp"}
			// declares its TYPE under the bare family name (#1358).
			name := f[0]
			if i := strings.IndexByte(name, '{'); i >= 0 {
				if !strings.HasSuffix(name, "}") {
					t.Errorf("unterminated label set in sample line: %q", line)
					continue
				}
				name = name[:i]
			}
			samples = append(samples, name)
		}
	}

	if len(samples) == 0 {
		t.Fatal("no sample lines emitted at all")
	}
	for _, name := range samples {
		if !declared[name] {
			t.Errorf("sample %q has no # TYPE declaration — scrapers will drop it", name)
		}
	}
}

// TestParseStatm covers the /proc parsing on every platform, so the field
// order is not left to a linux-only test that skips on the machine where this
// was written. Transposing the two fields is the failure that matters: it
// would publish virtual size as resident memory, sending a leak hunt after the
// wrong number.
func TestParseStatm(t *testing.T) {
	const pageSize = 4096

	tests := []struct {
		name     string
		raw      string
		wantRSS  uint64
		wantVirt uint64
		wantOK   bool
	}{
		{
			// A real /proc/self/statm line: size, resident, shared, text, lib,
			// data, dt. 2969 pages virtual, 1183 pages resident.
			name: "real statm line", raw: "2969 1183 771 21 0 264 0\n",
			wantVirt: 2969 * pageSize, wantRSS: 1183 * pageSize, wantOK: true,
		},
		{
			// #1349's own numbers, to make the mapping unmistakable:
			// 565600 kB resident inside 2753240 kB virtual.
			name: "the #1349 OOM proportions", raw: "688310 141400 0 0 0 0 0",
			wantVirt: 688310 * pageSize, wantRSS: 141400 * pageSize, wantOK: true,
		},
		{name: "trailing whitespace only", raw: "   \n", wantOK: false},
		{name: "single field", raw: "2969", wantOK: false},
		{name: "non-numeric", raw: "abc def", wantOK: false},
		{name: "empty", raw: "", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rss, virt, ok := parseStatm(tc.raw, pageSize)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if rss != tc.wantRSS {
				t.Errorf("rss = %d, want %d", rss, tc.wantRSS)
			}
			if virt != tc.wantVirt {
				t.Errorf("virt = %d, want %d", virt, tc.wantVirt)
			}
			if rss >= virt {
				t.Errorf("rss (%d) >= virt (%d) — fields look transposed", rss, virt)
			}
		})
	}
}

// A zero page size would silently render every memory series as 0, which is
// the same lie as publishing zeros when /proc is missing.
func TestParseStatm_RejectsZeroPageSize(t *testing.T) {
	if _, _, ok := parseStatm("2969 1183 771 21 0 264 0", 0); ok {
		t.Error("accepted a zero page size; every byte count would render as 0")
	}
}
