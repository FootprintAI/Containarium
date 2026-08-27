package incus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCPUStat(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    cpuThrottle
		wantOK  bool
	}{
		{
			name: "cgroup v2 cpu.stat with a throttled container",
			content: `usage_usec 12345678
user_usec 9000000
system_usec 3345678
nr_periods 40031
nr_throttled 12847
throttled_usec 98765432
`,
			want:   cpuThrottle{NrPeriods: 40031, NrThrottled: 12847, ThrottledUsec: 98765432},
			wantOK: true,
		},
		{
			name: "unthrottled container still reports periods",
			content: `usage_usec 500
nr_periods 8123
nr_throttled 0
throttled_usec 0
`,
			want:   cpuThrottle{NrPeriods: 8123},
			wantOK: true,
		},
		{
			// A cgroup with no CPU bandwidth limit set omits the burst/throttle
			// keys entirely on some kernels — usage-only is not a parse failure,
			// but it carries no throttling signal.
			name:    "usage-only cpu.stat has no throttling keys",
			content: "usage_usec 500\nuser_usec 100\nsystem_usec 400\n",
			want:    cpuThrottle{},
			wantOK:  false,
		},
		{
			name:    "empty file",
			content: "",
			want:    cpuThrottle{},
			wantOK:  false,
		},
		{
			// Defensive: a malformed value must not poison the other counters.
			name:    "malformed value is skipped, siblings survive",
			content: "nr_periods 100\nnr_throttled notanumber\nthrottled_usec 42\n",
			want:    cpuThrottle{NrPeriods: 100, ThrottledUsec: 42},
			wantOK:  true,
		},
		{
			// cgroup v1 spells the time counter in nanoseconds under a different
			// key; we normalize it to microseconds so callers see one unit.
			name:    "cgroup v1 throttled_time (ns) normalizes to usec",
			content: "nr_periods 10\nnr_throttled 3\nthrottled_time 5000000\n",
			want:    cpuThrottle{NrPeriods: 10, NrThrottled: 3, ThrottledUsec: 5000},
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseCPUStat(tt.content)
			if ok != tt.wantOK {
				t.Fatalf("parseCPUStat() ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("parseCPUStat() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCgroupV2PathFromProc(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "incus container under lxc.payload scope",
			content: "0::/lxc.payload.alice-container\n",
			want:    "lxc.payload.alice-container",
		},
		{
			name:    "systemd-managed nested path",
			content: "0::/lxc.payload.bob-container/system.slice/sshd.service\n",
			want:    "lxc.payload.bob-container/system.slice/sshd.service",
		},
		{
			// A hybrid host lists v1 controllers first; only the unified 0:: line
			// is usable for a cgroup v2 cpu.stat read.
			name:    "hybrid hierarchy picks the unified line",
			content: "12:memory:/lxc.payload.carol\n11:cpu,cpuacct:/lxc.payload.carol\n0::/lxc.payload.carol\n",
			want:    "lxc.payload.carol",
		},
		{
			name:    "root cgroup yields no relative path",
			content: "0::/\n",
			want:    "",
		},
		{
			name:    "cgroup v1 only — no unified line",
			content: "11:cpu,cpuacct:/lxc.payload.dave\n",
			want:    "",
		},
		{
			name:    "empty",
			content: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cgroupV2PathFromProc(tt.content); got != tt.want {
				t.Errorf("cgroupV2PathFromProc() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadCPUThrottle(t *testing.T) {
	// Build a fake cgroup hierarchy plus a fake /proc/<pid>/cgroup pointing into
	// it, so the whole resolve-then-read path is exercised without a live host.
	newTree := func(t *testing.T, procLine, cgroupRel, statBody string) (string, string) {
		t.Helper()
		dir := t.TempDir()
		procPath := filepath.Join(dir, "proc-cgroup")
		if err := os.WriteFile(procPath, []byte(procLine), 0o600); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(dir, "cgroup")
		if cgroupRel != "" {
			leaf := filepath.Join(root, cgroupRel)
			if err := os.MkdirAll(leaf, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(leaf, "cpu.stat"), []byte(statBody), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return procPath, root
	}

	t.Run("reads the container's counters", func(t *testing.T) {
		proc, root := newTree(t, "0::/lxc.payload.alice-container\n", "lxc.payload.alice-container",
			"usage_usec 10\nnr_periods 900\nnr_throttled 120\nthrottled_usec 3400\n")
		got, ok := readCPUThrottle(proc, root)
		if !ok {
			t.Fatal("readCPUThrottle() ok = false, want true")
		}
		want := cpuThrottle{NrPeriods: 900, NrThrottled: 120, ThrottledUsec: 3400}
		if got != want {
			t.Errorf("readCPUThrottle() = %+v, want %+v", got, want)
		}
	})

	t.Run("missing proc file is a silent no-signal", func(t *testing.T) {
		_, root := newTree(t, "", "", "")
		if _, ok := readCPUThrottle(filepath.Join(t.TempDir(), "absent"), root); ok {
			t.Error("readCPUThrottle() ok = true, want false")
		}
	})

	t.Run("missing cpu.stat is a silent no-signal", func(t *testing.T) {
		proc, root := newTree(t, "0::/lxc.payload.bob-container\n", "", "")
		if _, ok := readCPUThrottle(proc, root); ok {
			t.Error("readCPUThrottle() ok = true, want false")
		}
	})

	t.Run("path traversal in the cgroup line is refused", func(t *testing.T) {
		proc, root := newTree(t, "0::/../../etc\n", "", "")
		if _, ok := readCPUThrottle(proc, root); ok {
			t.Error("readCPUThrottle() ok = true, want false — traversal must be refused")
		}
	})

	t.Run("stopped container has no pid to resolve", func(t *testing.T) {
		if _, ok := containerCPUThrottle(0); ok {
			t.Error("containerCPUThrottle(0) ok = true, want false")
		}
	})
}
