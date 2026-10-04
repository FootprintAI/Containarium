//go:build !windows

package hostcheck

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The platform's own daemons must keep scheduling when tenants contend
// (#2284). The check reads the EFFECTIVE weight systemd realized for each
// unit's cgroup — not the unit file — so a drop-in that was written but
// never applied (no daemon-reload, no restart) shows up red.
func TestPlatformCPUWeightCheck(t *testing.T) {
	weight := strconv.Itoa(PlatformCPUWeight)
	cases := map[string]struct {
		files  map[string]string // relative to the system.slice dir
		wantOK bool
		detail []string
	}{
		"both units at the platform weight": {
			files:  map[string]string{"incus.service/cpu.weight": weight + "\n", "containarium.service/cpu.weight": weight + "\n"},
			wantOK: true,
			detail: []string{"incus.service=" + weight, "containarium.service=" + weight},
		},
		"above the floor is fine": {
			files:  map[string]string{"incus.service/cpu.weight": "5000\n", "containarium.service/cpu.weight": weight + "\n"},
			wantOK: true,
		},
		"incus still at the tenant default": {
			files:  map[string]string{"incus.service/cpu.weight": "100\n", "containarium.service/cpu.weight": weight + "\n"},
			wantOK: false,
			detail: []string{"incus.service=100", "below " + weight},
		},
		"daemon unit cgroup missing": {
			files:  map[string]string{"incus.service/cpu.weight": weight + "\n"},
			wantOK: false,
			detail: []string{"could not determine", "containarium.service"},
		},
		"nothing at all": {
			files:  map[string]string{},
			wantOK: false,
			detail: []string{"could not determine"},
		},
		"garbage is unknown, not a pass": {
			files:  map[string]string{"incus.service/cpu.weight": "max\n", "containarium.service/cpu.weight": weight + "\n"},
			wantOK: false,
			detail: []string{"could not determine", "incus.service"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, dir := tempPaths(t)
			slice := filepath.Join(dir, "system.slice")
			p.cgroupSystemSlice = slice
			for rel, content := range tc.files {
				write(t, filepath.Join(slice, rel), content)
			}
			c := platformCPUWeightCheck(p)
			if c.OK != tc.wantOK {
				t.Fatalf("OK = %v, want %v (detail: %s)", c.OK, tc.wantOK, c.Detail)
			}
			if c.Name != "platform daemons CPU weight" {
				t.Errorf("name = %q", c.Name)
			}
			for _, d := range tc.detail {
				if !strings.Contains(c.Detail, d) {
					t.Errorf("detail lacks %q: %s", d, c.Detail)
				}
			}
		})
	}
}

// The check rides along in RunPosture — non-blocking like every posture
// check — so `doctor`, `pool join` and the cloud probe all report it.
func TestRunPosture_IncludesPlatformCPUWeight(t *testing.T) {
	p, _ := tempPaths(t)
	for _, c := range runPosture(p) {
		if c.Name == "platform daemons CPU weight" {
			if c.Required || c.Kind != KindPosture {
				t.Errorf("must be a non-blocking posture check, got Required=%v Kind=%q", c.Required, c.Kind)
			}
			return
		}
	}
	t.Fatal("runPosture does not include the platform CPU weight check")
}

func TestPlatformCPUUnits(t *testing.T) {
	want := []string{"incus.service", "containarium.service"}
	if len(PlatformCPUUnits) != len(want) {
		t.Fatalf("PlatformCPUUnits = %v, want %v", PlatformCPUUnits, want)
	}
	for i := range want {
		if PlatformCPUUnits[i] != want[i] {
			t.Errorf("PlatformCPUUnits[%d] = %q, want %q", i, PlatformCPUUnits[i], want[i])
		}
	}
	if PlatformCPUWeight <= 100 {
		t.Errorf("PlatformCPUWeight = %d must sit well above systemd's default 100 (the tenant weight)", PlatformCPUWeight)
	}
}
