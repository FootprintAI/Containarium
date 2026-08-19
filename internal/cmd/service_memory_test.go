//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Memory bounds on the unit templates (#1350).
//
// The incident: #1349 leaked ~18 MB/day until the sentinel held 565 MB on a
// 1 GB host. Nothing bounded it, so the KERNEL resolved it — 36 minutes into a
// full-host stall (73.91% iowait, load 32.46, 12 tasks in D), after global
// reclaim had already made the box useless. `Restart=always` worked fine; what
// was missing was anything acting on memory pressure BEFORE the host was
// thrashing.
//
// The distinction these tests protect: with MemoryHigh, reclaim pressure stays
// inside the sentinel's own cgroup instead of evicting the host's page cache.
// The failure becomes local and survivable rather than taking the apex down.
//
// Corrected by #1454: that holds only where reclaim can make progress. With no
// swap and an anon-dominated cgroup there is nothing to reclaim, so a
// MemoryHigh BELOW MemoryMax stalls the process below its cap indefinitely —
// never restarted, still reported healthy. The band, not the cap, was the bug;
// see TestSentinelUnitMemoryBandRules.

func sentinelUnitForTest(t *testing.T) string {
	t.Helper()
	unit, err := buildSentinelUnit(sentinelUnitConfig{
		SpotVM:     "vm",
		Zone:       "zone",
		Project:    "proj",
		MemoryHigh: defaultSentinelMemoryHigh,
		MemoryMax:  defaultSentinelMemoryMax,
	})
	if err != nil {
		t.Fatalf("buildSentinelUnit: %v", err)
	}
	return unit
}

func TestSentinelUnitBoundsMemory(t *testing.T) {
	unit := sentinelUnitForTest(t)

	for _, want := range []string{
		// Without accounting the other two directives are inert on some
		// configurations, and no cgroup memory stats exist to look at either.
		"MemoryAccounting=yes",
		// The one that matters: throttle-and-reclaim inside this cgroup
		// before the host as a whole is under pressure.
		"MemoryHigh=" + defaultSentinelMemoryHigh,
		// The hard stop. With Restart=always this is a restart, not a death.
		"MemoryMax=" + defaultSentinelMemoryMax,
		// Explicit rather than inherited, so the interaction with
		// Restart=always is readable in the unit itself.
		"OOMPolicy=stop",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("sentinel unit missing %q — a leak would again stall the whole VM "+
				"instead of restarting one process\n--- got ---\n%s", want, unit)
		}
	}
}

// Restart=always is what turns MemoryMax from "the sentinel dies" into "the
// sentinel restarts". Capping memory without it would be a regression, so the
// pairing is pinned.
func TestSentinelUnitStillRestartsAfterAnOOMKill(t *testing.T) {
	unit := sentinelUnitForTest(t)
	if !strings.Contains(unit, "Restart=always") {
		t.Error("sentinel unit lost Restart=always; with MemoryMax set, that turns a bounded " +
			"leak into a permanently dead apex forwarder")
	}
}

// Every unit should at least ACCOUNT for its memory, even where we decline to
// cap it — that is what makes the working set measurable, and #1349 was
// invisible for 27 days precisely because nothing measured it.
func TestAllUnitsHaveMemoryAccounting(t *testing.T) {
	for name, unit := range unitSources(t) {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(unit, "MemoryAccounting=yes") {
				t.Errorf("%s does not enable MemoryAccounting — its working set cannot be "+
					"measured, so no one can tell a leak from normal growth", name)
			}
		})
	}
}

func TestParseSystemdMemoryValue(t *testing.T) {
	tests := []struct {
		in      string
		wantErr string
	}{
		// Percentages: relative to installed RAM, which is what lets one
		// default work on both the 1 GB and 2 GB sentinel hosts.
		{in: "35%"}, {in: "50%"}, {in: "100%"}, {in: "1%"},
		// Absolute sizes.
		{in: "512M"}, {in: "1G"}, {in: "1024K"}, {in: "2000000"}, {in: "4T"},
		{in: "infinity"},

		{in: "", wantErr: "empty"},
		{in: "abc", wantErr: "invalid"},
		{in: "-5M", wantErr: "invalid"},
		{in: "0%", wantErr: "between 1% and 100%"},
		{in: "101%", wantErr: "between 1% and 100%"},
		{in: "50 %", wantErr: "invalid"},
		{in: "50MB", wantErr: "invalid"}, // systemd wants M, not MB
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			err := validateSystemdMemoryValue(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateSystemdMemoryValue(%q) = %v, want nil", tc.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateSystemdMemoryValue(%q) = nil, want error containing %q", tc.in, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// #1454 inverted the rule these cases used to assert.
//
// The old rule REQUIRED MemoryHigh below MemoryMax, on the reasoning that
// reaching the cap without being reclaimed first was the #1349 shape. That
// reasoning holds only where reclaim can make progress. On a swapless host
// with an anon-dominated cgroup it cannot: page cache is gone within minutes
// and there is nothing left to evict, so the band between the two limits is a
// trap the process can neither leave nor die in. It stalls below the cap
// forever, Restart=always never fires, and systemd still reports it running.
//
// So: above max is still rejected, below max is rejected only without swap,
// and equal — the new default — is always allowed.
func TestSentinelUnitMemoryBandRules(t *testing.T) {
	tests := []struct {
		name, high, max string
		hasSwap         bool
		wantErr         string
	}{
		// Equal is the default and must always build.
		{name: "equal percentages, no swap", high: "50%", max: "50%"},
		{name: "equal percentages, swap", high: "50%", max: "50%", hasSwap: true},
		{name: "equal sizes, no swap", high: "512M", max: "512M"},

		// The regression this issue is about: a band on a swapless host.
		{name: "band without swap, percent", high: "35%", max: "50%", wantErr: "no swap"},
		{name: "band without swap, sizes", high: "256M", max: "512M", wantErr: "no swap"},

		// The same band is legitimate where anon can actually be paged out.
		{name: "band with swap, percent", high: "35%", max: "50%", hasSwap: true},
		{name: "band with swap, sizes", high: "256M", max: "512M", hasSwap: true},

		// Above the cap is incoherent regardless of swap: MemoryMax binds
		// first, so the advertised throttle can never engage.
		{name: "high above max, percent", high: "80%", max: "50%", wantErr: "must not be above"},
		{name: "high above max, sizes", high: "1G", max: "512M", wantErr: "must not be above"},
		{name: "high above max, with swap", high: "80%", max: "50%", hasSwap: true, wantErr: "must not be above"},

		// Mixed units cannot be ordered without knowing physical RAM, so they
		// are allowed through rather than guessed at.
		{name: "mixed units pass validation", high: "35%", max: "512M"},
		{name: "infinity max is not comparable", high: "35%", max: "infinity"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildSentinelUnit(sentinelUnitConfig{
				SpotVM: "vm", Zone: "z", Project: "p",
				MemoryHigh: tc.high, MemoryMax: tc.max, HostHasSwap: tc.hasSwap,
			})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// The shipped defaults must not themselves open a throttle band — that is the
// #1454 bug, and defaults are what almost every host actually runs. A host with
// no swap is the case that matters, since that is what the sentinel fleet is.
func TestSentinelMemoryDefaultsHaveNoThrottleBand(t *testing.T) {
	if defaultSentinelMemoryHigh != defaultSentinelMemoryMax {
		t.Errorf("default MemoryHigh (%s) != MemoryMax (%s): on a swapless host that band is where "+
			"the cgroup stalls below the cap and never gets restarted (#1454)",
			defaultSentinelMemoryHigh, defaultSentinelMemoryMax)
	}
	if _, err := buildSentinelUnit(sentinelUnitConfig{
		SpotVM: "vm", Zone: "z", Project: "p",
		MemoryHigh: defaultSentinelMemoryHigh, MemoryMax: defaultSentinelMemoryMax,
		HostHasSwap: false,
	}); err != nil {
		t.Fatalf("defaults must build on a swapless host, got: %v", err)
	}
}

// hostHasSwap decides which of the two band rules applies, so a
// misparse silently re-enables the #1454 configuration on a swapless host.
// Unreadable or malformed input must read as "no swap" — the conservative
// direction, since that only ever tightens the check.
func TestHostHasSwap(t *testing.T) {
	const meminfo = `MemTotal:         978352 kB
MemFree:           67784 kB
SwapTotal:      %s kB
SwapFree:              0 kB
`
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{name: "no swap", content: fmt.Sprintf(meminfo, "0"), want: false},
		{name: "has swap", content: fmt.Sprintf(meminfo, "2097148"), want: true},
		{name: "SwapTotal absent", content: "MemTotal: 978352 kB\n", want: false},
		{name: "unparseable value", content: "SwapTotal:  banana kB\n", want: false},
		{name: "no value at all", content: "SwapTotal:\n", want: false},
		{name: "empty file", content: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "meminfo")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			t.Cleanup(func(orig string) func() {
				return func() { procMeminfoPath = orig }
			}(procMeminfoPath))
			procMeminfoPath = path

			if got := hostHasSwap(); got != tc.want {
				t.Errorf("hostHasSwap() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A missing /proc/meminfo must not read as "has swap" — that would let the
// install path emit the throttle band on exactly the hosts it cannot verify.
func TestHostHasSwapMissingFileIsConservative(t *testing.T) {
	t.Cleanup(func(orig string) func() {
		return func() { procMeminfoPath = orig }
	}(procMeminfoPath))
	procMeminfoPath = filepath.Join(t.TempDir(), "definitely-absent")

	if hostHasSwap() {
		t.Error("hostHasSwap() = true for an unreadable /proc/meminfo; it must fail closed so an " +
			"unverifiable host still gets the no-band configuration (#1454)")
	}
}
