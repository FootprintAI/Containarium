//go:build !windows

package cmd

import (
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

// A MemoryHigh at or above MemoryMax is the no-throttle behaviour with extra
// words: the cgroup would hit the hard cap without ever having been reclaimed
// under pressure first, which is exactly the #1349 failure shape.
func TestSentinelUnitRejectsHighAtOrAboveMax(t *testing.T) {
	tests := []struct {
		name, high, max, wantErr string
	}{
		{name: "equal percentages", high: "50%", max: "50%", wantErr: "must be below"},
		{name: "high above max, percent", high: "80%", max: "50%", wantErr: "must be below"},
		{name: "equal sizes", high: "512M", max: "512M", wantErr: "must be below"},
		{name: "high above max, sizes", high: "1G", max: "512M", wantErr: "must be below"},
		{name: "valid percentages", high: "35%", max: "50%"},
		{name: "valid sizes", high: "256M", max: "512M"},
		// Mixed units cannot be compared without knowing physical RAM, so they
		// are allowed through rather than guessed at.
		{name: "mixed units pass validation", high: "35%", max: "512M"},
		{name: "infinity max is always above", high: "35%", max: "infinity"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildSentinelUnit(sentinelUnitConfig{
				SpotVM: "vm", Zone: "z", Project: "p",
				MemoryHigh: tc.high, MemoryMax: tc.max,
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

// The defaults have to leave real headroom over the sentinel's actual working
// set, or the cap causes restart loops — a worse failure than the slow leak it
// guards against. Cold start was 82 MB when #1349 was diagnosed; on the 1 GB
// host these percentages must sit several times above that.
func TestSentinelMemoryDefaultsLeaveHeadroom(t *testing.T) {
	const (
		oneGiB            = 1024 * 1024 * 1024
		observedColdStart = 82 * 1024 * 1024
		observedLeakPeak  = 565 * 1024 * 1024 // RSS at the OOM kill
	)

	highPct, err := percentValue(defaultSentinelMemoryHigh)
	if err != nil {
		t.Fatalf("default MemoryHigh is not a percentage: %v", err)
	}
	maxPct, err := percentValue(defaultSentinelMemoryMax)
	if err != nil {
		t.Fatalf("default MemoryMax is not a percentage: %v", err)
	}

	highBytes := oneGiB * highPct / 100
	maxBytes := oneGiB * maxPct / 100

	if highBytes < 3*observedColdStart {
		t.Errorf("MemoryHigh default (%s = %d bytes on a 1 GB host) is under 3x the observed "+
			"82 MB cold start; a busy sentinel would be throttled in normal operation",
			defaultSentinelMemoryHigh, highBytes)
	}
	// The whole point: both bounds must engage below where #1349 actually got
	// to, or they would not have changed that outcome at all.
	if maxBytes >= observedLeakPeak {
		t.Errorf("MemoryMax default (%s = %d bytes on a 1 GB host) is at or above the 565 MB the "+
			"#1349 leak reached — the cap would never have fired", defaultSentinelMemoryMax, maxBytes)
	}
	if highBytes >= maxBytes {
		t.Errorf("MemoryHigh (%d) must be below MemoryMax (%d)", highBytes, maxBytes)
	}
}
