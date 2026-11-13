package config

import "testing"

func TestLoadEgressConnCap(t *testing.T) {
	for _, tc := range []struct {
		name, rate, mode string
		want             EgressConnCap
		ignored          bool // the variable was set but unusable, so the daemon can say so
	}{
		{"unset is off", "", "", EgressConnCap{}, false},
		{"rate, default mode counts only", "200", "", EgressConnCap{PerSec: 200}, false},
		{"enforce", "200", "enforce", EgressConnCap{PerSec: 200, Enforce: true}, false},
		{"enforce is case and space tolerant", "200", " Enforce ", EgressConnCap{PerSec: 200, Enforce: true}, false},
		{"unknown mode is the safe one", "200", "block", EgressConnCap{PerSec: 200}, false},
		{"upper bound", "65535", "", EgressConnCap{PerSec: 65535}, false},
		{"zero is off", "0", "enforce", EgressConnCap{}, false},
		{"negative is off", "-5", "enforce", EgressConnCap{}, true},
		{"above the 16-bit field is off, not wrapped", "65536", "enforce", EgressConnCap{}, true},
		{"not a number is off", "many", "enforce", EgressConnCap{}, true},
		{"mode alone does not enable", "", "enforce", EgressConnCap{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvEgressConnCapPerSec, tc.rate)
			t.Setenv(EnvEgressConnCapMode, tc.mode)
			got := LoadEgressConnCap()
			if got.PerSec != tc.want.PerSec || got.Enforce != tc.want.Enforce {
				t.Fatalf("LoadEgressConnCap() = %+v, want %+v", got, tc.want)
			}
			if (got.Ignored != "") != tc.ignored {
				t.Fatalf("Ignored = %q, want it set: %v", got.Ignored, tc.ignored)
			}
		})
	}
}
