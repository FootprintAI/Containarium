package config

import "testing"

func TestLoadEgressConnCap(t *testing.T) {
	for _, tc := range []struct {
		name, rate, mode string
		want             EgressConnCap
	}{
		{"unset is off", "", "", EgressConnCap{}},
		{"rate, default mode counts only", "200", "", EgressConnCap{PerSec: 200}},
		{"enforce", "200", "enforce", EgressConnCap{PerSec: 200, Enforce: true}},
		{"enforce is case and space tolerant", "200", " Enforce ", EgressConnCap{PerSec: 200, Enforce: true}},
		{"unknown mode is the safe one", "200", "block", EgressConnCap{PerSec: 200}},
		{"upper bound", "65535", "", EgressConnCap{PerSec: 65535}},
		{"zero is off", "0", "enforce", EgressConnCap{}},
		{"negative is off", "-5", "enforce", EgressConnCap{}},
		{"above the 16-bit field is off, not wrapped", "65536", "enforce", EgressConnCap{}},
		{"not a number is off", "many", "enforce", EgressConnCap{}},
		{"mode alone does not enable", "", "enforce", EgressConnCap{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvEgressConnCapPerSec, tc.rate)
			t.Setenv(EnvEgressConnCapMode, tc.mode)
			if got := LoadEgressConnCap(); got != tc.want {
				t.Fatalf("LoadEgressConnCap() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
