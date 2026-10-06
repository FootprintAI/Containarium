package nicguard

import (
	"net/netip"
	"testing"
)

// Unset arms the guard (a boundary, not optional hardening); only an
// explicit off-word disables, and a typo fails closed.
func TestParseMode(t *testing.T) {
	tests := []struct {
		in   string
		want Mode
	}{
		{"", ModeEnforce},
		{"enforce", ModeEnforce},
		{"Enforce", ModeEnforce},
		{" enforce ", ModeEnforce},
		{"1", ModeEnforce},
		{"true", ModeEnforce},
		{"typo", ModeEnforce},
		{"off", ModeOff},
		{"OFF", ModeOff},
		{" off ", ModeOff},
		{"0", ModeOff},
		{"false", ModeOff},
		{"no", ModeOff},
		{"disabled", ModeOff},
	}
	for _, tc := range tests {
		if got := ParseMode(tc.in); got != tc.want {
			t.Errorf("ParseMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseBridge(t *testing.T) {
	tests := []struct {
		in         string
		wantBridge string
		wantGW     string
		wantErr    bool
	}{
		{"10.100.0.1/24", "10.100.0.0/24", "10.100.0.1", false},
		{"10.100.0.0/24", "10.100.0.0/24", "10.100.0.1", false},
		{"10.0.3.1/24", "10.0.3.0/24", "10.0.3.1", false},
		{"fd00::1/64", "", "", true},
		{"nope", "", "", true},
	}
	for _, tc := range tests {
		bridge, gw, err := ParseBridge(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseBridge(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseBridge(%q): %v", tc.in, err)
		}
		if bridge != netip.MustParsePrefix(tc.wantBridge) || gw != netip.MustParseAddr(tc.wantGW) {
			t.Errorf("ParseBridge(%q) = %s, %s; want %s, %s", tc.in, bridge, gw, tc.wantBridge, tc.wantGW)
		}
	}
}
