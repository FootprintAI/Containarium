package config

import "testing"

// #2612: counting observation-only would-deny events is opt-in.
func TestLoadThreatDetect_DenyBurstCountLogOnly(t *testing.T) {
	if LoadThreatDetect().DenyBurstCountLogOnly {
		t.Fatal("DenyBurstCountLogOnly must default to false")
	}
	t.Setenv(EnvThreatDenyBurstCountLogOnly, "1")
	if !LoadThreatDetect().DenyBurstCountLogOnly {
		t.Fatal("DenyBurstCountLogOnly not set from " + EnvThreatDenyBurstCountLogOnly)
	}
}

// #3709: handing outbound fan-out findings to the process responder is opt-in.
func TestLoadThreatDetect_FanoutRespond(t *testing.T) {
	if LoadThreatDetect().FanoutRespond {
		t.Fatal("FanoutRespond must default to false")
	}
	t.Setenv(EnvThreatFanoutRespond, "1")
	if !LoadThreatDetect().FanoutRespond {
		t.Fatal("FanoutRespond not set from " + EnvThreatFanoutRespond)
	}
}

// #3709: the flow log is opt-in, in hours, clamped to 72.
func TestLoadThreatDetect_FlowLogRetention(t *testing.T) {
	if got := LoadThreatDetect().FlowLogRetention; got != 0 {
		t.Fatalf("FlowLogRetention defaults to %v, want 0 (off)", got)
	}
	for _, tc := range []struct {
		in   string
		want int // hours
	}{{"6", 6}, {"72", 72}, {"500", 72}, {"0", 0}, {"-3", 0}, {"soon", 0}} {
		t.Setenv(EnvThreatFlowLogHours, tc.in)
		if got := LoadThreatDetect().FlowLogRetention; got.Hours() != float64(tc.want) {
			t.Errorf("%q -> %v, want %dh", tc.in, got, tc.want)
		}
	}
}
