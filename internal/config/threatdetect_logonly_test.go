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
