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
