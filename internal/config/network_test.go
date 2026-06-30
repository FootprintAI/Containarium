package config

import "testing"

func clearNetworkEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{EnvNetworkPolicyBPFObject, EnvNetworkPolicyEnforce, EnvNetworkPolicySignatures} {
		t.Setenv(k, "")
	}
}

// TestLoadNetworkDefaults verifies the observation-only default posture: enforcer
// disabled, both arming flags off.
func TestLoadNetworkDefaults(t *testing.T) {
	clearNetworkEnv(t)
	if got := LoadNetwork(); got != (Network{}) {
		t.Errorf("LoadNetwork with empty env = %+v, want zero value", got)
	}
}

// TestLoadNetworkReadsEnv verifies the field mapping and that the arming flags
// honor the truthy convention.
func TestLoadNetworkReadsEnv(t *testing.T) {
	clearNetworkEnv(t)
	t.Setenv(EnvNetworkPolicyBPFObject, "/opt/containarium/netpolicy.bpf.o")
	t.Setenv(EnvNetworkPolicyEnforce, "1")
	t.Setenv(EnvNetworkPolicySignatures, "yes")

	want := Network{
		PolicyBPFObject:  "/opt/containarium/netpolicy.bpf.o",
		PolicyEnforce:    true,
		PolicySignatures: true,
	}
	if got := LoadNetwork(); got != want {
		t.Errorf("LoadNetwork = %+v, want %+v", got, want)
	}
}

// TestLoadNetworkArmingFlagsOffByDefault verifies that an unset or non-truthy
// arming flag stays off — a safety-relevant default for the eBPF enforcer.
func TestLoadNetworkArmingFlagsOffByDefault(t *testing.T) {
	clearNetworkEnv(t)
	t.Setenv(EnvNetworkPolicyBPFObject, "/x.o")
	for _, v := range []string{"", "0", "false", "off", "no"} {
		t.Setenv(EnvNetworkPolicyEnforce, v)
		if LoadNetwork().PolicyEnforce {
			t.Errorf("PolicyEnforce=true for %q, want off", v)
		}
	}
}
