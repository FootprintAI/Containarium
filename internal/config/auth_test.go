package config

import "testing"

func clearAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvStrictScopes, "")
}

// TestLoadAuthDefaults verifies the permissive default posture (#1679): strict
// mode is off unless explicitly armed.
func TestLoadAuthDefaults(t *testing.T) {
	clearAuthEnv(t)
	if got := LoadAuth(); got != (Auth{}) {
		t.Errorf("LoadAuth with empty env = %+v, want zero value", got)
	}
}

func TestLoadAuthReadsEnv(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv(EnvStrictScopes, "1")
	if got := LoadAuth(); !got.StrictScopes {
		t.Errorf("LoadAuth().StrictScopes = false, want true for %q=1", EnvStrictScopes)
	}
}

func TestLoadAuthStrictScopesOffByDefault(t *testing.T) {
	clearAuthEnv(t)
	for _, v := range []string{"", "0", "false", "off", "no"} {
		t.Setenv(EnvStrictScopes, v)
		if LoadAuth().StrictScopes {
			t.Errorf("StrictScopes=true for %q, want off", v)
		}
	}
}
