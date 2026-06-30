package config

import "testing"

// TestLoadSentinelEmpty verifies all fields are empty when nothing is set.
func TestLoadSentinelEmpty(t *testing.T) {
	for _, k := range []string{
		EnvSentinelAddr, EnvSentinelAlertWebhook, EnvSentinelAuthSecret,
		EnvSentinelCertSANs, EnvSentinelHost, EnvSentinelHTTPSPort,
		EnvSentinelPublicKey, EnvSentinelSigningKey, EnvSentinelURL,
	} {
		t.Setenv(k, "")
	}
	if got := LoadSentinel(); got != (Sentinel{}) {
		t.Errorf("LoadSentinel with empty env = %+v, want zero value", got)
	}
}

// TestLoadSentinelReadsEnv verifies Load maps each variable to its field.
func TestLoadSentinelReadsEnv(t *testing.T) {
	t.Setenv(EnvSentinelHost, "sentinel.example.com")
	t.Setenv(EnvSentinelAuthSecret, "supersecretvalue")
	t.Setenv(EnvSentinelHTTPSPort, "8443")

	s := LoadSentinel()
	if s.Host != "sentinel.example.com" {
		t.Errorf("Host = %q, want sentinel.example.com", s.Host)
	}
	if s.AuthSecret != "supersecretvalue" {
		t.Errorf("AuthSecret = %q", s.AuthSecret)
	}
	if s.HTTPSPort != "8443" {
		t.Errorf("HTTPSPort = %q, want 8443", s.HTTPSPort)
	}
}

// TestSentinelValidateHTTPSPort covers the only validation rule today.
func TestSentinelValidateHTTPSPort(t *testing.T) {
	cases := []struct {
		port    string
		wantErr bool
	}{
		{"", false},        // unset is valid (caller defaults to HTTP port + 1)
		{"8443", false},    // in range
		{"1", false},       // lower bound
		{"65535", false},   // upper bound
		{"notaport", true}, // non-numeric
		{"0", true},        // below range
		{"70000", true},    // above range
		{"-5", true},       // negative
	}
	for _, tc := range cases {
		err := Sentinel{HTTPSPort: tc.port}.Validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("Validate(HTTPSPort=%q) err = %v, wantErr = %v", tc.port, err, tc.wantErr)
		}
	}
}
