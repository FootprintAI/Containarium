//go:build !windows && !containarium_client

package cmd

import "testing"

// The daemon's sentinel URL comes from --sentinel-url, falling back to
// CONTAINARIUM_SENTINEL_URL (the name the peer-PKI comments and the
// TriggerUpgrade error already tell operators to use). The flag wins so an
// explicit command line is never silently overridden by the environment.
func TestResolveSentinelURL(t *testing.T) {
	tests := []struct {
		name, flag, env, want string
	}{
		{"flag only", "http://flag:8081", "", "http://flag:8081"},
		{"env only", "", "http://env:8081", "http://env:8081"},
		{"flag wins over env", "http://flag:8081", "http://env:8081", "http://flag:8081"},
		{"neither", "", "", ""},
		{"whitespace env is unset", "", "  \n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveSentinelURL(tt.flag, tt.env); got != tt.want {
				t.Fatalf("resolveSentinelURL(%q, %q) = %q, want %q", tt.flag, tt.env, got, tt.want)
			}
		})
	}
}
