//go:build !containarium_client

package cmd

import "testing"

// TestResolveServerAddr_Default pins that containariumd's resolveServerAddr
// is the identity function: no credentials-file fallback, even with an
// empty input. An operator's host must never get silently repointed from
// local Incus to a stale remote fleet by a leftover default_server (#1776).
func TestResolveServerAddr_Default(t *testing.T) {
	for _, in := range []string{"", "35.229.246.67:50051", "https://cloud.example.com"} {
		if got := resolveServerAddr(in); got != in {
			t.Errorf("resolveServerAddr(%q) = %q, want unchanged under containariumd", in, got)
		}
	}
}
