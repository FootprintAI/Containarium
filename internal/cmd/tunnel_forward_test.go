package cmd

import "testing"

func TestParseForwardMap(t *testing.T) {
	t.Run("empty is nil", func(t *testing.T) {
		m, err := parseForwardMap(nil)
		if err != nil || m != nil {
			t.Fatalf("parseForwardMap(nil) = (%v, %v), want (nil, nil)", m, err)
		}
	})
	t.Run("valid entries", func(t *testing.T) {
		m, err := parseForwardMap([]string{"32022=10.0.0.5:32022", "443=lb.example.com:443"})
		if err != nil {
			t.Fatalf("parseForwardMap: %v", err)
		}
		if m[32022] != "10.0.0.5:32022" || m[443] != "lb.example.com:443" {
			t.Errorf("map = %v", m)
		}
	})
	for _, bad := range []string{"noequals", "0=host:1", "70000=host:1", "32022=nohostport"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			if _, err := parseForwardMap([]string{bad}); err == nil {
				t.Errorf("parseForwardMap(%q) should error", bad)
			}
		})
	}
}
