package hostport

import "testing"

func TestSplit(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		defPort  int
		wantHost string
		wantPort int
	}{
		// Ported from internal/sshconfig/generate_test.go's former
		// TestSplitHostPort — bare host / host:port / bracketed IPv6,
		// with and without an explicit port.
		{"bare host uses default port", "sentinel.example.com", 22, "sentinel.example.com", 22},
		{"host:port", "sentinel.example.com:2222", 22, "sentinel.example.com", 2222},
		{"bracketed IPv6 with port", "[2001:db8::1]:2222", 22, "2001:db8::1", 2222},
		{"bracketed IPv6 without port uses default", "[2001:db8::1]", 22, "2001:db8::1", 22},

		// Ported from internal/sentinel/sshsession/plugin.go's former
		// splitHostPort — a live connection's RemoteAddr(), default 0,
		// and the "can't parse at all" fallback (whole string as host).
		{"downstream client address", "203.0.113.42:4242", 0, "203.0.113.42", 4242},
		{"no port and no default falls back to the whole string", "not-an-address", 0, "not-an-address", 0},
		{"non-numeric port falls back to default", "example.com:notaport", 0, "example.com", 0},

		// Ported from internal/cmd/egress_via_client.go's former
		// splitHostPort — a self-generated SOCKS listener address.
		{"loopback socks address", "127.0.0.1:38901", 0, "127.0.0.1", 38901},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, p := Split(c.in, c.defPort)
			if h != c.wantHost || p != c.wantPort {
				t.Errorf("Split(%q, %d) = (%q, %d), want (%q, %d)",
					c.in, c.defPort, h, p, c.wantHost, c.wantPort)
			}
		})
	}
}
