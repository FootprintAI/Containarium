package server

import "testing"

// TestBridgeDNSRaw covers the incusbr0 raw.dnsmasq construction: the base
// *.baseDomain -> caddy hairpin, plus the SSH-apex carve-out so the sentinel
// apex isn't swallowed by the wildcard (#837.1).
func TestBridgeDNSRaw(t *testing.T) {
	cases := []struct {
		name               string
		base, caddyIP, ssh string
		want               string
	}{
		{
			name: "ssh apex carved out",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "region-a.example.com",
			want: "address=/example.com/10.0.3.5\nserver=/region-a.example.com/#",
		},
		{
			name: "no ssh host -> wildcard only (direct mode)",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "",
			want: "address=/example.com/10.0.3.5",
		},
		{
			name: "ssh host equal to base -> no carve-out (would self-collide)",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "example.com",
			want: "address=/example.com/10.0.3.5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bridgeDNSRaw(tc.base, tc.caddyIP, tc.ssh); got != tc.want {
				t.Errorf("bridgeDNSRaw(%q,%q,%q)\n got: %q\nwant: %q", tc.base, tc.caddyIP, tc.ssh, got, tc.want)
			}
		})
	}
}
