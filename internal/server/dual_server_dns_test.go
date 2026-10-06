package server

import (
	"strings"
	"testing"
)

// TestBridgeDNSRaw covers the incusbr0 raw.dnsmasq construction: the base
// *.baseDomain -> caddy hairpin, plus the SSH-apex carve-out so the sentinel
// apex isn't swallowed by the wildcard (#837.1).
func TestBridgeDNSRaw(t *testing.T) {
	cases := []struct {
		name               string
		base, caddyIP, ssh string
		extra              []string
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
		// #2188: operator-configured passthrough hosts sit next to the SSH
		// carve-out, each resolved via the upstream resolvers.
		{
			name: "one passthrough host",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "",
			extra: []string{"api.example.com"},
			want:  "address=/example.com/10.0.3.5\nserver=/api.example.com/#",
		},
		{
			name: "ssh apex then passthrough hosts, in flag order",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "region-a.example.com",
			extra: []string{"api.example.com", "cp.example.com"},
			want:  "address=/example.com/10.0.3.5\nserver=/region-a.example.com/#\nserver=/api.example.com/#\nserver=/cp.example.com/#",
		},
		{
			name: "duplicates and the ssh host are emitted once",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "region-a.example.com",
			extra: []string{"api.example.com", "API.example.com", "region-a.example.com", "api.example.com."},
			want:  "address=/example.com/10.0.3.5\nserver=/region-a.example.com/#\nserver=/api.example.com/#",
		},
		{
			name: "host equal to base is ignored (would cancel the wildcard)",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "",
			extra: []string{"example.com", "Example.COM."},
			want:  "address=/example.com/10.0.3.5",
		},
		{
			name: "blank entries are ignored",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "",
			extra: []string{"", "  ", "api.example.com"},
			want:  "address=/example.com/10.0.3.5\nserver=/api.example.com/#",
		},
		{
			// Defence in depth: the flag is validated at boot, but a value
			// that could inject a dnsmasq directive must never reach the
			// generated file.
			name: "entries that could inject a directive are dropped",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "",
			extra: []string{"a.example.com\nserver=/evil.example/1.2.3.4", "b.example.com/#", "c d.example.com", "ok.example.com"},
			want:  "address=/example.com/10.0.3.5\nserver=/ok.example.com/#",
		},
		{
			name: "no passthrough hosts leaves the value byte-identical",
			base: "example.com", caddyIP: "10.0.3.5", ssh: "region-a.example.com",
			extra: nil,
			want:  "address=/example.com/10.0.3.5\nserver=/region-a.example.com/#",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bridgeDNSRaw(tc.base, tc.caddyIP, tc.ssh, tc.extra...); got != tc.want {
				t.Errorf("bridgeDNSRaw(%q,%q,%q,%q)\n got: %q\nwant: %q", tc.base, tc.caddyIP, tc.ssh, tc.extra, got, tc.want)
			}
		})
	}
}

// #2188: --dns-passthrough-host is validated at boot so a typo fails visibly
// instead of silently writing a broken dnsmasq record.
func TestValidateDNSPassthroughHosts(t *testing.T) {
	cases := []struct {
		name    string
		hosts   []string
		wantErr bool
	}{
		{"none", nil, false},
		{"plain names", []string{"api.example.com", "cp.example.com"}, false},
		{"mixed case and trailing dot", []string{"API.Example.com."}, false},
		{"underscore label", []string{"_dmarc.example.com"}, false},
		{"empty entry", []string{"api.example.com", ""}, true},
		{"whitespace only", []string{"   "}, true},
		{"embedded space", []string{"a b.example.com"}, true},
		{"newline", []string{"a.example.com\nserver=/x/1.2.3.4"}, true},
		{"slash", []string{"a.example.com/#"}, true},
		{"url instead of host", []string{"https://api.example.com"}, true},
		{"wildcard", []string{"*.example.com"}, true},
		{"empty label", []string{"a..example.com"}, true},
		{"label over 63 bytes", []string{strings.Repeat("a", 64) + ".example.com"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDNSPassthroughHosts(tc.hosts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateDNSPassthroughHosts(%q) err = %v; wantErr %v", tc.hosts, err, tc.wantErr)
			}
		})
	}
}
