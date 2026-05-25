package server

import "testing"

func TestResolveFullDomain(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		baseDomain string
		want       string
	}{
		// Simple subdomain — should append base domain
		{
			name:       "simple subdomain",
			domain:     "myapp",
			baseDomain: "<cluster>.example.com",
			want:       "myapp.<cluster>.example.com",
		},
		// Already has base domain suffix — use as-is
		{
			name:       "already has base domain suffix",
			domain:     "myapp.<cluster>.example.com",
			baseDomain: "<cluster>.example.com",
			want:       "myapp.<cluster>.example.com",
		},
		// Domain equals base domain exactly
		{
			name:       "domain equals base domain",
			domain:     "<cluster>.example.com",
			baseDomain: "<cluster>.example.com",
			want:       "<cluster>.example.com",
		},
		// Independent FQDN — must NOT append base domain (the bug scenario)
		{
			name:       "independent FQDN not doubled",
			domain:     "tenant-a.dev.example.com",
			baseDomain: "<cluster>.example.com",
			want:       "tenant-a.dev.example.com",
		},
		// Another independent FQDN
		{
			name:       "another independent FQDN",
			domain:     "api.example.com",
			baseDomain: "<cluster>.example.com",
			want:       "api.example.com",
		},
		// No base domain configured — use as-is
		{
			name:       "no base domain simple subdomain",
			domain:     "myapp",
			baseDomain: "",
			want:       "myapp",
		},
		{
			name:       "no base domain FQDN",
			domain:     "myapp.example.com",
			baseDomain: "",
			want:       "myapp.example.com",
		},
		// Multi-level subdomain of base domain — use as-is
		{
			name:       "multi-level subdomain of base domain",
			domain:     "a.b.<cluster>.example.com",
			baseDomain: "<cluster>.example.com",
			want:       "a.b.<cluster>.example.com",
		},
		// Partial overlap but NOT a suffix — must not double
		{
			name:       "partial overlap not suffix",
			domain:     "tenant-b.example.com",
			baseDomain: "<cluster>.example.com",
			want:       "tenant-b.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveFullDomain(tt.domain, tt.baseDomain)
			if got != tt.want {
				t.Errorf("resolveFullDomain(%q, %q) = %q, want %q", tt.domain, tt.baseDomain, got, tt.want)
			}
		})
	}
}
