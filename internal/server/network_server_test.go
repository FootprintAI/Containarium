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
			baseDomain: "containarium.kafeido.app",
			want:       "myapp.containarium.kafeido.app",
		},
		// Already has base domain suffix — use as-is
		{
			name:       "already has base domain suffix",
			domain:     "myapp.containarium.kafeido.app",
			baseDomain: "containarium.kafeido.app",
			want:       "myapp.containarium.kafeido.app",
		},
		// Domain equals base domain exactly
		{
			name:       "domain equals base domain",
			domain:     "containarium.kafeido.app",
			baseDomain: "containarium.kafeido.app",
			want:       "containarium.kafeido.app",
		},
		// Independent FQDN — must NOT append base domain (the bug scenario)
		{
			name:       "independent FQDN not doubled",
			domain:     "facelabor.dev.kafeido.app",
			baseDomain: "containarium.kafeido.app",
			want:       "facelabor.dev.kafeido.app",
		},
		// Another independent FQDN
		{
			name:       "another independent FQDN",
			domain:     "api.example.com",
			baseDomain: "containarium.kafeido.app",
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
			domain:     "a.b.containarium.kafeido.app",
			baseDomain: "containarium.kafeido.app",
			want:       "a.b.containarium.kafeido.app",
		},
		// Partial overlap but NOT a suffix — must not double
		{
			name:       "partial overlap not suffix",
			domain:     "pes.kafeido.app",
			baseDomain: "containarium.kafeido.app",
			want:       "pes.kafeido.app",
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
