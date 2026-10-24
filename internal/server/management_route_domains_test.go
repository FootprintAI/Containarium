//go:build !containarium_client

package server

import (
	"testing"
)

// TestManagementRouteDomains covers #213: the daemon ensures one management
// route per PublicBaseDomains entry (so every parent domain's apex is Caddied
// + served), falling back to BaseDomain for single-domain deployments.
func TestManagementRouteDomains(t *testing.T) {
	tests := []struct {
		name string
		cfg  *DualServerConfig
		want []string
	}{
		{
			name: "single base domain (unchanged behavior)",
			cfg:  &DualServerConfig{BaseDomain: "example.org"},
			want: []string{"example.org"},
		},
		{
			name: "multiple public base domains take precedence",
			cfg: &DualServerConfig{
				BaseDomain:        "example.org",
				PublicBaseDomains: []string{"lab.example.com", "demo.example.org"},
			},
			want: []string{"lab.example.com", "demo.example.org"},
		},
		{
			name: "public base domains without a base domain",
			cfg:  &DualServerConfig{PublicBaseDomains: []string{"a.com"}},
			want: []string{"a.com"},
		},
		{
			name: "nothing configured → no routes",
			cfg:  &DualServerConfig{},
			want: nil,
		},
		{
			name: "nil config → no routes",
			cfg:  nil,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := managementRouteDomains(tt.cfg)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("domain[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
