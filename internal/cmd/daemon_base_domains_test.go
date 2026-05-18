package cmd

import (
	"reflect"
	"testing"
)

// TestResolvePublicBaseDomains pins the precedence: explicit
// --public-base-domain values always win; otherwise the daemon's
// --base-domain becomes a single-entry default; empty in both
// yields nil (suffix matching disabled).
func TestResolvePublicBaseDomains(t *testing.T) {
	cases := []struct {
		name   string
		public []string
		base   string
		want   []string
	}{
		{
			name:   "explicit single value wins",
			public: []string{"lab.example.com"},
			base:   "example.com",
			want:   []string{"lab.example.com"},
		},
		{
			name:   "explicit multi-value wins (lab-hosts-demo pattern)",
			public: []string{"lab.example.com", "demo.example.org"},
			base:   "example.com",
			want:   []string{"lab.example.com", "demo.example.org"},
		},
		{
			name:   "no explicit, base provides single fallback",
			public: nil,
			base:   "example.org",
			want:   []string{"example.org"},
		},
		{
			name:   "both empty → nil",
			public: nil,
			base:   "",
			want:   nil,
		},
		{
			name:   "explicit empty slice still falls back",
			public: []string{},
			base:   "example.org",
			want:   []string{"example.org"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolvePublicBaseDomains(tc.public, tc.base)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("resolvePublicBaseDomains(%v, %q) = %v, want %v",
					tc.public, tc.base, got, tc.want)
			}
		})
	}
}
