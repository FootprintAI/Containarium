//go:build !containarium_client

package cmd

import (
	"reflect"
	"testing"
)

// TestResolvePublicBaseDomains pins the precedence: explicit
// --public-base-domain values always win; otherwise the daemon's
// --base-domain becomes a single-entry default; empty in both
// yields nil (suffix matching disabled). A BYOC backend advertises
// nothing at all (#2262).
func TestResolvePublicBaseDomains(t *testing.T) {
	cases := []struct {
		name   string
		public []string
		base   string
		byoc   bool
		want   []string
	}{
		{
			name: "byoc: stored base domain is not advertised",
			base: "cp.example.com",
			byoc: true,
			want: nil,
		},
		{
			name:   "byoc: explicit values are not advertised either",
			public: []string{"lab.example.com"},
			base:   "cp.example.com",
			byoc:   true,
			want:   nil,
		},
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
			got := resolvePublicBaseDomains(tc.public, tc.base, tc.byoc)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("resolvePublicBaseDomains(%v, %q, %v) = %v, want %v",
					tc.public, tc.base, tc.byoc, got, tc.want)
			}
		})
	}
}
