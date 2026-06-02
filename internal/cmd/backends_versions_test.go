package cmd

import "testing"

func TestBackendVersionStatus(t *testing.T) {
	cases := []struct {
		name    string
		current string
		latest  string
		want    string
	}{
		{"behind", "0.21.0", "v0.21.2", "behind"},
		{"behind across minor", "v0.20.0", "v0.21.0", "behind"},
		{"current equal", "v0.21.2", "v0.21.2", "current"},
		{"current equal sans-v", "0.21.2", "v0.21.2", "current"},
		{"ahead counts as current", "v0.22.0", "v0.21.2", "current"},
		{"dev build", "dev", "v0.21.2", "dev"},
		{"missing current", "", "v0.21.2", "unknown"},
		{"missing latest", "v0.21.0", "", "unknown"},
		{"unparseable current is not behind", "garbage", "v0.21.2", "current"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := backendVersionStatus(tc.current, tc.latest); got != tc.want {
				t.Errorf("backendVersionStatus(%q, %q) = %q, want %q", tc.current, tc.latest, got, tc.want)
			}
		})
	}
}
