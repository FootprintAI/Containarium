//go:build !windows && !containarium_client

package cmd

import (
	"strings"
	"testing"
)

func TestBYOCBaseDomainWarning(t *testing.T) {
	cases := []struct {
		name      string
		byoc      bool
		value     string
		src       baseDomainSource
		wantEmpty bool
		wantHas   []string
	}{
		{name: "unmarked host never warns", byoc: false, value: "cp.example.com", src: baseDomainFromDB, wantEmpty: true},
		{name: "byoc with the built-in default", byoc: true, value: "example.org", src: baseDomainFromDefault, wantEmpty: true},
		{name: "byoc with an empty stored value", byoc: true, value: "", src: baseDomainFromDB, wantEmpty: true},
		{
			name: "byoc with a stored value names it, its source and the runbook",
			byoc: true, value: "cp.example.com", src: baseDomainFromDB,
			wantHas: []string{`"cp.example.com"`, "from daemon_config", "NOT served", "no certificate", "#2262",
				"docs/BYOC-BACKEND-BRINGUP.md", "ingress route"},
		},
		{
			name: "byoc with a passed flag says to drop it",
			byoc: true, value: "cp.example.com", src: baseDomainFromFlag,
			wantHas: []string{`"cp.example.com"`, "from flag", "drop --base-domain"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := byocBaseDomainWarning(tc.byoc, tc.value, tc.src)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("want no warning, got %q", got)
				}
				return
			}
			for _, s := range tc.wantHas {
				if !strings.Contains(got, s) {
					t.Errorf("warning missing %q:\n%s", s, got)
				}
			}
		})
	}
}
