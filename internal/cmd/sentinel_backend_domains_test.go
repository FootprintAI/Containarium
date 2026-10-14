//go:build !windows && !containarium_client

package cmd

import "testing"

func TestInFleetCertScopeFromFlags(t *testing.T) {
	scope, err := inFleetCertScopeFromFlags("prod.example.com", []string{"api.example.com"}, []string{"example.com"})
	if err != nil {
		t.Fatalf("valid flags: %v", err)
	}
	if scope.Hostname != "prod.example.com" || len(scope.Aliases) != 1 || len(scope.BaseDomains) != 1 {
		t.Fatalf("scope = %+v, want the flag values", scope)
	}

	empty, err := inFleetCertScopeFromFlags("", nil, nil)
	if err != nil {
		t.Fatalf("no flags: %v", err)
	}
	if !empty.Empty() {
		t.Fatalf("no flags gave scope %+v, want empty", empty)
	}

	bad := []struct {
		hostname    string
		aliases     []string
		baseDomains []string
	}{
		{hostname: "*.example.com"},
		{aliases: []string{"api..example.com"}},
		{baseDomains: []string{"com"}},
		{baseDomains: []string{"Example.com"}},
	}
	for _, b := range bad {
		if _, err := inFleetCertScopeFromFlags(b.hostname, b.aliases, b.baseDomains); err == nil {
			t.Errorf("inFleetCertScopeFromFlags(%q, %v, %v) = nil error, want one", b.hostname, b.aliases, b.baseDomains)
		}
	}
}
