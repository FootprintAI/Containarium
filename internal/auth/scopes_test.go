package auth

import (
	"testing"
)

func TestHasScope_NilGrantedIsUnrestricted(t *testing.T) {
	// Pre-1.7 token (no scopes claim). HasScope must let
	// it through so existing deployments don't break.
	if !HasScope(nil, ScopeContainersWrite) {
		t.Fatal("nil granted should be treated as unrestricted")
	}
	if !HasScope(nil, "anything") {
		t.Fatal("nil granted should be treated as unrestricted for any scope")
	}
}

func TestHasScope_EmptyRequiredAlwaysAllowed(t *testing.T) {
	// Some MCP tools are pure introspection — no scope
	// required. Even an empty-scopes token can call them.
	if !HasScope([]string{}, "") {
		t.Fatal("empty required scope should always pass")
	}
	if !HasScope(nil, "") {
		t.Fatal("empty required scope should always pass (nil grants)")
	}
}

func TestHasScope_WildcardCoversAll(t *testing.T) {
	if !HasScope([]string{ScopeWildcard}, ScopeContainersWrite) {
		t.Fatal("'*' should cover containers:write")
	}
	if !HasScope([]string{"some-other", ScopeWildcard}, ScopeSecretsRead) {
		t.Fatal("'*' anywhere in granted should cover any required")
	}
}

func TestHasScope_ExactMatch(t *testing.T) {
	granted := []string{ScopeContainersRead, ScopeSecretsRead}
	if !HasScope(granted, ScopeContainersRead) {
		t.Fatal("exact match should pass")
	}
	if HasScope(granted, ScopeContainersWrite) {
		t.Fatal("missing scope should be rejected")
	}
	if HasScope(granted, ScopeSecretsWrite) {
		t.Fatal("missing scope should be rejected")
	}
}

func TestHasScope_EmptyGrantsExplicitDeny(t *testing.T) {
	// A non-nil but empty granted list means "explicitly
	// no scopes" — only empty-required tools pass.
	if HasScope([]string{}, ScopeContainersRead) {
		t.Fatal("explicit empty grant should deny scoped tools")
	}
}

func TestHasScope_TrimsWhitespace(t *testing.T) {
	// JWT shouldn't have whitespace in arrays, but tolerate
	// it for hand-edited tokens / unusual issuers.
	if !HasScope([]string{" containers:read "}, ScopeContainersRead) {
		t.Fatal("whitespace in granted scope should be trimmed")
	}
}

func TestIntersectScopes(t *testing.T) {
	cases := []struct {
		name     string
		caller   []string
		manifest []string
		want     []string
	}{
		{
			name:     "nil caller is unrestricted, manifest stays the ceiling",
			caller:   nil,
			manifest: []string{ScopeContainersRead, ScopeSecretsRead},
			want:     []string{ScopeContainersRead, ScopeSecretsRead},
		},
		{
			name:     "wildcard caller intersects down to the manifest",
			caller:   []string{ScopeWildcard},
			manifest: []string{ScopeContainersRead, ScopeSecretsRead},
			want:     []string{ScopeContainersRead, ScopeSecretsRead},
		},
		{
			name:     "wildcard manifest intersects down to the caller",
			caller:   []string{ScopeContainersRead},
			manifest: []string{ScopeWildcard},
			want:     []string{ScopeContainersRead},
		},
		{
			name:     "empty caller grants nothing regardless of manifest",
			caller:   []string{},
			manifest: []string{ScopeContainersRead, ScopeSecretsRead},
			want:     []string{},
		},
		{
			name:     "empty manifest grants nothing regardless of caller",
			caller:   []string{ScopeWildcard},
			manifest: []string{},
			want:     []string{},
		},
		{
			name:     "disjoint sets intersect to nothing",
			caller:   []string{ScopeContainersRead},
			manifest: []string{ScopeSecretsRead},
			want:     []string{},
		},
		{
			name:     "caller with only agents:run gets no resource scopes",
			caller:   []string{ScopeAgentsRun},
			manifest: []string{ScopeContainersRead},
			want:     []string{},
		},
		{
			name:     "strict subset keeps only the shared scopes",
			caller:   []string{ScopeContainersRead, ScopeSecretsRead, ScopeRoutesWrite},
			manifest: []string{ScopeContainersRead, ScopeSecretsRead},
			want:     []string{ScopeContainersRead, ScopeSecretsRead},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IntersectScopes(tc.caller, tc.manifest)
			if len(got) != len(tc.want) {
				t.Fatalf("IntersectScopes(%v, %v) = %v, want %v", tc.caller, tc.manifest, got, tc.want)
			}
			gotSet := map[string]bool{}
			for _, s := range got {
				gotSet[s] = true
			}
			for _, s := range tc.want {
				if !gotSet[s] {
					t.Fatalf("IntersectScopes(%v, %v) = %v, want %v (missing %q)", tc.caller, tc.manifest, got, tc.want, s)
				}
			}
		})
	}
}

func TestIntersectScopes_ManifestScopeCallerLacksIsNeverGranted(t *testing.T) {
	// Regression for #1676: a manifest declaring a scope the caller doesn't
	// hold must never leak that scope into the minted token.
	caller := []string{ScopeContainersRead}
	manifest := []string{ScopeContainersRead, ScopeSecretsWrite}
	got := IntersectScopes(caller, manifest)
	for _, s := range got {
		if s == ScopeSecretsWrite {
			t.Fatalf("IntersectScopes(%v, %v) = %v; caller never held %q", caller, manifest, got, ScopeSecretsWrite)
		}
	}
	if len(got) != 1 || got[0] != ScopeContainersRead {
		t.Fatalf("IntersectScopes(%v, %v) = %v, want [%q]", caller, manifest, got, ScopeContainersRead)
	}
}

func TestParseScopes(t *testing.T) {
	cases := map[string][]string{
		"":                                   nil,
		"   ":                                nil,
		",,,":                                nil,
		"containers:read":                    {"containers:read"},
		"containers:read,secrets:read":       {"containers:read", "secrets:read"},
		" containers:read , secrets:read,, ": {"containers:read", "secrets:read"},
		"*":                                  {"*"},
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got := ParseScopes(in)
			if len(got) != len(want) {
				t.Fatalf("ParseScopes(%q) = %v, want %v", in, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("ParseScopes(%q)[%d] = %q, want %q", in, i, got[i], want[i])
				}
			}
		})
	}
}
