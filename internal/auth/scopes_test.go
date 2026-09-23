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

// TestExcludeScopes covers ExcludeScopes' own contract, independent of
// its mintedAgentTokenScopes call site (agent_server_test.go covers the
// integration).
func TestExcludeScopes(t *testing.T) {
	got := ExcludeScopes([]string{ScopeContainersRead, ScopeTrackerAdmin, ScopeSecretsWrite}, ScopeTrackerAdmin)
	want := []string{ScopeContainersRead, ScopeSecretsWrite}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ExcludeScopes = %v, want %v", got, want)
	}
}

func TestExcludeScopes_NilStaysNil(t *testing.T) {
	// A nil scope set means "unrestricted" (HasScope's policy); excluding
	// from "no restriction" would silently narrow an unrestricted legacy
	// token instead of leaving the "no restriction" decision to whatever
	// upstream check already made it.
	if got := ExcludeScopes(nil, ScopeTrackerAdmin); got != nil {
		t.Fatalf("ExcludeScopes(nil, ...) = %v, want nil", got)
	}
}

func TestExcludeScopes_ExcludingEverythingLeavesEmptyNotNil(t *testing.T) {
	// An empty (non-nil) result means "zero grants" — HasScope must NOT
	// read this the same as the nil "unrestricted" case.
	got := ExcludeScopes([]string{ScopeTrackerAdmin}, ScopeTrackerAdmin)
	if got == nil {
		t.Fatal("ExcludeScopes result is nil, want a non-nil empty slice (zero grants, not unrestricted)")
	}
	if len(got) != 0 {
		t.Fatalf("ExcludeScopes = %v, want empty", got)
	}
	if HasScope(got, ScopeContainersRead) {
		t.Error("HasScope(empty, ...) = true, want false — empty must mean zero grants, not unrestricted")
	}
}

// TestIsKnownScope_SandboxScopes is the regression test for #1926:
// ScopeSandboxesRead/ScopeSandboxesWrite were defined in the const block
// (added for #1488) but never added to AllScopes, so IsKnownScope silently
// rejected a skill manifest or token-mint request declaring
// sandboxes:read/sandboxes:write.
func TestIsKnownScope_SandboxScopes(t *testing.T) {
	for _, s := range []string{ScopeSandboxesRead, ScopeSandboxesWrite} {
		if !IsKnownScope(s) {
			t.Errorf("IsKnownScope(%q) = false, want true (missing from AllScopes?)", s)
		}
	}
}

// TestIsKnownScope_TrackerScopes guards against the class of bug filed as
// #1926 (ScopeSandboxesRead/Write defined but missing from AllScopes,
// silently rejected by IsKnownScope) recurring for the new tracker scopes.
func TestIsKnownScope_TrackerScopes(t *testing.T) {
	for _, s := range []string{ScopeTrackerRead, ScopeTrackerWrite, ScopeTrackerAdmin} {
		if !IsKnownScope(s) {
			t.Errorf("IsKnownScope(%q) = false, want true (missing from AllScopes?)", s)
		}
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
