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

func TestParseScopes(t *testing.T) {
	cases := map[string][]string{
		"":                              nil,
		"   ":                           nil,
		",,,":                           nil,
		"containers:read":               {"containers:read"},
		"containers:read,secrets:read":  {"containers:read", "secrets:read"},
		" containers:read , secrets:read,, ": {"containers:read", "secrets:read"},
		"*":                             {"*"},
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
