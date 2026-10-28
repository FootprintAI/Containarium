package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 1.7b — RequireScope semantics.

func TestRequireScope_AllowsWhenNoSubject_ReturnsUnauthenticated(t *testing.T) {
	err := RequireScope(context.Background(), ScopeSecretsWrite)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v want Unauthenticated", err)
	}
}

func TestRequireScope_AllowsWhenScopesAbsent(t *testing.T) {
	// Pre-1.7 token (no scopes claim) — must keep working
	// for backwards compat. The role check is still the
	// authoritative gate for these tokens.
	ctx := ContextWithTestSubject(context.Background(), "alice", "user")
	if err := RequireScope(ctx, ScopeSecretsWrite); err != nil {
		t.Fatalf("absent scopes claim should pass (backwards compat); got %v", err)
	}
}

func TestRequireScope_RejectsWhenScopeMissing(t *testing.T) {
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, []string{ScopeContainersRead},
	)
	err := RequireScope(ctx, ScopeSecretsWrite)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("missing scope: got %v want PermissionDenied", err)
	}
}

func TestRequireScope_AllowsWhenScopeGranted(t *testing.T) {
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, []string{ScopeContainersRead, ScopeSecretsWrite},
	)
	if err := RequireScope(ctx, ScopeSecretsWrite); err != nil {
		t.Fatalf("granted scope: got %v", err)
	}
}

func TestRequireScope_WildcardCoversAny(t *testing.T) {
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, []string{ScopeWildcard},
	)
	if err := RequireScope(ctx, ScopeSecretsWrite); err != nil {
		t.Fatalf("wildcard should cover any scope; got %v", err)
	}
	if err := RequireScope(ctx, "future:scope"); err != nil {
		t.Fatalf("wildcard should cover unknown scopes; got %v", err)
	}
}

// Empty scopes is not a producible state in production —
// the issuance path omits the claim entirely when no
// `--scopes` are passed (CLI StringSlice + len>0 guard in
// GenerateToken + the wire-marshal filter in middleware).
// HasScope's contract says nil grants are unrestricted; we
// therefore don't try to assert an "explicit empty deny"
// — that policy doesn't exist on the wire.

func TestRequireScope_NotIntertwinedWithRole(t *testing.T) {
	// Phase 1.7b — scopes are independent of roles. An admin
	// with no scope-grant for the resource is still denied.
	// (Roles answer "who"; scopes answer "what was granted".)
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{RoleAdmin}, []string{ScopeContainersRead},
	)
	err := RequireScope(ctx, ScopeSecretsWrite)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin without scope: got %v want PermissionDenied", err)
	}
}

// #1679 — strict mode rejects unscoped tokens instead of fail-open.

func TestRequireScope_StrictMode_RejectsUnscopedToken(t *testing.T) {
	SetStrictScopes(true)
	defer SetStrictScopes(false)

	ctx := ContextWithTestSubject(context.Background(), "alice", "user")
	err := RequireScope(ctx, ScopeSecretsWrite)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("strict mode, unscoped token: got %v want PermissionDenied", err)
	}
	if !IsStrictScopesDenial(err) {
		t.Fatalf("strict mode, unscoped token: err %v not recognized as a strict-scopes denial", err)
	}
}

func TestRequireScope_StrictMode_StillAllowsScopedToken(t *testing.T) {
	SetStrictScopes(true)
	defer SetStrictScopes(false)

	ctx := ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, []string{ScopeSecretsWrite},
	)
	if err := RequireScope(ctx, ScopeSecretsWrite); err != nil {
		t.Fatalf("strict mode, scoped token with the required scope: got %v want nil", err)
	}
}

func TestRequireScope_StrictMode_InsufficientScopeIsDistinguishableFromUnscoped(t *testing.T) {
	SetStrictScopes(true)
	defer SetStrictScopes(false)

	ctx := ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, []string{ScopeContainersRead},
	)
	err := RequireScope(ctx, ScopeSecretsWrite)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("strict mode, insufficient scope: got %v want PermissionDenied", err)
	}
	if IsStrictScopesDenial(err) {
		t.Fatalf("strict mode, insufficient (but present) scope: err %v must NOT be classified as a strict-scopes denial — an operator needs to tell these apart", err)
	}
}

func TestRequireScope_PermissiveMode_UnaffectedByStrictModeOff(t *testing.T) {
	// Default posture (AC: "default remains permissive") — this is
	// TestRequireScope_AllowsWhenScopesAbsent's exact scenario, repeated
	// here with SetStrictScopes(false) made explicit so the strict-mode
	// tests above can't leave global state that silently breaks it.
	SetStrictScopes(false)

	ctx := ContextWithTestSubject(context.Background(), "alice", "user")
	if err := RequireScope(ctx, ScopeSecretsWrite); err != nil {
		t.Fatalf("permissive mode, unscoped token: got %v want nil", err)
	}
}

func TestRequireScope_RecordsUnscopedCallRegardlessOfMode(t *testing.T) {
	// The measurement AC ("report how many recent calls used unscoped
	// tokens before flipping the switch") only works if the counter
	// increments in permissive mode too — that's the whole point.
	SetStrictScopes(false)
	ResetUnscopedTokenCallsForTest()

	ctx := ContextWithTestSubject(context.Background(), "alice", "user")
	_ = RequireScope(ctx, ScopeSecretsWrite)

	if got := UnscopedTokenCalls().Count; got != 1 {
		t.Fatalf("UnscopedTokenCalls().Count = %d, want 1 after one unscoped call in permissive mode", got)
	}

	// A scoped call must NOT count as unscoped.
	scopedCtx := ContextWithTestSubjectScopes(context.Background(),
		"bob", []string{"user"}, []string{ScopeSecretsWrite},
	)
	_ = RequireScope(scopedCtx, ScopeSecretsWrite)
	if got := UnscopedTokenCalls().Count; got != 1 {
		t.Fatalf("UnscopedTokenCalls().Count = %d after a scoped call, want unchanged 1", got)
	}
}

func TestRequireAnyScope(t *testing.T) {
	verifyOrWrite := []string{ScopeBackupsVerify, ScopeBackupsWrite}
	for _, tc := range []struct {
		name     string
		scopes   []string // nil = a token with no scopes claim
		strict   bool
		accepted []string
		want     codes.Code
	}{
		{"narrow scope", []string{ScopeBackupsVerify}, false, verifyOrWrite, codes.OK},
		{"legacy scope", []string{ScopeBackupsWrite}, false, verifyOrWrite, codes.OK},
		{"wildcard", []string{ScopeWildcard}, false, verifyOrWrite, codes.OK},
		{"neither", []string{ScopeBackupsRead}, false, verifyOrWrite, codes.PermissionDenied},
		{"empty", []string{}, false, verifyOrWrite, codes.PermissionDenied},
		// No scopes claim: allowed for backwards compat, refused under
		// strict scopes, the same as RequireScope.
		{"no scopes claim", nil, false, verifyOrWrite, codes.OK},
		{"no scopes claim, strict", nil, true, verifyOrWrite, codes.PermissionDenied},
		// A misconfigured call site fails closed. HasScope(_, "") is true,
		// so an empty accepted entry would otherwise admit every caller.
		{"no accepted scopes", []string{ScopeBackupsWrite}, false, nil, codes.Internal},
		{"empty accepted scope", []string{ScopeBackupsRead}, false, []string{ScopeBackupsVerify, ""}, codes.Internal},
		{"empty accepted scope only", []string{ScopeBackupsRead}, false, []string{""}, codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetStrictScopes(tc.strict)
			defer SetStrictScopes(false)
			ctx := ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, tc.scopes)
			_, err := RequireAnyScope(ctx, tc.accepted...)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("code = %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}

// RequireAnyScope reports which accepted scope admitted the caller: the first
// entry, in the caller's order, that the token satisfies. A wildcard or
// unscoped token satisfies the first entry, so a caller that lists the
// preferred scope first sees the legacy one only for a token that holds it
// and not the preferred one (#3186).
func TestRequireAnyScope_ReportsMatchedScope(t *testing.T) {
	SetStrictScopes(false)
	for _, tc := range []struct {
		name   string
		scopes []string // nil = a token with no scopes claim
		want   string
	}{
		{"narrow scope", []string{ScopeBackupsRead, ScopeBackupsVerify}, ScopeBackupsVerify},
		{"legacy scope only", []string{ScopeBackupsRead, ScopeBackupsWrite}, ScopeBackupsWrite},
		{"both scopes", []string{ScopeBackupsWrite, ScopeBackupsVerify}, ScopeBackupsVerify},
		{"wildcard", []string{ScopeWildcard}, ScopeBackupsVerify},
		{"no scopes claim", nil, ScopeBackupsVerify},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, tc.scopes)
			got, err := RequireAnyScope(ctx, ScopeBackupsVerify, ScopeBackupsWrite)
			if err != nil {
				t.Fatalf("unexpected denial: %v", err)
			}
			if got != tc.want {
				t.Fatalf("matched scope = %q, want %q", got, tc.want)
			}
		})
	}
	denied := ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, []string{ScopeBackupsRead})
	if got, err := RequireAnyScope(denied, ScopeBackupsVerify, ScopeBackupsWrite); err == nil || got != "" {
		t.Fatalf("denied call: matched = %q, err = %v; want \"\" and an error", got, err)
	}
}
