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
