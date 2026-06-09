package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #621 — RequireRoleOrScope passes if the caller holds the role OR
// explicitly holds the scope. It gates read paths an admin reaches by
// role and a least-privilege token reaches by an explicit read scope.
// Unlike RequireScope, a nil/absent scopes claim must NOT unlock the read
// (that's HasExplicitScope, not HasScope).

func TestRequireRoleOrScope_NoSubject(t *testing.T) {
	err := RequireRoleOrScope(context.Background(), RoleAdmin, ScopeTokensRead)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v (%v)", status.Code(err), err)
	}
}

func TestRequireRoleOrScope_AdminByRole(t *testing.T) {
	// Admin role, an unrelated scope — the role alone passes.
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{RoleAdmin}, []string{ScopeContainersRead})
	if err := RequireRoleOrScope(ctx, RoleAdmin, ScopeTokensRead); err != nil {
		t.Fatalf("admin by role should pass: %v", err)
	}
}

func TestRequireRoleOrScope_NonAdminWithScope(t *testing.T) {
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"collector", []string{"user"}, []string{ScopeTokensRead})
	if err := RequireRoleOrScope(ctx, RoleAdmin, ScopeTokensRead); err != nil {
		t.Fatalf("non-admin with explicit scope should pass: %v", err)
	}
}

func TestRequireRoleOrScope_NonAdminMissingScope(t *testing.T) {
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, []string{ScopeContainersRead})
	err := RequireRoleOrScope(ctx, RoleAdmin, ScopeTokensRead)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v (%v)", status.Code(err), err)
	}
}

// The key difference from RequireScope: an absent scopes claim is NOT a
// pass. A subject with no scopes claim and not holding the role is denied —
// a missing claim must not silently unlock an otherwise admin-only read.
func TestRequireRoleOrScope_AbsentScopesClaimIsDenied(t *testing.T) {
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, nil)
	err := RequireRoleOrScope(ctx, RoleAdmin, ScopeTokensRead)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("absent scopes claim must be denied; got %v (%v)", status.Code(err), err)
	}
}

func TestRequireRoleOrScope_WildcardScopePasses(t *testing.T) {
	ctx := ContextWithTestSubjectScopes(context.Background(),
		"svc", []string{"user"}, []string{ScopeWildcard})
	if err := RequireRoleOrScope(ctx, RoleAdmin, ScopeTokensRead); err != nil {
		t.Fatalf("wildcard scope should pass: %v", err)
	}
}
