package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRequireRoleOrScope_Vs_Narrowed(t *testing.T) {
	const scope = "anon:admin"
	cases := []struct {
		name         string
		roles        []string
		scopes       []string // nil = no scopes claim
		plain, tight codes.Code
	}{
		{"unscoped admin", []string{RoleAdmin}, nil, codes.OK, codes.OK},
		{"unscoped non-admin", []string{"user"}, nil, codes.PermissionDenied, codes.PermissionDenied},
		{"scoped admin with the scope", []string{RoleAdmin}, []string{scope}, codes.OK, codes.OK},
		{"scoped admin, wildcard", []string{RoleAdmin}, []string{ScopeWildcard}, codes.OK, codes.OK},
		// The one difference: read paths keep admin-by-role (#621); mutating paths narrow.
		{"scoped admin WITHOUT the scope", []string{RoleAdmin}, []string{ScopeContainersRead}, codes.OK, codes.PermissionDenied},
		{"scoped admin, empty scopes claim", []string{RoleAdmin}, []string{}, codes.OK, codes.PermissionDenied},
		{"scoped non-admin with the scope", []string{"user"}, []string{scope}, codes.OK, codes.OK},
		{"scoped non-admin without it", []string{"user"}, []string{ScopeContainersRead}, codes.PermissionDenied, codes.PermissionDenied},
	}
	for _, c := range cases {
		ctx := ContextWithTestSubjectScopes(context.Background(), "u", c.roles, c.scopes)
		if got := status.Code(RequireRoleOrScope(ctx, RoleAdmin, scope)); got != c.plain {
			t.Errorf("RequireRoleOrScope %s: got %v want %v", c.name, got, c.plain)
		}
		if got := status.Code(RequireRoleOrScopeNarrowed(ctx, RoleAdmin, scope)); got != c.tight {
			t.Errorf("RequireRoleOrScopeNarrowed %s: got %v want %v", c.name, got, c.tight)
		}
	}
	if got := status.Code(RequireRoleOrScopeNarrowed(context.Background(), RoleAdmin, scope)); got != codes.Unauthenticated {
		t.Errorf("no subject: got %v want Unauthenticated", got)
	}
}
