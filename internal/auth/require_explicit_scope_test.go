package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #2415 — RequireExplicitScope: the gate for the audit-ingest write path.
// Unlike RequireScope it never falls through to the "no scopes claim =
// unrestricted" backwards-compat path, strict mode or not.

func TestScopeAuditIngest_IsKnown(t *testing.T) {
	if !IsKnownScope(ScopeAuditIngest) {
		t.Fatalf("%q must be registered in AllScopes", ScopeAuditIngest)
	}
	if ScopeAuditIngest != "audit:ingest" {
		t.Fatalf("scope string = %q, want audit:ingest", ScopeAuditIngest)
	}
}

func TestRequireExplicitScope(t *testing.T) {
	SetStrictScopes(false)
	t.Cleanup(func() { SetStrictScopes(false) })

	tests := []struct {
		name   string
		ctx    context.Context
		strict bool
		want   codes.Code
	}{
		{
			name: "no subject",
			ctx:  context.Background(),
			want: codes.Unauthenticated,
		},
		{
			name: "scope granted",
			ctx:  ContextWithTestSubjectScopes(context.Background(), "shipper", []string{"service"}, []string{ScopeAuditIngest}),
			want: codes.OK,
		},
		{
			name: "wildcard granted",
			ctx:  ContextWithTestSubjectScopes(context.Background(), "admin", []string{"admin"}, []string{ScopeWildcard}),
			want: codes.OK,
		},
		{
			name: "other scopes only",
			ctx:  ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, []string{ScopeContainersRead, ScopeAuditRead}),
			want: codes.PermissionDenied,
		},
		{
			// The case that distinguishes this helper from RequireScope: a
			// pre-scope token with no scopes claim is denied even though
			// strict mode is off.
			name: "no scopes claim, strict off",
			ctx:  ContextWithTestSubject(context.Background(), "admin", "admin"),
			want: codes.PermissionDenied,
		},
		{
			name:   "no scopes claim, strict on",
			ctx:    ContextWithTestSubject(context.Background(), "admin", "admin"),
			strict: true,
			want:   codes.PermissionDenied,
		},
		{
			name: "empty scopes claim",
			ctx:  ContextWithTestSubjectScopes(context.Background(), "alice", []string{"user"}, []string{}),
			want: codes.PermissionDenied,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SetStrictScopes(tc.strict)
			defer SetStrictScopes(false)
			err := RequireExplicitScope(tc.ctx, ScopeAuditIngest)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("RequireExplicitScope = %v (code %s), want code %s", err, got, tc.want)
			}
		})
	}
}
