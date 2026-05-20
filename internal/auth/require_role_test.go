package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Phase 1.4 — RequireRole returns the right status code for the
// three input shapes: no subject, subject without role, subject
// with role. Tracks audit finding A-MED-4.

func TestRequireRole_NoSubject(t *testing.T) {
	err := RequireRole(context.Background(), RoleAdmin)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v (%v)", status.Code(err), err)
	}
}

func TestRequireRole_MissingRole(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, "user"))
	err := RequireRole(ctx, RoleAdmin)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v (%v)", status.Code(err), err)
	}
}

func TestRequireRole_HasRole(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "_system", MDKeyRoles, "admin"))
	if err := RequireRole(ctx, RoleAdmin); err != nil {
		t.Fatalf("admin should be allowed: %v", err)
	}
}

func TestRequireRole_MultipleRoles(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, "user,viewer,admin,billing"))
	if err := RequireRole(ctx, RoleAdmin); err != nil {
		t.Fatalf("admin among multiple roles should be allowed: %v", err)
	}
}

func TestRequireRole_FromContextFallback(t *testing.T) {
	// In-process / direct gRPC case: no incoming metadata,
	// claims live in plain context via ContextWithClaims.
	claims := &Claims{Username: "alice", Roles: []string{"admin"}}
	ctx := ContextWithClaims(context.Background(), claims)
	if err := RequireRole(ctx, RoleAdmin); err != nil {
		t.Fatalf("context-fallback admin should be allowed: %v", err)
	}
}
