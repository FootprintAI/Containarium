package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestHasRole(t *testing.T) {
	if !HasRole([]string{"user", "admin"}, "admin") {
		t.Fatal("admin should be found")
	}
	if HasRole([]string{"user"}, "admin") {
		t.Fatal("admin should NOT be found")
	}
	if HasRole(nil, "admin") {
		t.Fatal("nil roles should not match")
	}
}

func TestSubjectFromGRPCContext_Metadata(t *testing.T) {
	md := metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, "user,viewer")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	u, roles, ok := SubjectFromGRPCContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if u != "alice" {
		t.Fatalf("username: got %q, want alice", u)
	}
	if len(roles) != 2 || roles[0] != "user" || roles[1] != "viewer" {
		t.Fatalf("roles: got %v, want [user viewer]", roles)
	}
}

func TestSubjectFromGRPCContext_ContextFallback(t *testing.T) {
	claims := &Claims{Username: "bob", Roles: []string{"admin"}}
	ctx := ContextWithClaims(context.Background(), claims)

	u, roles, ok := SubjectFromGRPCContext(ctx)
	if !ok || u != "bob" {
		t.Fatalf("got u=%q ok=%v, want bob/true", u, ok)
	}
	if !HasRole(roles, "admin") {
		t.Fatalf("expected admin role, got %v", roles)
	}
}

func TestSubjectFromGRPCContext_None(t *testing.T) {
	_, _, ok := SubjectFromGRPCContext(context.Background())
	if ok {
		t.Fatal("expected ok=false for empty context")
	}
}

func TestAuthorizeTenant_SameSubject(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, "user"))
	if err := AuthorizeTenant(ctx, "alice"); err != nil {
		t.Fatalf("alice should be authorized for alice: %v", err)
	}
}

func TestAuthorizeTenant_CrossTenantDenied(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, "user"))
	err := AuthorizeTenant(ctx, "bob")
	if err == nil {
		t.Fatal("alice acting on bob should be denied")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", status.Code(err))
	}
}

func TestAuthorizeTenant_AdminBypass(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "_system", MDKeyRoles, "admin"))
	if err := AuthorizeTenant(ctx, "bob"); err != nil {
		t.Fatalf("admin should be allowed cross-tenant: %v", err)
	}
}

func TestAuthorizeTenant_NoSubject(t *testing.T) {
	err := AuthorizeTenant(context.Background(), "alice")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v (%v)", status.Code(err), err)
	}
}

func TestSplitRoles_TrimsWhitespace(t *testing.T) {
	got := splitRoles("user, admin , viewer")
	want := []string{"user", "admin", "viewer"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %q want %q", i, got[i], want[i])
		}
	}
}
