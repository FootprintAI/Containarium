package auth

import (
	"context"
	"encoding/json"
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

// TestActFromGRPCContext_Metadata is the #1677 analogue of
// TestSubjectFromGRPCContext_Metadata: the primary API surface is REST via
// grpc-gateway, and a delegation claim only survives that hop as metadata
// (see ActFromGRPCContext's doc comment) — this pins that the JSON-encoded
// nested chain round-trips through it intact.
func TestActFromGRPCContext_Metadata(t *testing.T) {
	act := &Actor{Subject: "agent-relay-agent", Act: &Actor{Subject: "alice"}}
	encoded, err := json.Marshal(act)
	if err != nil {
		t.Fatalf("setup: marshal: %v", err)
	}
	md := metadata.Pairs(MDKeyAct, string(encoded))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	got, ok := ActFromGRPCContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.Subject != "agent-relay-agent" || got.Act == nil || got.Act.Subject != "alice" {
		t.Fatalf("got %+v, want the nested chain intact", got)
	}
}

func TestActFromGRPCContext_ContextFallback(t *testing.T) {
	act := &Actor{Subject: "bob"}
	claims := &Claims{Username: "agent-x", Act: act}
	ctx := ContextWithClaims(context.Background(), claims)

	got, ok := ActFromGRPCContext(ctx)
	if !ok || got == nil || got.Subject != "bob" {
		t.Fatalf("got %+v ok=%v, want {Subject: bob}/true", got, ok)
	}
}

// TestActFromGRPCContext_None is the backward-compat AC: absence is valid,
// reported as unattributed (ok=false), never an error.
func TestActFromGRPCContext_None(t *testing.T) {
	act, ok := ActFromGRPCContext(context.Background())
	if ok || act != nil {
		t.Fatalf("got act=%+v ok=%v, want nil/false for a context with no delegation claim", act, ok)
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
