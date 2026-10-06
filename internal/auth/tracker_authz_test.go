package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// #2268 — AuthorizeTrackerTenant: AuthorizeTenant plus the one extra way a
// RUN token passes, for the tenant its run_tenant claim names.

// runTokenCtx is the metadata shape a real run token produces after the
// HTTP middleware and gateway annotator: the BOX as subject, no roles, a
// run_id and the tenant the run was started for.
func runTokenCtx(runID, tenant string) context.Context {
	pairs := []string{MDKeyUsername, "agent-product-define", MDKeyRoles, ""}
	if runID != "" {
		pairs = append(pairs, MDKeyRunID, runID)
	}
	if tenant != "" {
		pairs = append(pairs, MDKeyRunTenant, tenant)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

func TestAuthorizeTrackerTenant_RunTokenForItsOwnTenant(t *testing.T) {
	if err := AuthorizeTrackerTenant(runTokenCtx("run-1", "alice"), "alice"); err != nil {
		t.Fatalf("a run token started by alice must act on alice's tracker: %v", err)
	}
}

func TestAuthorizeTrackerTenant_RunTokenForAnotherTenant(t *testing.T) {
	err := AuthorizeTrackerTenant(runTokenCtx("run-1", "alice"), "bob")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a run token started by alice on bob's tracker: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}
}

func TestAuthorizeTrackerTenant_RunTokenIsNotTheTenantElsewhere(t *testing.T) {
	// The plain tenant check is unchanged: the run token's subject is the
	// box, so it is NOT alice for any non-tracker RPC — least privilege.
	err := AuthorizeTenant(runTokenCtx("run-1", "alice"), "alice")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AuthorizeTenant(run token, alice): code = %v (%v), want PermissionDenied", status.Code(err), err)
	}
}

func TestAuthorizeTrackerTenant_RunTenantWithoutRunIDIsIgnored(t *testing.T) {
	// Only a run token may act for a tenant it is not: a run_tenant claim
	// on a token with no run_id buys nothing.
	err := AuthorizeTrackerTenant(runTokenCtx("", "alice"), "alice")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("run_tenant without run_id: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}
}

func TestAuthorizeTrackerTenant_RunTokenWithoutRunTenant(t *testing.T) {
	// A run token minted before the claim existed is refused exactly as
	// before — nothing is inferred from act or from the box name.
	err := AuthorizeTrackerTenant(runTokenCtx("run-1", ""), "alice")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("run token with no run_tenant: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}
}

func TestAuthorizeTrackerTenant_OperatorAndAdminUnchanged(t *testing.T) {
	self := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "alice", MDKeyRoles, "user"))
	if err := AuthorizeTrackerTenant(self, "alice"); err != nil {
		t.Fatalf("alice on alice: %v", err)
	}
	if err := AuthorizeTrackerTenant(self, "bob"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("alice on bob: code = %v, want PermissionDenied", status.Code(err))
	}
	admin := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(MDKeyUsername, "operator", MDKeyRoles, RoleAdmin))
	if err := AuthorizeTrackerTenant(admin, "bob"); err != nil {
		t.Fatalf("admin on bob: %v", err)
	}
}

func TestAuthorizeTrackerTenant_NoSubject(t *testing.T) {
	err := AuthorizeTrackerTenant(context.Background(), "alice")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no subject: code = %v, want Unauthenticated", status.Code(err))
	}
	// A run_tenant claim with no subject at all is not a subject.
	md := metadata.Pairs(MDKeyRunID, "run-1", MDKeyRunTenant, "alice")
	err = AuthorizeTrackerTenant(metadata.NewIncomingContext(context.Background(), md), "alice")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("run claims with no subject: code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestAuthorizeTrackerTenant_ContextFallback(t *testing.T) {
	// The in-process path: claims as context values, no incoming metadata.
	claims := &Claims{Username: "agent-product-define", Roles: nil, RunID: "run-1", RunTenant: "alice"}
	ctx := ContextWithClaims(context.Background(), claims)
	if err := AuthorizeTrackerTenant(ctx, "alice"); err != nil {
		t.Fatalf("context-value run token on its own tenant: %v", err)
	}
	if err := AuthorizeTrackerTenant(ctx, "bob"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("context-value run token on another tenant: code = %v, want PermissionDenied", status.Code(err))
	}
}

// #2268 — RunTenantFromGRPCContext is how AuthorizeTrackerTenant recovers
// the run's tenant, propagated the same way MDKeyTrackerConn is.

func TestRunTenantFromGRPCContext_Metadata(t *testing.T) {
	md := metadata.Pairs(MDKeyRunTenant, "alice")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	got, ok := RunTenantFromGRPCContext(ctx)
	if !ok || got != "alice" {
		t.Fatalf("got %q ok=%v, want alice/true", got, ok)
	}
}

func TestRunTenantFromGRPCContext_ContextFallback(t *testing.T) {
	claims := &Claims{Username: "agent-x", RunTenant: "alice"}
	ctx := ContextWithClaims(context.Background(), claims)

	got, ok := RunTenantFromGRPCContext(ctx)
	if !ok || got != "alice" {
		t.Fatalf("got %q ok=%v, want alice/true", got, ok)
	}
}

func TestRunTenantFromGRPCContext_None(t *testing.T) {
	got, ok := RunTenantFromGRPCContext(context.Background())
	if ok || got != "" {
		t.Fatalf("got %q ok=%v, want empty/false for a context with no run_tenant", got, ok)
	}
}
