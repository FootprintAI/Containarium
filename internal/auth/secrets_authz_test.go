package auth

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// secretCtx builds an incoming gRPC context. Passing scopes="" omits the claim
// entirely, which is the shape `token generate` produces without --scopes and
// the one this whole change is about.
func secretCtx(username, roles, scopes string) context.Context {
	pairs := []string{MDKeyUsername, username, MDKeyRoles, roles}
	if scopes != "" {
		pairs = append(pairs, MDKeyScopes, scopes)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

// The composition this change exists to break: an unscoped admin token reading
// another tenant's secrets. Both of the old gates passed it — the scope check
// because the claim is absent, the tenant check because of the role.
func TestAuthorizeSecretTenant_UnscopedAdminDeniedCrossTenant(t *testing.T) {
	ctx := secretCtx("cloud-daemon", "admin", "")

	for _, scope := range []string{ScopeSecretsRead, ScopeSecretsWrite} {
		err := AuthorizeSecretTenant(ctx, "alice", scope)
		if err == nil {
			t.Fatalf("%s: unscoped admin token authorized for another tenant's secrets", scope)
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: code = %v, want PermissionDenied", scope, status.Code(err))
		}
	}

	// The old behavior, for contrast: AuthorizeTenant still allows this, and is
	// still correct for container operations. Only secrets are narrowed.
	if err := AuthorizeTenant(ctx, "alice"); err != nil {
		t.Errorf("AuthorizeTenant should be unchanged for the admin role: %v", err)
	}
}

// An operator who states the scope keeps working. Cross-tenant secret access is
// meant to become deliberate, not impossible.
func TestAuthorizeSecretTenant_ExplicitlyScopedAdminAllowed(t *testing.T) {
	if err := AuthorizeSecretTenant(secretCtx("ops", "admin", "secrets:read"), "alice", ScopeSecretsRead); err != nil {
		t.Errorf("admin with an explicit secrets:read denied: %v", err)
	}
	if err := AuthorizeSecretTenant(secretCtx("ops", "admin", "containers:read,secrets:write"), "alice", ScopeSecretsWrite); err != nil {
		t.Errorf("admin with an explicit secrets:write denied: %v", err)
	}
	// The wildcard is an explicit grant.
	if err := AuthorizeSecretTenant(secretCtx("ops", "admin", "*"), "alice", ScopeSecretsRead); err != nil {
		t.Errorf("wildcard scope denied: %v", err)
	}
}

// Holding the wrong secrets scope is not holding the right one.
func TestAuthorizeSecretTenant_WrongScopeDoesNotCarry(t *testing.T) {
	err := AuthorizeSecretTenant(secretCtx("ops", "admin", "secrets:read"), "alice", ScopeSecretsWrite)
	if err == nil {
		t.Fatal("secrets:read authorized a write")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", status.Code(err))
	}
}

// Self-access is not the vulnerability and must not regress: it is the path
// every ordinary `containarium secrets` call takes, including from the unscoped
// tokens the CLI documents as "unrestricted".
func TestAuthorizeSecretTenant_SelfAccessUnchanged(t *testing.T) {
	cases := []struct{ name, roles, scopes string }{
		{"unscoped non-admin", "user", ""},
		{"unscoped admin", "admin", ""},
		{"scoped", "user", "secrets:read,secrets:write"},
		{"unrelated scope", "user", "containers:read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := secretCtx("alice", c.roles, c.scopes)
			if err := AuthorizeSecretTenant(ctx, "alice", ScopeSecretsRead); err != nil {
				t.Errorf("alice denied her own secrets: %v", err)
			}
			if err := AuthorizeSecretTenant(ctx, "alice", ScopeSecretsWrite); err != nil {
				t.Errorf("alice denied writing her own secrets: %v", err)
			}
		})
	}
}

// A non-admin reaching across tenants is still denied, and the scope does not
// buy its way past the role check — otherwise any tenant could grant itself
// cross-tenant access by asking for a scope.
func TestAuthorizeSecretTenant_NonAdminCrossTenantDeniedEvenWithScope(t *testing.T) {
	err := AuthorizeSecretTenant(secretCtx("alice", "user", "secrets:read"), "bob", ScopeSecretsRead)
	if err == nil {
		t.Fatal("a scoped non-admin read another tenant's secrets")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestAuthorizeSecretTenant_NoSubject(t *testing.T) {
	err := AuthorizeSecretTenant(context.Background(), "alice", ScopeSecretsRead)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", status.Code(err))
	}
}

// The denial has to tell an operator what to do about it — an opaque
// PermissionDenied on a path that worked yesterday is how a security fix gets
// reverted rather than adopted.
func TestAuthorizeSecretTenant_DenialIsActionable(t *testing.T) {
	err := AuthorizeSecretTenant(secretCtx("cloud-daemon", "admin", ""), "alice", ScopeSecretsRead)
	if err == nil {
		t.Fatal("expected denial")
	}
	msg := status.Convert(err).Message()
	for _, want := range []string{"secrets:read", "--scopes"} {
		if !strings.Contains(msg, want) {
			t.Errorf("denial message %q does not mention %q", msg, want)
		}
	}
}
