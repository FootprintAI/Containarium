package server

import (
	"context"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 3.2 — privileged-Podman policy gate (audit A-HIGH-3).

func resetPrivilegedPolicy(t *testing.T) {
	t.Helper()
	privilegedPolicy = PrivilegedPolicyAll
	privilegedPolicyOnce = sync.Once{}
}

func TestPrivilegedPolicy_DefaultIsAll(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "")
	resetPrivilegedPolicy(t)
	if got := loadPrivilegedPolicy(); got != PrivilegedPolicyAll {
		t.Fatalf("policy = %v, want PrivilegedPolicyAll (backwards-compat default)", got)
	}
}

func TestPrivilegedPolicy_ParsesAdminOnly(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "admin-only")
	resetPrivilegedPolicy(t)
	if got := loadPrivilegedPolicy(); got != PrivilegedPolicyAdminOnly {
		t.Fatalf("policy = %v, want PrivilegedPolicyAdminOnly", got)
	}
}

func TestPrivilegedPolicy_ParsesDisabled(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "disabled")
	resetPrivilegedPolicy(t)
	if got := loadPrivilegedPolicy(); got != PrivilegedPolicyDisabled {
		t.Fatalf("policy = %v, want PrivilegedPolicyDisabled", got)
	}
}

func TestAuthorizePrivilegedPodman_AllPolicy(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "all")
	resetPrivilegedPolicy(t)

	// "all" accepts every caller, no role check needed.
	allowed, err := authorizePrivilegedPodman(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !allowed {
		t.Fatal("policy=all must allow privileged")
	}
}

func TestAuthorizePrivilegedPodman_AdminOnly_NonAdminRejected(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "admin-only")
	resetPrivilegedPolicy(t)

	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	allowed, err := authorizePrivilegedPodman(ctx)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
	if allowed {
		t.Fatal("non-admin must not be allowed")
	}
}

func TestAuthorizePrivilegedPodman_AdminOnly_AdminAllowed(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "admin-only")
	resetPrivilegedPolicy(t)

	ctx := auth.ContextWithSystemIdentity(context.Background())
	allowed, err := authorizePrivilegedPodman(ctx)
	if err != nil {
		t.Fatalf("admin must pass: %v", err)
	}
	if !allowed {
		t.Fatal("admin must be allowed")
	}
}

func TestAuthorizePrivilegedPodman_Disabled_DowngradesEvenForAdmin(t *testing.T) {
	t.Setenv(privilegedPolicyEnv, "disabled")
	resetPrivilegedPolicy(t)

	ctx := auth.ContextWithSystemIdentity(context.Background())
	allowed, err := authorizePrivilegedPodman(ctx)
	if err != nil {
		t.Fatalf("disabled policy must not error: %v", err)
	}
	if allowed {
		t.Fatal("disabled policy must downgrade to unprivileged even for admin")
	}
}
