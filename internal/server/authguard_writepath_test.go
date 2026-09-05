package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #1716 and #1717: two write paths that reached real state with no
// authorization guard at all. These assert the denial, not the happy path —
// the happy path was never broken, and a test that only proves the guard lets
// the right caller through would still pass with the guard removed.

// scopedTenantCtx is tenantCtx (rbac_phase_1_4_tenant_test.go) plus a scopes
// claim — these guards check scope AND tenancy, so both have to be set.
func scopedTenantCtx(username string, scopes ...string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), username, []string{"user"}, scopes)
}

// #1716. The username is request input naming whose box gets touched. Before
// the fix, any caller could pass any username: Enable/Disable mutated state
// inside another tenant's box, and Discover/Status read it.
func TestComposeAutostart_RefusesAnotherTenantsBox(t *testing.T) {
	s := &ComposeAutostartServer{}
	// alice is authenticated, correctly scoped, and targets bob's box.
	ctx := scopedTenantCtx("alice", auth.ScopeContainersRead, auth.ScopeContainersWrite)

	calls := map[string]func() error{
		"Discover": func() error {
			_, err := s.Discover(ctx, &pb.DiscoverRequest{Username: "bob"})
			return err
		},
		"Enable": func() error {
			_, err := s.Enable(ctx, &pb.EnableRequest{Username: "bob"})
			return err
		},
		"Disable": func() error {
			_, err := s.Disable(ctx, &pb.DisableRequest{Username: "bob"})
			return err
		},
		"Status": func() error {
			_, err := s.Status(ctx, &pb.StatusRequest{Username: "bob"})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil {
				t.Fatalf("%s reached bob's box for a caller authenticated as alice", name)
			}
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Errorf("code = %v, want PermissionDenied (got %v)", got, err)
			}
		})
	}
}

// Scope alone must not be enough, and neither must tenancy alone. A caller
// acting on its OWN box still needs the right scope — otherwise a read-only
// token could flip autostart.
func TestComposeAutostart_ReadScopeCannotMutateOwnBox(t *testing.T) {
	s := &ComposeAutostartServer{}
	ctx := scopedTenantCtx("alice", auth.ScopeContainersRead) // read only

	if _, err := s.Enable(ctx, &pb.EnableRequest{Username: "alice"}); err == nil {
		t.Error("a containers:read token enabled autostart on its own box")
	} else if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("Enable: code = %v, want PermissionDenied", got)
	}
	if _, err := s.Disable(ctx, &pb.DisableRequest{Username: "alice"}); err == nil {
		t.Error("a containers:read token disabled autostart on its own box")
	}
}

// An entirely unauthenticated caller must not reach any of them.
func TestComposeAutostart_RefusesUnauthenticated(t *testing.T) {
	s := &ComposeAutostartServer{}
	if _, err := s.Enable(context.Background(), &pb.EnableRequest{Username: "alice"}); err == nil {
		t.Fatal("an unauthenticated caller enabled autostart")
	}
}

// #1717. The bad-destination blocklist is a fleet-wide detection control.
// Removing an entry silently disables a rule, which is why this is gated on
// the admin role and not only a scope.
func TestBadDestination_MutationRequiresAdmin(t *testing.T) {
	s := &ThreatDetectionServer{}
	// Correctly scoped, but not an admin.
	ctx := scopedTenantCtx("alice", auth.ScopeSecurityWrite)

	if _, err := s.AddBadDestination(ctx, &pb.AddBadDestinationRequest{Cidr: "10.0.0.0/8"}); err == nil {
		t.Error("a non-admin added a fleet-wide blocklist entry")
	} else if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("Add: code = %v, want PermissionDenied", got)
	}
	if _, err := s.RemoveBadDestination(ctx, &pb.RemoveBadDestinationRequest{Cidr: "10.0.0.0/8"}); err == nil {
		t.Error("a non-admin removed a fleet-wide blocklist entry — this silently disables a detection rule")
	} else if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("Remove: code = %v, want PermissionDenied", got)
	}
}

// ...and the admin role alone is not enough either: the scope is still required.
func TestBadDestination_AdminStillNeedsTheScope(t *testing.T) {
	s := &ThreatDetectionServer{}
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "ops",
		[]string{auth.RoleAdmin}, []string{auth.ScopeSecurityRead})

	if _, err := s.RemoveBadDestination(ctx, &pb.RemoveBadDestinationRequest{Cidr: "10.0.0.0/8"}); err == nil {
		t.Error("an admin holding only security:read mutated the blocklist")
	}
}

func TestBadDestination_RefusesUnauthenticated(t *testing.T) {
	s := &ThreatDetectionServer{}
	if _, err := s.AddBadDestination(context.Background(), &pb.AddBadDestinationRequest{Cidr: "10.0.0.0/8"}); err == nil {
		t.Fatal("an unauthenticated caller mutated the blocklist")
	}
}
