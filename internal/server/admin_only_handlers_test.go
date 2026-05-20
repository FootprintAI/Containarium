package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 1.4 — Cluster-level handlers must require the admin role
// regardless of which tenant the JWT names. AuthorizeTenant alone
// would let a user move / adopt their own container; RequireRole
// closes that gap. Audit finding A-MED-4.

func TestGetSystemInfo_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{} // GetSystemInfo's authz fires before any field access
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")

	_, err := srv.GetSystemInfo(ctx, &pb.GetSystemInfoRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

func TestGetSystemInfo_RejectsNoSubject(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing subject must be Unauthenticated; got %v", status.Code(err))
	}
}

func TestMoveContainer_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")

	_, err := srv.MoveContainer(ctx, &pb.MoveContainerRequest{
		Username:        "alice",
		TargetBackendId: "tunnel-other",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied even on own username; got %v (%v)", status.Code(err), err)
	}
}

func TestAdoptMigratedContainer_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")

	_, err := srv.AdoptMigratedContainer(ctx, &pb.AdoptMigratedContainerRequest{
		Username: "alice",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

// Positive coverage (admin token passes the gate) is exercised
// indirectly by existing handler tests that use testCtx() — those
// inject ContextWithSystemIdentity (admin role) and would fail
// immediately at RequireRole if the gate were misconfigured.
