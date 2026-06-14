package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The capacity RPCs (#680) are admin-only: they read/mutate a fleet-level
// scheduling signal, not a tenant resource.

func TestAdvertiseCapacity_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.AdvertiseCapacity(ctx, &pb.AdvertiseCapacityRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

func TestWithdrawCapacity_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.WithdrawCapacity(ctx, &pb.WithdrawCapacityRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

func TestGetCapacityHeadroom_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.GetCapacityHeadroom(ctx, &pb.GetCapacityHeadroomRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

// Advertise → Get → Withdraw (twice) exercises the lifecycle and the
// idempotence of withdraw. The nil manager makes hostStateSnapshot return a
// zero-resource snapshot, so the spare figures are zero but the advertise /
// withdraw state transitions are still observable.
func TestCapacityLifecycleIdempotentWithdraw(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithSystemIdentity(context.Background())

	adv, err := srv.AdvertiseCapacity(ctx, &pb.AdvertiseCapacityRequest{
		Policy: &pb.CapacityPolicy{ReserveFraction: 0.1},
	})
	if err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if adv.Headroom == nil || !adv.Headroom.Advertised {
		t.Fatalf("advertise should set advertised=true; got %+v", adv.Headroom)
	}

	got, err := srv.GetCapacityHeadroom(ctx, &pb.GetCapacityHeadroomRequest{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Headroom == nil || !got.Headroom.Advertised {
		t.Fatalf("get after advertise should be advertised; got %+v", got.Headroom)
	}

	w1, err := srv.WithdrawCapacity(ctx, &pb.WithdrawCapacityRequest{})
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if w1.Headroom == nil || w1.Headroom.Advertised {
		t.Fatalf("withdraw should clear advertised; got %+v", w1.Headroom)
	}

	// Idempotent: a second withdraw succeeds and stays withdrawn.
	w2, err := srv.WithdrawCapacity(ctx, &pb.WithdrawCapacityRequest{})
	if err != nil {
		t.Fatalf("second withdraw: %v", err)
	}
	if w2.Headroom == nil || w2.Headroom.Advertised {
		t.Fatalf("second withdraw must remain withdrawn; got %+v", w2.Headroom)
	}
}
