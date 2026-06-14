package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The capability-profile RPCs (#681) are admin-only: they read/record a
// fleet-level hardware signal, not a tenant resource.

func TestProfileBackend_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.ProfileBackend(ctx, &pb.ProfileBackendRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

func TestGetCapabilityProfile_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.GetCapabilityProfile(ctx, &pb.GetCapabilityProfileRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

// GetCapabilityProfile before any ProfileBackend returns a null profile (not an
// error) so the control plane can tell "unprofiled" from "profiled".
func TestGetCapabilityProfile_NullBeforeProfiling(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithSystemIdentity(context.Background())
	resp, err := srv.GetCapabilityProfile(ctx, &pb.GetCapabilityProfileRequest{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.Profile != nil {
		t.Fatalf("expected null profile before profiling; got %+v", resp.Profile)
	}
}

// Profile (skip GPU, nil manager) → Get records and reads back. The nil manager
// + missing Incus daemon yields zero hardware figures, but the benchmark runs
// and the profile is persisted and class-reconciled. reportedClass is set so we
// can assert the reconciliation path.
func TestProfileBackendRecordsAndPersists(t *testing.T) {
	srv := &ContainerServer{}
	srv.SetCapabilityIdentity("region-a", "")
	ctx := auth.ContextWithSystemIdentity(context.Background())

	rec, err := srv.ProfileBackend(ctx, &pb.ProfileBackendRequest{SkipGpu: true})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if rec.Profile == nil {
		t.Fatalf("profile response must carry a profile")
	}
	if rec.Profile.Region != "region-a" {
		t.Fatalf("region = %q, want region-a", rec.Profile.Region)
	}
	// Empty reported class is treated as consistent.
	if !rec.Profile.ClassConsistent {
		t.Fatalf("empty reported class must reconcile as consistent; got %+v", rec.Profile)
	}
	if rec.Profile.Benchmark == nil || rec.Profile.Benchmark.CpuOpsPerSec <= 0 {
		t.Fatalf("benchmark must run and report positive CPU score; got %+v", rec.Profile.Benchmark)
	}
	if rec.Profile.ProfiledAt == "" {
		t.Fatalf("profiledAt must be stamped")
	}

	got, err := srv.GetCapabilityProfile(ctx, &pb.GetCapabilityProfileRequest{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Profile == nil || got.Profile.Region != "region-a" {
		t.Fatalf("get after profile must return the persisted profile; got %+v", got.Profile)
	}
}
