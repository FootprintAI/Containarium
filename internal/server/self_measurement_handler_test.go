package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetSelfMeasurement (#683) is admin-only: the signed integrity attestation is
// a control-plane verification signal, not a tenant resource.
func TestGetSelfMeasurement_RejectsNonAdmin(t *testing.T) {
	srv := &ContainerServer{}
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.GetSelfMeasurement(ctx, &pb.GetSelfMeasurementRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin must be denied; got %v (%v)", status.Code(err), err)
	}
}

// With no peer pool bootstrapped there is no node identity key, so the local
// measurement is produced but unsigned — present and unverifiable, not an
// error and not flagged as tamper.
func TestGetSelfMeasurement_LocalUnsignedWhenNoPKI(t *testing.T) {
	srv := &ContainerServer{}
	srv.SetIntegrityConfig(map[string]string{
		"base_domain":            "example.com",
		"network_policy_enforce": "0",
	})
	ctx := auth.ContextWithSystemIdentity(context.Background())

	resp, err := srv.GetSelfMeasurement(ctx, &pb.GetSelfMeasurementRequest{})
	if err != nil {
		t.Fatalf("GetSelfMeasurement: %v", err)
	}
	m := resp.Measurement
	if m == nil {
		t.Fatalf("expected a measurement")
	}
	if m.Signed {
		t.Errorf("expected unsigned measurement without a peer identity key")
	}
	if m.Signature != "" {
		t.Errorf("unsigned measurement must have empty signature, got %q", m.Signature)
	}
	if m.HashAlgorithm == "" || m.MeasurementDigest == "" || m.ConfigDigest == "" {
		t.Errorf("measurement should carry hash/measurement/config digests even when unsigned: %+v", m)
	}
	// The running test binary exists on disk, so the binary digest is populated.
	if m.BinaryDigest == "" {
		t.Errorf("expected a non-empty binary digest for the running daemon binary")
	}
}
