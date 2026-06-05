package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// kmsAdminCtx builds a context carrying the kms:admin scope + admin role.
func kmsAdminCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin}, []string{auth.ScopeKMSAdmin})
}

func TestSetKMSStatus_NormalizesBackend(t *testing.T) {
	cs := &ContainerServer{}
	cs.SetKMSStatus("  AWS  ", "aws kms (region=us-west-2)", true, false)
	if cs.kmsBackend != "aws" {
		t.Fatalf("backend not normalized: %q", cs.kmsBackend)
	}
	// Empty backend defaults to "none".
	cs.SetKMSStatus("", "disabled", false, false)
	if cs.kmsBackend != "none" {
		t.Fatalf("empty backend should normalize to none; got %q", cs.kmsBackend)
	}
}

func TestGetKMSStatus_ReturnsSnapshot(t *testing.T) {
	cs := &ContainerServer{}
	cs.SetKMSStatus("vault", "vault transit (addr=https://v|transit|k)", true, true)
	srv := NewKmsServer(cs)

	resp, err := srv.GetKMSStatus(kmsAdminCtx(), &pb.GetKMSStatusRequest{})
	if err != nil {
		t.Fatalf("GetKMSStatus: %v", err)
	}
	if resp.Backend != "vault" || !resp.KmsConfigured || !resp.RequireEnvelope {
		t.Fatalf("unexpected status: %+v", resp)
	}
	if resp.Description == "" {
		t.Fatal("description should pass through")
	}
}

func TestKMS_RequiresAdminScope(t *testing.T) {
	srv := NewKmsServer(&ContainerServer{})

	// Missing the kms:admin scope (has a different scope).
	noScope := auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin}, []string{auth.ScopeSecretsRead})
	if _, err := srv.GetKMSStatus(noScope, &pb.GetKMSStatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("missing kms:admin scope should be PermissionDenied; got %v", err)
	}

	// Has the scope but not the admin role.
	notAdmin := auth.ContextWithTestSubjectScopes(context.Background(),
		"alice", []string{"user"}, []string{auth.ScopeKMSAdmin})
	if _, err := srv.GetKMSStatus(notAdmin, &pb.GetKMSStatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin should be PermissionDenied; got %v", err)
	}

	// No subject at all.
	if _, err := srv.GetKMSStatus(context.Background(), &pb.GetKMSStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no subject should be Unauthenticated; got %v", err)
	}
}

func TestKMS_CoverageAndMigrate_RequireStore(t *testing.T) {
	// secretsStore is nil → both data-plane RPCs return Unavailable
	// (and only AFTER auth passes).
	srv := NewKmsServer(&ContainerServer{})

	if _, err := srv.GetEnvelopeCoverage(kmsAdminCtx(), &pb.GetEnvelopeCoverageRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("coverage without store should be Unavailable; got %v", err)
	}
	if _, err := srv.MigrateToEnvelope(kmsAdminCtx(), &pb.MigrateToEnvelopeRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("migrate without store should be Unavailable; got %v", err)
	}
}
