package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func newNPServerWithSigs() *NetworkPolicyServer {
	s := NewNetworkPolicyServer(NewMemNetworkPolicyStore())
	s.SetSignatureStore(NewMemNetworkPolicySignatureStore())
	return s
}

func TestNetworkPolicySignature_CRUD(t *testing.T) {
	s := newNPServerWithSigs()
	ctx := npAdminCtx()

	set, err := s.SetNetworkPolicySignature(ctx, &pb.SetNetworkPolicySignatureRequest{
		Signature: &pb.NetworkPolicySignature{Name: "CVE-2024-9", Pattern: "${jndi:", Enabled: true, Note: "log4shell-ish"},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if set.GetSignature().GetId() == 0 || set.GetSignature().GetPattern() != "${jndi:" {
		t.Fatalf("set result wrong: %+v", set.GetSignature())
	}

	list, err := s.ListNetworkPolicySignatures(ctx, &pb.ListNetworkPolicySignaturesRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.GetSignatures()) != 1 {
		t.Fatalf("want 1 signature, got %d", len(list.GetSignatures()))
	}

	if _, err := s.DeleteNetworkPolicySignature(ctx, &pb.DeleteNetworkPolicySignatureRequest{Name: "CVE-2024-9"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Idempotent delete.
	if _, err := s.DeleteNetworkPolicySignature(ctx, &pb.DeleteNetworkPolicySignatureRequest{Name: "CVE-2024-9"}); err != nil {
		t.Fatalf("second Delete should be idempotent: %v", err)
	}
}

func TestNetworkPolicySignature_Validation(t *testing.T) {
	s := newNPServerWithSigs()
	ctx := npAdminCtx()
	cases := []struct {
		name string
		sig  *pb.NetworkPolicySignature
	}{
		{"empty name", &pb.NetworkPolicySignature{Pattern: "x"}},
		{"name with slash", &pb.NetworkPolicySignature{Name: "a/b", Pattern: "x"}},
		{"empty pattern", &pb.NetworkPolicySignature{Name: "ok"}},
		{"pattern too long", &pb.NetworkPolicySignature{Name: "ok", Pattern: string(make([]byte, 33))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.SetNetworkPolicySignature(ctx, &pb.SetNetworkPolicySignatureRequest{Signature: c.sig})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("want InvalidArgument, got %v", err)
			}
		})
	}
}

func TestNetworkPolicySignature_AdminOnly(t *testing.T) {
	s := newNPServerWithSigs()
	userCtx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	_, err := s.SetNetworkPolicySignature(userCtx, &pb.SetNetworkPolicySignatureRequest{
		Signature: &pb.NetworkPolicySignature{Name: "x", Pattern: "y"},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("non-admin set should be PermissionDenied, got %v", err)
	}
}

func TestNetworkPolicySignature_Unavailable(t *testing.T) {
	// No signature store wired → Set/Delete return Unavailable, List returns empty.
	s := NewNetworkPolicyServer(NewMemNetworkPolicyStore())
	ctx := npAdminCtx()
	if _, err := s.SetNetworkPolicySignature(ctx, &pb.SetNetworkPolicySignatureRequest{
		Signature: &pb.NetworkPolicySignature{Name: "x", Pattern: "y"},
	}); status.Code(err) != codes.Unavailable {
		t.Errorf("set without store = %v, want Unavailable", err)
	}
	list, err := s.ListNetworkPolicySignatures(ctx, &pb.ListNetworkPolicySignaturesRequest{})
	if err != nil || len(list.GetSignatures()) != 0 {
		t.Errorf("list without store = (%v, %d sigs), want (nil, 0)", err, len(list.GetSignatures()))
	}
}
