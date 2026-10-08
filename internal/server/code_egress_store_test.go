package server

import (
	"context"
	"errors"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// codeEgressStoreContract is the behaviour both CodingToolEgressPolicyStore
// implementations must share. The Postgres half runs it from
// code_egress_store_integration_test.go.
func codeEgressStoreContract(t *testing.T, s CodingToolEgressPolicyStore) {
	t.Helper()
	ctx := context.Background()

	if _, err := s.Get(ctx, "alice"); !errors.Is(err, ErrCodingToolEgressPolicyNotFound) {
		t.Fatalf("Get on an empty store = %v, want ErrCodingToolEgressPolicyNotFound", err)
	}

	first, prev, err := s.Set(ctx, &pb.CodingToolEgressPolicy{
		Tenant: "alice", Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		EgressCidrs: []string{"192.0.2.0/24"}, EgressDomains: []string{"api.example.com"},
	}, "admin-user")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if prev != 0 || first.GetRevision() <= 0 {
		t.Fatalf("first Set: prev=%d revision=%d, want prev=0 and a positive revision", prev, first.GetRevision())
	}
	if first.GetUpdatedBy() != "admin-user" || first.GetUpdatedAt() == nil {
		t.Errorf("Set must stamp updated_by/updated_at, got %+v", first)
	}

	got, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GetRevision() != first.GetRevision() || got.GetMode() != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE ||
		len(got.GetEgressCidrs()) != 1 || got.GetEgressCidrs()[0] != "192.0.2.0/24" ||
		len(got.GetEgressDomains()) != 1 || got.GetEgressDomains()[0] != "api.example.com" {
		t.Errorf("round trip lost data: %+v", got)
	}

	// The cluster default lives under the empty tenant, independent of alice.
	def, _, err := s.Set(ctx, &pb.CodingToolEgressPolicy{Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY}, "admin-user")
	if err != nil {
		t.Fatalf("Set default: %v", err)
	}
	if def.GetRevision() <= first.GetRevision() {
		t.Errorf("revisions must be monotonic across keys: %d after %d", def.GetRevision(), first.GetRevision())
	}
	if d, err := s.Get(ctx, ""); err != nil || len(d.GetEgressCidrs()) != 0 || len(d.GetEgressDomains()) != 0 {
		t.Errorf("cluster default with empty lists: %+v, %v", d, err)
	}

	second, prev, err := s.Set(ctx, &pb.CodingToolEgressPolicy{Tenant: "alice", Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE}, "admin-user")
	if err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if prev != first.GetRevision() || second.GetRevision() <= def.GetRevision() {
		t.Errorf("second Set: prev=%d (want %d) revision=%d (want > %d)", prev, first.GetRevision(), second.GetRevision(), def.GetRevision())
	}
	if got, _ := s.Get(ctx, "alice"); len(got.GetEgressCidrs()) != 0 || len(got.GetEgressDomains()) != 0 {
		t.Errorf("Set replaces, it does not merge: %+v", got)
	}

	removed, err := s.Delete(ctx, "alice")
	if err != nil || removed != second.GetRevision() {
		t.Fatalf("Delete = %d, %v; want the removed revision %d", removed, err, second.GetRevision())
	}
	if _, err := s.Get(ctx, "alice"); !errors.Is(err, ErrCodingToolEgressPolicyNotFound) {
		t.Errorf("Get after Delete = %v, want not found", err)
	}
	if removed, err := s.Delete(ctx, "alice"); err != nil || removed != 0 {
		t.Errorf("Delete of a missing policy = %d, %v; want 0, nil (idempotent)", removed, err)
	}
	third, _, err := s.Set(ctx, &pb.CodingToolEgressPolicy{Tenant: "alice"}, "admin-user")
	if err != nil {
		t.Fatalf("Set after Delete: %v", err)
	}
	if third.GetRevision() <= second.GetRevision() {
		t.Errorf("revision went backwards after a delete: %d after %d", third.GetRevision(), second.GetRevision())
	}
}

func TestCodingToolEgressPolicyStore_MemContract(t *testing.T) {
	codeEgressStoreContract(t, NewMemCodingToolEgressPolicyStore())
}

func TestCodingToolEgressPolicyStore_MemReturnsCopies(t *testing.T) {
	ctx := context.Background()
	s := NewMemCodingToolEgressPolicyStore()
	stored, _, err := s.Set(ctx, &pb.CodingToolEgressPolicy{Tenant: "alice", EgressCidrs: []string{"192.0.2.0/24"}}, "a")
	if err != nil {
		t.Fatal(err)
	}
	stored.EgressCidrs[0] = "0.0.0.0/0"
	got, _ := s.Get(ctx, "alice")
	got.EgressCidrs = append(got.EgressCidrs, "0.0.0.0/0")
	again, _ := s.Get(ctx, "alice")
	if len(again.GetEgressCidrs()) != 1 || again.GetEgressCidrs()[0] != "192.0.2.0/24" {
		t.Fatalf("stored state was mutated through a returned pointer: %v", again.GetEgressCidrs())
	}
}
