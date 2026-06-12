package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/netpolicy"
)

func TestMemSignatureStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemNetworkPolicySignatureStore()

	// First insert assigns an id in the operator range.
	a, err := s.Set(ctx, "CVE-2024-1", []byte("evilpattern"), true, "note A")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if a.GetId() < netpolicy.OperatorIDBase {
		t.Fatalf("assigned id %d below OperatorIDBase %d", a.GetId(), netpolicy.OperatorIDBase)
	}
	if a.GetName() != "CVE-2024-1" || a.GetPattern() != "evilpattern" || !a.GetEnabled() {
		t.Fatalf("stored shape wrong: %+v", a)
	}

	// A second name gets a distinct, higher id.
	b, _ := s.Set(ctx, "CVE-2024-2", []byte("other"), true, "")
	if b.GetId() == a.GetId() {
		t.Fatalf("two signatures share id %d", a.GetId())
	}

	// Re-setting an existing name KEEPS its id (so audit references stay stable),
	// updates the pattern/enabled.
	a2, _ := s.Set(ctx, "CVE-2024-1", []byte("updated"), false, "note A2")
	if a2.GetId() != a.GetId() {
		t.Errorf("upsert changed id: %d -> %d", a.GetId(), a2.GetId())
	}
	if a2.GetPattern() != "updated" || a2.GetEnabled() {
		t.Errorf("upsert didn't update pattern/enabled: %+v", a2)
	}

	// List is sorted by name.
	list, _ := s.List(ctx)
	if len(list) != 2 || list[0].GetName() != "CVE-2024-1" || list[1].GetName() != "CVE-2024-2" {
		t.Fatalf("list wrong: %+v", list)
	}

	// Delete; a missing delete is ErrSignatureNotFound.
	if err := s.Delete(ctx, "CVE-2024-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, "CVE-2024-1"); err != ErrSignatureNotFound {
		t.Errorf("second delete = %v, want ErrSignatureNotFound", err)
	}
	if list, _ := s.List(ctx); len(list) != 1 {
		t.Errorf("after delete want 1, got %d", len(list))
	}
}
