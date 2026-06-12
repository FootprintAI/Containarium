package server

import (
	"context"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestNonNilStrings guards the fix for the egress_cidrs/egress_domains NOT NULL
// violation: a policy with no domains (or no CIDRs) arrives as a nil slice, and
// pgx would encode that as SQL NULL against a `TEXT[] NOT NULL` column. nonNilStrings
// coerces nil -> empty so the array stores '{}' instead.
func TestNonNilStrings(t *testing.T) {
	if got := nonNilStrings(nil); got == nil {
		t.Fatal("nil input must become a non-nil empty slice (else pgx writes NULL)")
	} else if len(got) != 0 {
		t.Fatalf("nil input should yield empty slice, got %v", got)
	}

	in := []string{"0.0.0.0/0", "10.0.0.0/8"}
	got := nonNilStrings(in)
	if len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("non-nil input must pass through unchanged, got %v", got)
	}

	// Empty-but-non-nil passes through as-is (already safe).
	if got := nonNilStrings([]string{}); got == nil || len(got) != 0 {
		t.Fatalf("empty non-nil slice should stay empty non-nil, got %v", got)
	}
}

// TestMemStore_DenyRulesPersistAndSetPreserves guards the #660 persistence fix:
// deny rules survive a Set/Get round-trip (clonePolicy used to drop them), and a
// later `set` of the allow-policy must NOT wipe them (Set owns the allow-policy;
// deny rules are owned by MutateDenyRules).
func TestMemStore_DenyRulesPersistAndSetPreserves(t *testing.T) {
	ctx := context.Background()
	s := NewMemNetworkPolicyStore()

	// A fresh Set never carries deny rules (they're owned by MutateDenyRules).
	if err := s.Set(ctx, &pb.NetworkPolicy{
		Tenant:      "acme",
		EgressCidrs: []string{"0.0.0.0/0"},
		DenyRules:   []*pb.NetworkPolicyDenyRule{{Cidr: "1.2.3.4/32"}}, // should be ignored by Set
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(ctx, "acme")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.GetDenyRules()) != 0 {
		t.Fatalf("Set must not store deny rules (owned by MutateDenyRules), got %+v", got.GetDenyRules())
	}

	// Add a deny rule via the atomic path; it must persist through Get.
	if _, err := s.MutateDenyRules(ctx, "acme", func(ex []*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) {
		return append(ex, &pb.NetworkPolicyDenyRule{Cidr: "9.9.9.9/32", Note: "CVE-x"}), nil
	}); err != nil {
		t.Fatalf("MutateDenyRules: %v", err)
	}
	got, _ = s.Get(ctx, "acme")
	if len(got.GetDenyRules()) != 1 || got.GetDenyRules()[0].GetCidr() != "9.9.9.9/32" {
		t.Fatalf("deny rule did not persist: %+v", got.GetDenyRules())
	}

	// A subsequent `set` (allow-policy change) must preserve the deny rule.
	if err := s.Set(ctx, &pb.NetworkPolicy{Tenant: "acme", EgressCidrs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("Set #2: %v", err)
	}
	got, _ = s.Get(ctx, "acme")
	if len(got.GetDenyRules()) != 1 {
		t.Fatalf("set wiped deny rules; want them preserved, got %+v", got.GetDenyRules())
	}
	if len(got.GetEgressCidrs()) != 1 || got.GetEgressCidrs()[0] != "10.0.0.0/8" {
		t.Errorf("set should have updated the allow-list: %+v", got.GetEgressCidrs())
	}
}

// TestEncodeDecodeDenyRules round-trips the JSONB persistence shape.
func TestEncodeDecodeDenyRules(t *testing.T) {
	in := []*pb.NetworkPolicyDenyRule{
		{Cidr: "1.2.3.4/32", Port: 6379, Proto: "tcp", Note: "CVE-1", ExpiresAt: "2026-07-01T00:00:00Z"},
		{Cidr: "10.0.0.0/8"},
	}
	b, err := encodeDenyRules(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := decodeDenyRules(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 2 || out[0].GetCidr() != "1.2.3.4/32" || out[0].GetPort() != 6379 || out[0].GetProto() != "tcp" || out[0].GetExpiresAt() != "2026-07-01T00:00:00Z" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	// Empty/`[]`/nil all decode to nil (no rules).
	for _, b := range [][]byte{nil, []byte("[]"), []byte("")} {
		if got, err := decodeDenyRules(b); err != nil || got != nil {
			t.Errorf("decodeDenyRules(%q) = (%v, %v), want (nil, nil)", b, got, err)
		}
	}
}
