package netpolicy

import (
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestCompile_DenyRules_OK(t *testing.T) {
	got, err := Compile(&pb.NetworkPolicy{
		Tenant: "alice",
		DenyRules: []*pb.NetworkPolicyDenyRule{
			{Cidr: "1.2.3.4", Port: 6379, Proto: "TCP", Note: "CVE-2024-0001"}, // bare host → /32, proto upper-cased
			{Cidr: "10.0.0.0/8"}, // CIDR, any port/proto
			{Cidr: "1.2.3.4", Port: 6379, Proto: "tcp", Note: "dup-key-wins"}, // same (cidr,port,proto) → dedup
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// 3 input rules, two share a (cidr,port,proto) key → 2 unique.
	if len(got.DenyRules) != 2 {
		t.Fatalf("want 2 deny rules, got %d: %+v", len(got.DenyRules), got.DenyRules)
	}
	// Sorted by CIDR string: "1.2.3.4/32" < "10.0.0.0/8".
	r0, r1 := got.DenyRules[0], got.DenyRules[1]
	if r0.CIDR.String() != "1.2.3.4/32" {
		t.Errorf("rule0 cidr = %s, want 1.2.3.4/32", r0.CIDR)
	}
	if r0.Port != 6379 || r0.Proto != 6 {
		t.Errorf("rule0 port/proto = %d/%d, want 6379/6", r0.Port, r0.Proto)
	}
	if r0.Note != "dup-key-wins" {
		t.Errorf("rule0 note = %q, want the later duplicate's note", r0.Note)
	}
	if r1.CIDR.String() != "10.0.0.0/8" || r1.Port != 0 || r1.Proto != 0 {
		t.Errorf("rule1 = %+v, want 10.0.0.0/8 any/any", r1)
	}
}

func TestCompile_DenyRules_Errors(t *testing.T) {
	cases := []struct {
		name string
		rule *pb.NetworkPolicyDenyRule
		want string
	}{
		{"empty cidr", &pb.NetworkPolicyDenyRule{Cidr: "  "}, "cidr is required"},
		{"bad cidr", &pb.NetworkPolicyDenyRule{Cidr: "nope"}, "invalid deny address"},
		{"bad prefix", &pb.NetworkPolicyDenyRule{Cidr: "10.0.0.0/40"}, "invalid deny cidr"},
		{"port range", &pb.NetworkPolicyDenyRule{Cidr: "1.1.1.1", Port: 70000}, "out of range"},
		{"bad proto", &pb.NetworkPolicyDenyRule{Cidr: "1.1.1.1", Proto: "sctp"}, "unknown deny proto"},
		{"bad expiry", &pb.NetworkPolicyDenyRule{Cidr: "1.1.1.1", ExpiresAt: "soon"}, "expires_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(&pb.NetworkPolicy{Tenant: "t", DenyRules: []*pb.NetworkPolicyDenyRule{tc.rule}})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestDenyRule_Expired(t *testing.T) {
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	past := DenyRule{ExpiresAt: now.Add(-time.Hour)}
	future := DenyRule{ExpiresAt: now.Add(time.Hour)}
	never := DenyRule{} // zero ExpiresAt

	if !past.Expired(now) {
		t.Error("past rule should be expired")
	}
	if future.Expired(now) {
		t.Error("future rule should not be expired")
	}
	if never.Expired(now) {
		t.Error("rule with no expiry should never be expired")
	}
}

func TestCompile_DenyRules_ExpiryPreserved(t *testing.T) {
	// Compile is time-pure: an already-expired rule still compiles (the daemon,
	// not this layer, drops it). ExpiresAt must round-trip.
	got, err := Compile(&pb.NetworkPolicy{
		Tenant:    "t",
		DenyRules: []*pb.NetworkPolicyDenyRule{{Cidr: "9.9.9.9/32", ExpiresAt: "2020-01-01T00:00:00Z"}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(got.DenyRules) != 1 {
		t.Fatalf("want 1 deny rule, got %d", len(got.DenyRules))
	}
	if got.DenyRules[0].ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be preserved by Compile, not zeroed")
	}
	// ToProto round-trips the normalized form.
	rt := got.ToProto()
	if len(rt.GetDenyRules()) != 1 || rt.GetDenyRules()[0].GetCidr() != "9.9.9.9/32" {
		t.Errorf("ToProto deny round-trip wrong: %+v", rt.GetDenyRules())
	}
	if rt.GetDenyRules()[0].GetExpiresAt() == "" {
		t.Error("ToProto should render expires_at")
	}
}
