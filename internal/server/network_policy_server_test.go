package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func npAdminCtx() context.Context {
	return auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
}

func newNPServer() *NetworkPolicyServer {
	return NewNetworkPolicyServer(NewMemNetworkPolicyStore())
}

func TestNetworkPolicy_SetNormalizesAndRoundTrips(t *testing.T) {
	s := newNPServer()
	ctx := npAdminCtx()

	set, err := s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{
		Tenant:           "alice",
		AllowIntraTenant: true,
		EgressCidrs:      []string{"1.2.3.4/24", "10.0.0.0/8", "1.2.3.4/24"}, // non-network + dup
		EgressDomains:    []string{"API.github.com", "api.github.com."},
		// mode unspecified → should normalize to LOG_ONLY
	}})
	if err != nil {
		t.Fatalf("SetNetworkPolicy: %v", err)
	}
	p := set.GetPolicy()
	if len(p.GetEgressCidrs()) != 2 || p.GetEgressCidrs()[0] != "1.2.3.0/24" {
		t.Errorf("CIDRs not normalized/deduped: %v", p.GetEgressCidrs())
	}
	if len(p.GetEgressDomains()) != 1 || p.GetEgressDomains()[0] != "api.github.com" {
		t.Errorf("domains not normalized/deduped: %v", p.GetEgressDomains())
	}
	if p.GetMode() != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY {
		t.Errorf("mode should default to LOG_ONLY, got %v", p.GetMode())
	}

	got, err := s.GetNetworkPolicy(ctx, &pb.GetNetworkPolicyRequest{Tenant: "alice"})
	if err != nil {
		t.Fatalf("GetNetworkPolicy: %v", err)
	}
	if got.GetPolicy().GetTenant() != "alice" || !got.GetPolicy().GetAllowIntraTenant() {
		t.Errorf("round-trip mismatch: %+v", got.GetPolicy())
	}
}

func TestNetworkPolicy_SetRejectsInvalid(t *testing.T) {
	s := newNPServer()
	_, err := s.SetNetworkPolicy(npAdminCtx(), &pb.SetNetworkPolicyRequest{
		Policy: &pb.NetworkPolicy{Tenant: "alice", EgressCidrs: []string{"not-a-cidr"}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for bad CIDR, got %v", err)
	}
}

func TestNetworkPolicy_GetNotFound(t *testing.T) {
	s := newNPServer()
	_, err := s.GetNetworkPolicy(npAdminCtx(), &pb.GetNetworkPolicyRequest{Tenant: "ghost"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestNetworkPolicy_ListAndDelete(t *testing.T) {
	s := newNPServer()
	ctx := npAdminCtx()
	for _, tn := range []string{"bob", "alice"} {
		if _, err := s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: tn}}); err != nil {
			t.Fatalf("Set %s: %v", tn, err)
		}
	}
	list, err := s.ListNetworkPolicies(ctx, &pb.ListNetworkPoliciesRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.GetPolicies()) != 2 || list.GetPolicies()[0].GetTenant() != "alice" {
		t.Errorf("expected sorted [alice, bob], got %v", list.GetPolicies())
	}

	if _, err := s.DeleteNetworkPolicy(ctx, &pb.DeleteNetworkPolicyRequest{Tenant: "alice"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Idempotent: deleting again is fine.
	if _, err := s.DeleteNetworkPolicy(ctx, &pb.DeleteNetworkPolicyRequest{Tenant: "alice"}); err != nil {
		t.Fatalf("Delete (2nd) should be idempotent: %v", err)
	}
	if _, err := s.GetNetworkPolicy(ctx, &pb.GetNetworkPolicyRequest{Tenant: "alice"}); status.Code(err) != codes.NotFound {
		t.Errorf("alice should be gone, got %v", err)
	}
}

func TestNetworkPolicy_PatchDenyRules(t *testing.T) {
	s := newNPServer()
	ctx := npAdminCtx()

	// Add to a tenant with no prior policy: the patch creates a minimal policy.
	res, err := s.PatchNetworkPolicyDenyRules(ctx, &pb.PatchNetworkPolicyDenyRulesRequest{
		Tenant: "acme",
		Add:    []*pb.NetworkPolicyDenyRule{{Cidr: "1.2.3.4", Port: 6379, Proto: "tcp", Note: "CVE-x"}},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	rules := res.GetPolicy().GetDenyRules()
	if len(rules) != 1 || rules[0].GetCidr() != "1.2.3.4/32" || rules[0].GetPort() != 6379 {
		t.Fatalf("add result wrong (host should normalize to /32): %+v", rules)
	}

	// Re-adding the same CIDR replaces it (CIDR-keyed), so count stays 1.
	res, err = s.PatchNetworkPolicyDenyRules(ctx, &pb.PatchNetworkPolicyDenyRulesRequest{
		Tenant: "acme",
		Add:    []*pb.NetworkPolicyDenyRule{{Cidr: "1.2.3.4/32", Port: 443, Note: "CVE-y"}},
	})
	if err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if rs := res.GetPolicy().GetDenyRules(); len(rs) != 1 || rs[0].GetPort() != 443 {
		t.Fatalf("re-add same CIDR should replace, got %+v", rs)
	}

	// The allow-policy survives a deny patch (and vice versa): set an allow-list,
	// then patch — both must coexist.
	if _, err := s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "acme", EgressCidrs: []string{"0.0.0.0/0"}}}); err != nil {
		t.Fatalf("set allow-list: %v", err)
	}
	got, _ := s.GetNetworkPolicy(ctx, &pb.GetNetworkPolicyRequest{Tenant: "acme"})
	if len(got.GetPolicy().GetDenyRules()) != 1 || len(got.GetPolicy().GetEgressCidrs()) != 1 {
		t.Fatalf("allow-list and deny rule should coexist: %+v", got.GetPolicy())
	}

	// Remove by bare host (must match the stored /32).
	res, err = s.PatchNetworkPolicyDenyRules(ctx, &pb.PatchNetworkPolicyDenyRulesRequest{Tenant: "acme", RemoveCidrs: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(res.GetPolicy().GetDenyRules()) != 0 {
		t.Fatalf("remove should empty the deny rules, got %+v", res.GetPolicy().GetDenyRules())
	}

	// Removing a rule that isn't there → NotFound (pure removal).
	if _, err := s.PatchNetworkPolicyDenyRules(ctx, &pb.PatchNetworkPolicyDenyRulesRequest{Tenant: "acme", RemoveCidrs: []string{"9.9.9.9/32"}}); status.Code(err) != codes.NotFound {
		t.Fatalf("removing a missing rule should be NotFound, got %v", err)
	}

	// An invalid add rule → InvalidArgument, store untouched.
	if _, err := s.PatchNetworkPolicyDenyRules(ctx, &pb.PatchNetworkPolicyDenyRulesRequest{Tenant: "acme", Add: []*pb.NetworkPolicyDenyRule{{Cidr: "not-a-cidr"}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad add cidr should be InvalidArgument, got %v", err)
	}

	// Empty patch → InvalidArgument.
	if _, err := s.PatchNetworkPolicyDenyRules(ctx, &pb.PatchNetworkPolicyDenyRulesRequest{Tenant: "acme"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty patch should be InvalidArgument, got %v", err)
	}
}

func TestNetworkPolicy_PatchDenyRulesAdminOnly(t *testing.T) {
	s := newNPServer()
	userCtx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	_, err := s.PatchNetworkPolicyDenyRules(userCtx, &pb.PatchNetworkPolicyDenyRulesRequest{Tenant: "acme", Add: []*pb.NetworkPolicyDenyRule{{Cidr: "1.2.3.4/32"}}})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("non-admin patch should be PermissionDenied, got %v", err)
	}
}

func TestNetworkPolicy_AdminOnly(t *testing.T) {
	s := newNPServer()
	userCtx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	for _, call := range []func() error{
		func() error {
			_, e := s.SetNetworkPolicy(userCtx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "alice"}})
			return e
		},
		func() error {
			_, e := s.GetNetworkPolicy(userCtx, &pb.GetNetworkPolicyRequest{Tenant: "alice"})
			return e
		},
		func() error { _, e := s.ListNetworkPolicies(userCtx, &pb.ListNetworkPoliciesRequest{}); return e },
		func() error {
			_, e := s.DeleteNetworkPolicy(userCtx, &pb.DeleteNetworkPolicyRequest{Tenant: "alice"})
			return e
		},
	} {
		if err := call(); status.Code(err) != codes.PermissionDenied {
			t.Errorf("non-admin should get PermissionDenied, got %v", err)
		}
	}
}
