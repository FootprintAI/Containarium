package server

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3131: while the network-policy store is the in-memory fallback (Postgres
// configured but unreachable at startup), operator mutations are refused at
// the API boundary so nothing is silently lost on restart. Reads still work,
// and the daemon's own in-process writers keep writing to memory.

const degradedMsg = "network-policy store is degraded: running on the in-memory fallback (Postgres unavailable at startup); nothing was changed"

// newDegradedNPServer is a server on the in-memory fallback, with one policy
// and one signature already in it so reads and deletes have something to hit.
func newDegradedNPServer(t *testing.T) *NetworkPolicyServer {
	t.Helper()
	s := newNPServer()
	s.SetSignatureStore(NewMemNetworkPolicySignatureStore())
	ctx := npAdminCtx()
	if _, err := s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "alice"}}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	// Set never writes deny rules (MutateDenyRules owns them, #660).
	if _, err := s.PatchNetworkPolicyDenyRules(ctx, &pb.PatchNetworkPolicyDenyRulesRequest{
		Tenant: "alice", Add: []*pb.NetworkPolicyDenyRule{{Cidr: "9.9.9.9/32"}},
	}); err != nil {
		t.Fatalf("seed deny rule: %v", err)
	}
	if _, err := s.SetNetworkPolicySignature(ctx, &pb.SetNetworkPolicySignatureRequest{Signature: &pb.NetworkPolicySignature{
		Name: "sig1", Pattern: "evil", Enabled: true,
	}}); err != nil {
		t.Fatalf("seed signature: %v", err)
	}
	s.SetDurable(false)
	return s
}

// degradedMutations is every operator write the decision on #3131 gates.
func degradedMutations() []struct {
	name string
	call func(context.Context, *NetworkPolicyServer) error
} {
	return []struct {
		name string
		call func(context.Context, *NetworkPolicyServer) error
	}{
		{"SetNetworkPolicy", func(ctx context.Context, s *NetworkPolicyServer) error {
			_, err := s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "bob"}})
			return err
		}},
		{"PatchNetworkPolicyDenyRules", func(ctx context.Context, s *NetworkPolicyServer) error {
			_, err := s.PatchNetworkPolicyDenyRules(ctx, &pb.PatchNetworkPolicyDenyRulesRequest{
				Tenant: "alice", Add: []*pb.NetworkPolicyDenyRule{{Cidr: "8.8.8.8/32"}},
			})
			return err
		}},
		{"DeleteNetworkPolicy", func(ctx context.Context, s *NetworkPolicyServer) error {
			_, err := s.DeleteNetworkPolicy(ctx, &pb.DeleteNetworkPolicyRequest{Tenant: "alice"})
			return err
		}},
		{"SetNetworkPolicySignature", func(ctx context.Context, s *NetworkPolicyServer) error {
			_, err := s.SetNetworkPolicySignature(ctx, &pb.SetNetworkPolicySignatureRequest{Signature: &pb.NetworkPolicySignature{
				Name: "sig2", Pattern: "bad", Enabled: true,
			}})
			return err
		}},
		{"DeleteNetworkPolicySignature", func(ctx context.Context, s *NetworkPolicyServer) error {
			_, err := s.DeleteNetworkPolicySignature(ctx, &pb.DeleteNetworkPolicySignatureRequest{Name: "sig1"})
			return err
		}},
	}
}

func TestNetworkPolicy_DegradedRejectsMutationsAndChangesNothing(t *testing.T) {
	for _, m := range degradedMutations() {
		t.Run(m.name, func(t *testing.T) {
			s := newDegradedNPServer(t)
			ctx := npAdminCtx()
			err := m.call(ctx, s)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("code = %v (err %v), want Unavailable", status.Code(err), err)
			}
			if got := status.Convert(err).Message(); got != degradedMsg {
				t.Errorf("message = %q, want %q", got, degradedMsg)
			}

			// Nothing was changed: the seeded policy and signature are intact
			// and the would-be new ones do not exist.
			list, lerr := s.ListNetworkPolicies(ctx, &pb.ListNetworkPoliciesRequest{})
			if lerr != nil {
				t.Fatalf("ListNetworkPolicies while degraded: %v", lerr)
			}
			if len(list.GetPolicies()) != 1 || list.GetPolicies()[0].GetTenant() != "alice" {
				t.Errorf("policies changed: %v", list.GetPolicies())
			}
			if rules := list.GetPolicies()[0].GetDenyRules(); len(rules) != 1 || rules[0].GetCidr() != "9.9.9.9/32" {
				t.Errorf("deny rules changed: %v", rules)
			}
			sigs, serr := s.ListNetworkPolicySignatures(ctx, &pb.ListNetworkPolicySignaturesRequest{})
			if serr != nil {
				t.Fatalf("ListNetworkPolicySignatures while degraded: %v", serr)
			}
			if len(sigs.GetSignatures()) != 1 || sigs.GetSignatures()[0].GetName() != "sig1" {
				t.Errorf("signatures changed: %v", sigs.GetSignatures())
			}
		})
	}
}

// The admin check still comes first: a non-admin caller learns nothing about
// the store's state.
func TestNetworkPolicy_DegradedStillChecksAuthFirst(t *testing.T) {
	s := newDegradedNPServer(t)
	_, err := s.SetNetworkPolicy(context.Background(), &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "bob"}})
	if c := status.Code(err); c == codes.Unavailable || c == codes.OK {
		t.Fatalf("unauthenticated caller got %v, want an auth error", c)
	}
}

func TestNetworkPolicy_DegradedReadsStillWork(t *testing.T) {
	s := newDegradedNPServer(t)
	ctx := npAdminCtx()
	got, err := s.GetNetworkPolicy(ctx, &pb.GetNetworkPolicyRequest{Tenant: "alice"})
	if err != nil || got.GetPolicy().GetTenant() != "alice" {
		t.Fatalf("GetNetworkPolicy while degraded: %v, %v", got, err)
	}
	if _, err := s.ListNetworkPolicies(ctx, &pb.ListNetworkPoliciesRequest{}); err != nil {
		t.Fatalf("ListNetworkPolicies while degraded: %v", err)
	}
	if _, err := s.ListNetworkPolicySignatures(ctx, &pb.ListNetworkPolicySignaturesRequest{}); err != nil {
		t.Fatalf("ListNetworkPolicySignatures while degraded: %v", err)
	}
	if _, err := s.GetNetworkPolicyStatus(ctx, &pb.GetNetworkPolicyStatusRequest{Tenant: "alice"}); err != nil {
		t.Fatalf("GetNetworkPolicyStatus while degraded: %v", err)
	}
}

// A server with a durable store accepts every mutation (the default, and the
// no-Postgres configuration where the in-memory store IS the store).
func TestNetworkPolicy_DurableAcceptsMutations(t *testing.T) {
	for _, m := range degradedMutations() {
		t.Run(m.name, func(t *testing.T) {
			s := newDegradedNPServer(t)
			s.SetDurable(true)
			if err := m.call(npAdminCtx(), s); err != nil {
				t.Fatalf("durable store rejected %s: %v", m.name, err)
			}
		})
	}
}

func TestNetworkPolicy_NewServerIsDurable(t *testing.T) {
	if !NewNetworkPolicyServer(NewMemNetworkPolicyStore()).Durable() {
		t.Fatal("a new server should be durable until told otherwise")
	}
}

// Attaching the durable store on the same live server ends the rejection: the
// flag is read on every call, not captured at construction.
func TestNetworkPolicy_InstallDurableStoreEndsRejectionWithoutRestart(t *testing.T) {
	s := newDegradedNPServer(t)
	ctx := npAdminCtx()
	req := &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "bob"}}
	if _, err := s.SetNetworkPolicy(ctx, req); status.Code(err) != codes.Unavailable {
		t.Fatalf("before attach: code = %v, want Unavailable", status.Code(err))
	}
	if s.Durable() {
		t.Fatal("degraded server reports Durable() = true")
	}

	durable := NewMemNetworkPolicyStore() // stands in for the Postgres store
	s.InstallDurableStore(durable)

	if !s.Durable() {
		t.Fatal("InstallDurableStore did not flip Durable()")
	}
	if s.Store() != NetworkPolicyStore(durable) {
		t.Fatal("InstallDurableStore did not install the store")
	}
	if _, err := s.SetNetworkPolicy(ctx, req); err != nil {
		t.Fatalf("after attach: %v", err)
	}
	if _, err := durable.Get(ctx, "bob"); err != nil {
		t.Fatalf("write did not reach the attached store: %v", err)
	}
}

// The decision on #3131 keeps the daemon's own writers live while degraded:
// rejecting them would drop an enforcement effect (a quarantined tenant's
// egress block, an agent box's egress restriction) for the whole window.
func TestNetworkPolicy_DegradedInProcessWritersNotRejected(t *testing.T) {
	ctx := context.Background()

	t.Run("cloud policy sync", func(t *testing.T) {
		s := newDegradedNPServer(t)
		if err := newCloudPolicySink(s).SyncNetworkPolicies(ctx, []*cloudv1.NetworkPolicy{{OrgId: "org-1"}}); err != nil {
			t.Fatalf("cloud sync rejected while degraded: %v", err)
		}
		if _, err := s.Store().Get(ctx, "org-1"); err != nil {
			t.Fatalf("cloud policy not in the fallback store: %v", err)
		}
	})

	t.Run("agent-skill launch policy", func(t *testing.T) {
		s := newDegradedNPServer(t)
		p := &pb.NetworkPolicy{
			Tenant:    "agent-tenant",
			DenyRules: []*pb.NetworkPolicyDenyRule{{Cidr: "10.0.0.5/32", Note: a2aDenyNote}},
		}
		if err := storeAgentSkillPolicy(ctx, s.Store(), p); err != nil {
			t.Fatalf("agent-skill policy rejected while degraded: %v", err)
		}
		got, err := s.Store().Get(ctx, "agent-tenant")
		if err != nil || len(got.GetDenyRules()) != 1 {
			t.Fatalf("agent-skill policy not in the fallback store: %v, %v", got, err)
		}
	})

	t.Run("auto-quarantine", func(t *testing.T) {
		s := newDegradedNPServer(t)
		NewAutoQuarantine(s.Store()).OnScanResult("alice-box", "alice", "infected")
		got, err := s.Store().Get(ctx, "alice")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		found := false
		for _, r := range got.GetDenyRules() {
			if r.GetCidr() == quarantineCIDR && strings.Contains(r.GetNote(), "quarantine") {
				found = true
			}
		}
		if !found {
			t.Fatalf("quarantine deny rule not written while degraded: %v", got.GetDenyRules())
		}
	})
}
