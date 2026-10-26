package server

import (
	"slices"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3051: a failed allow-list write must reach the owning tenant's status even
// when that tenant has no running box. These drive the enforcer's egress step
// with a fake loader (fakeEgressApplier), record the pass the way reconcile
// does, and read the tenant's status through the RPC.

const egressIncompletePath = pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_EGRESS_ALLOWLIST_INCOMPLETE

// egressPass runs one reconcile pass's plan, egress apply and record on e,
// with the egress writes going to f and every planned veth loaded.
func egressPass(t *testing.T, e *NetworkPolicyEnforcer, views []containerView, policies map[string]netpolicy.CompiledPolicy, f *fakeEgressApplier) {
	t.Helper()
	idName := make(map[uint32]string)
	for _, v := range views {
		idName[v.TenantID] = v.Tenant
	}
	plan := planReconcile(views, policies, true)
	loaded := make(map[int]bool, len(plan.vethPolicy))
	for ifindex := range plan.vethPolicy {
		loaded[ifindex] = true
	}
	incomplete, names := e.applyEgressPass(plan, idName, f)
	e.recordApplied(appliedFromPass(views, plan, loaded, policies, incomplete, names), statusNow)
}

// egressTestEnforcer is an enforcer that reports as running (no BPF loaded).
func egressTestEnforcer() *NetworkPolicyEnforcer {
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), nil, nil, nil, true)
	e.running = true
	return e
}

func egressPolicy(t *testing.T, tenant, cidr string) netpolicy.CompiledPolicy {
	return compiled(t, &pb.NetworkPolicy{Tenant: tenant, EgressCidrs: []string{cidr}})
}

func hasEgressIncomplete(st *pb.NetworkPolicyStatus) bool {
	return slices.Contains(st.GetUncoveredPaths(), egressIncompletePath)
}

// A tenant's policy is removed after its last box is gone, and the removal of
// its allow-list entries fails: destinations stay allowed that no policy
// allows. The tenant has no box at all, yet its status must say so.
func TestEgressIncomplete_FailedRemovalWithNoRunningBox(t *testing.T) {
	e := egressTestEnforcer()
	acme := containerView{Name: "acme-a", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}
	bob := containerView{Name: "bob-a", Tenant: "bob", TenantID: 2, Ifindex: 21, HasVeth: true, Running: true}
	policies := map[string]netpolicy.CompiledPolicy{
		"acme": egressPolicy(t, "acme", "192.0.2.0/24"),
		"bob":  egressPolicy(t, "bob", "198.51.100.0/24"),
	}
	f := &fakeEgressApplier{}
	egressPass(t, e, []containerView{acme, bob}, policies, f)

	// acme's box is deleted and its policy removed; every acme entry fails to delete.
	f.failDel = map[netbpf.EgressEntry]bool{}
	for ee := range e.egressInstalled {
		if ee.TenantID == acme.TenantID {
			f.failDel[ee] = true
		}
	}
	if len(f.failDel) == 0 {
		t.Fatal("setup: pass 1 installed no acme allow-list entries")
	}
	delete(policies, "acme")
	egressPass(t, e, []containerView{bob}, policies, f)

	st := npStatusFor(t, e, true, "acme")
	if !hasEgressIncomplete(st) {
		t.Errorf("acme status = %v %v, want %v: its failed removal left destinations allowed", st.GetState(), st.GetUncoveredPaths(), egressIncompletePath)
	}
	if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED {
		t.Errorf("acme state = %v, want NOT_LOADED (no box)", st.GetState())
	}

	// Another tenant's status is unaffected.
	if st := npStatusFor(t, e, true, "bob"); hasEgressIncomplete(st) || st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED {
		t.Errorf("bob status = %v %v, want LOADED with a complete allow-list", st.GetState(), st.GetUncoveredPaths())
	}

	// Once the removal lands the record clears.
	f.failDel = nil
	egressPass(t, e, []containerView{bob}, policies, f)
	if st := npStatusFor(t, e, true, "acme"); hasEgressIncomplete(st) {
		t.Errorf("after the retried removal succeeded acme still reports %v", st.GetUncoveredPaths())
	}
	if _, kept := e.egressNames[acme.TenantID]; kept {
		t.Error("acme's name is still remembered after its last entry was removed (the map must stay bounded)")
	}
}

// A tenant with only stopped boxes still has its allow-list written (the plan
// does not need a running box), so a failed add is real and must be reported.
func TestEgressIncomplete_FailedAddWithOnlyStoppedBoxes(t *testing.T) {
	e := egressTestEnforcer()
	acme := containerView{Name: "acme-a", Tenant: "acme", TenantID: 1, Running: false}
	bob := containerView{Name: "bob-a", Tenant: "bob", TenantID: 2, Ifindex: 21, HasVeth: true, Running: true}
	policies := map[string]netpolicy.CompiledPolicy{
		"acme": egressPolicy(t, "acme", "192.0.2.0/24"),
		"bob":  egressPolicy(t, "bob", "198.51.100.0/24"),
	}
	plan := planReconcile([]containerView{acme, bob}, policies, true)
	f := &fakeEgressApplier{failAdd: map[netbpf.EgressEntry]bool{}}
	for _, ee := range plan.egress {
		if ee.TenantID == acme.TenantID {
			f.failAdd[ee] = true
		}
	}
	if len(f.failAdd) == 0 {
		t.Fatal("setup: the plan writes no allow-list entries for a tenant with only stopped boxes")
	}
	egressPass(t, e, []containerView{acme, bob}, policies, f)

	st := npStatusFor(t, e, true, "acme")
	if !hasEgressIncomplete(st) {
		t.Errorf("acme status = %v %v, want %v", st.GetState(), st.GetUncoveredPaths(), egressIncompletePath)
	}
	if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED {
		t.Errorf("acme state = %v, want NOT_LOADED (no running box)", st.GetState())
	}
	if st.GetBoxesLoaded() != 0 || st.GetBoxesNotLoaded() != 0 {
		t.Errorf("acme boxes loaded/not loaded = %d/%d, want 0/0 (stopped boxes are not counted)", st.GetBoxesLoaded(), st.GetBoxesNotLoaded())
	}
	if st := npStatusFor(t, e, true, "bob"); hasEgressIncomplete(st) || st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED {
		t.Errorf("bob status = %v %v, want LOADED with a complete allow-list", st.GetState(), st.GetUncoveredPaths())
	}
}

// buildPolicyStatus lists the uncovered path for a NOT_LOADED tenant too, and
// not for one whose allow-list is complete.
func TestBuildPolicyStatus_EgressIncompleteWhenNotLoaded(t *testing.T) {
	st := npStatusFor(t, fakeAppliedSource{fresh(tenantApplied{EgressIncomplete: true})}, true, "acme")
	if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED || !hasEgressIncomplete(st) {
		t.Errorf("status = %v %v, want NOT_LOADED with %v", st.GetState(), st.GetUncoveredPaths(), egressIncompletePath)
	}
	if st := npStatusFor(t, fakeAppliedSource{fresh(tenantApplied{})}, true, "acme"); hasEgressIncomplete(st) {
		t.Errorf("a complete allow-list must not report %v: %v", egressIncompletePath, st.GetUncoveredPaths())
	}
}
