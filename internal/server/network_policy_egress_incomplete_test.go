package server

import (
	"fmt"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeEgressApplier records AddEgress/DeleteEgress calls and fails the ones
// listed, so applyEgress's apply/report/retry semantics are testable without a
// kernel.
type fakeEgressApplier struct {
	failAdd map[netbpf.EgressEntry]bool
	failDel map[netbpf.EgressEntry]bool
}

func (f *fakeEgressApplier) AddEgress(e netbpf.EgressEntry) error {
	if f.failAdd[e] {
		return fmt.Errorf("inject add failure")
	}
	return nil
}

func (f *fakeEgressApplier) DeleteEgress(e netbpf.EgressEntry) error {
	if f.failDel[e] {
		return fmt.Errorf("inject delete failure")
	}
	return nil
}

func egressEntry(tenant uint32, last byte) netbpf.EgressEntry {
	return netbpf.EgressEntry{PrefixLen: 32 + 32, TenantID: tenant, Addr: [4]byte{10, 0, 0, last}}
}

// #2983: a failed allow-list write must be attributed to its tenant, left out
// of the installed set so the next pass retries it, and must not touch another
// tenant.
func TestApplyEgress_ReportsTheTenantOfAFailedEntry(t *testing.T) {
	a1, a2, b1 := egressEntry(1, 1), egressEntry(1, 2), egressEntry(2, 1)
	installed := map[netbpf.EgressEntry]bool{}
	f := &fakeEgressApplier{failAdd: map[netbpf.EgressEntry]bool{a2: true}}

	incomplete := applyEgress(installed, []netbpf.EgressEntry{a1, a2, b1}, nil, f)

	if !incomplete[1] {
		t.Errorf("tenant 1 had an entry fail but is not reported incomplete: %v", incomplete)
	}
	if incomplete[2] {
		t.Errorf("tenant 2 had no failure but is reported incomplete: %v", incomplete)
	}
	if installed[a2] {
		t.Error("the failed entry was recorded as installed, so it would never be retried")
	}
	if !installed[a1] || !installed[b1] {
		t.Errorf("the entries that succeeded must be recorded as installed: %v", installed)
	}

	// The next pass retries the failed entry and, once it lands, reports clean.
	f.failAdd = nil
	incomplete = applyEgress(installed, []netbpf.EgressEntry{a2}, nil, f)
	if len(incomplete) != 0 || !installed[a2] {
		t.Errorf("after the retry succeeds: incomplete=%v installed[a2]=%v", incomplete, installed[a2])
	}
}

// A removal that fails leaves a destination allowed that the policy no longer
// allows (worse than a missing entry in enforce mode), so it is reported too.
func TestApplyEgress_ReportsTheTenantOfAFailedRemoval(t *testing.T) {
	gone, kept := egressEntry(1, 9), egressEntry(2, 9)
	installed := map[netbpf.EgressEntry]bool{gone: true, kept: true}
	f := &fakeEgressApplier{failDel: map[netbpf.EgressEntry]bool{gone: true}}

	incomplete := applyEgress(installed, nil, []netbpf.EgressEntry{gone, kept}, f)

	if !incomplete[1] || incomplete[2] {
		t.Errorf("incomplete = %v, want only tenant 1", incomplete)
	}
	if !installed[gone] {
		t.Error("an entry that could not be removed must stay recorded so the next pass retries it")
	}
	if installed[kept] {
		t.Error("an entry that was removed must leave the installed set")
	}
}

// The pass result reaches the per-tenant applied state, and only for the
// tenants named.
func TestAppliedFromPass_MarksEgressIncomplete(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{
		"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme"}),
		"bob":  compiled(t, &pb.NetworkPolicy{Tenant: "bob"}),
	}
	views := []containerView{
		{Name: "acme-a", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true},
		{Name: "bob-a", Tenant: "bob", TenantID: 2, Ifindex: 21, HasVeth: true, Running: true},
	}
	plan := planReconcile(views, policies, true)
	loaded := map[int]bool{11: true, 21: true}

	got := appliedFromPass(views, plan, loaded, policies, map[uint32]bool{1: true}, map[uint32]string{1: "acme"})

	if !got["acme"].EgressIncomplete {
		t.Errorf("acme = %+v, want EgressIncomplete", got["acme"])
	}
	if got["bob"].EgressIncomplete {
		t.Errorf("bob = %+v, must not be marked", got["bob"])
	}
}

// The status says so: the tenant's boxes are loaded, but the allow-list in the
// kernel is not what the policy says, and the uncovered path names that.
func TestBuildPolicyStatus_EgressIncompleteIsAnUncoveredPath(t *testing.T) {
	const incomplete = pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_EGRESS_ALLOWLIST_INCOMPLETE
	has := func(st *pb.NetworkPolicyStatus) bool {
		for _, p := range st.GetUncoveredPaths() {
			if p == incomplete {
				return true
			}
		}
		return false
	}
	base := tenantApplied{Mode: netbpf.ModeEnforce, BoxesLoaded: 1}

	bad := base
	bad.EgressIncomplete = true
	st := npStatusFor(t, fakeAppliedSource{fresh(bad)}, true, "acme")
	if !has(st) {
		t.Errorf("uncovered paths = %v, want %v", st.GetUncoveredPaths(), incomplete)
	}
	if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED {
		t.Errorf("state = %v: the boxes are loaded, the gap is reported as an uncovered path", st.GetState())
	}

	if st := npStatusFor(t, fakeAppliedSource{fresh(base)}, true, "acme"); has(st) {
		t.Errorf("a complete allow-list must not report %v: %v", incomplete, st.GetUncoveredPaths())
	}
}
