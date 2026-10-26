package server

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	stUnset   = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED
	stLogOnly = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
	stEnforce = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
)

// fakeAppliedSource is a canned enforcer view for the RPC tests.
type fakeAppliedSource struct{ snap appliedSnapshot }

func (f fakeAppliedSource) AppliedState(string) appliedSnapshot { return f.snap }

// statusNow is the server clock in the RPC tests and the end of the canned
// reconcile pass, so a snapshot from fresh is never stale.
var statusNow = time.Unix(1700000000, 0)

// fresh is a snapshot of a pass that just completed with tenant's state.
func fresh(a tenantApplied) appliedSnapshot {
	return appliedSnapshot{Running: true, Reconciled: true, Found: true, Tenant: a, ReconciledAt: statusNow, Interval: defaultNetPolicyReconcileInterval}
}

// appliedPass runs one reconcile's plan through appliedFromPass, with every
// planned veth loaded unless listed in failed.
func appliedPass(t *testing.T, views []containerView, policies map[string]netpolicy.CompiledPolicy, armed bool, failed ...int) map[string]tenantApplied {
	t.Helper()
	plan := planReconcile(views, policies, armed)
	loaded := make(map[int]bool, len(plan.vethPolicy))
	for ifindex := range plan.vethPolicy {
		loaded[ifindex] = !slices.Contains(failed, ifindex)
	}
	return appliedFromPass(views, plan, loaded, policies, nil, nil)
}

func npStatusFor(t *testing.T, src appliedStateSource, armed bool, tenant string) *pb.NetworkPolicyStatus {
	t.Helper()
	s := newNPServer()
	s.clock = func() time.Time { return statusNow }
	s.SetEnforcementArmed(armed)
	if src != nil {
		s.SetAppliedStateSource(src)
	}
	resp, err := s.GetNetworkPolicyStatus(npAdminCtx(), &pb.GetNetworkPolicyStatusRequest{Tenant: tenant})
	if err != nil {
		t.Fatalf("GetNetworkPolicyStatus: %v", err)
	}
	return resp.GetStatus()
}

// A requested ENFORCE is reported as what the kernel holds: LOG_ONLY on an
// unarmed host, ENFORCE on an armed one — for both modes.
func TestNetworkPolicyStatus_ArmedVsUnarmedHost(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{
		"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", Mode: stEnforce}),
	}
	views := []containerView{{Name: "acme-container", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}}

	for _, tc := range []struct {
		armed bool
		want  pb.NetworkPolicyMode
	}{{false, stLogOnly}, {true, stEnforce}} {
		applied := appliedPass(t, views, policies, tc.armed)
		st := npStatusFor(t, fakeAppliedSource{fresh(applied["acme"])}, tc.armed, "acme")
		if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED {
			t.Fatalf("armed=%v: state = %v, want LOADED", tc.armed, st.GetState())
		}
		if st.GetEffectiveMode() != tc.want || st.GetEffectiveEgressMode() != tc.want {
			t.Errorf("armed=%v: effective mode=%v egress=%v, want %v for both", tc.armed, st.GetEffectiveMode(), st.GetEffectiveEgressMode(), tc.want)
		}
		if st.GetEnforcementArmed() != tc.armed {
			t.Errorf("armed=%v: enforcement_armed = %v", tc.armed, st.GetEnforcementArmed())
		}
		if st.GetLastReconciledAt().AsTime() != statusNow.UTC() {
			t.Errorf("armed=%v: last_reconciled_at = %v", tc.armed, st.GetLastReconciledAt().AsTime())
		}
		if st.GetBoxesLoaded() != 1 || st.GetBoxesNotLoaded() != 0 {
			t.Errorf("armed=%v: boxes loaded=%d not=%d, want 1/0", tc.armed, st.GetBoxesLoaded(), st.GetBoxesNotLoaded())
		}
	}
}

// The separate egress mode is reported as loaded.
func TestNetworkPolicyStatus_SeparateEgressMode(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{
		"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", Mode: stEnforce, EgressMode: stLogOnly}),
	}
	views := []containerView{{Name: "acme-container", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}}
	applied := appliedPass(t, views, policies, true)
	st := npStatusFor(t, fakeAppliedSource{fresh(applied["acme"])}, true, "acme")
	if st.GetEffectiveMode() != stEnforce || st.GetEffectiveEgressMode() != stLogOnly {
		t.Errorf("effective mode=%v egress=%v, want ENFORCE/LOG_ONLY", st.GetEffectiveMode(), st.GetEffectiveEgressMode())
	}
}

// Nothing applied means unknown modes, never a guess from the stored policy.
func TestNetworkPolicyStatus_UnknownWhenNothingApplied(t *testing.T) {
	cases := []struct {
		name   string
		src    appliedStateSource
		want   pb.NetworkPolicyAppliedState
		wantAt bool // a pass completed, so its time is reported
	}{
		{"no enforcer configured", nil, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING, false},
		{"enforcer not started", fakeAppliedSource{appliedSnapshot{}}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING, false},
		{"no reconcile pass yet", fakeAppliedSource{appliedSnapshot{Running: true}}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_UNSPECIFIED, false},
		{"no box of the tenant loaded", fakeAppliedSource{appliedSnapshot{Running: true, Reconciled: true, ReconciledAt: statusNow, Interval: defaultNetPolicyReconcileInterval}}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newNPServer()
			s.clock = func() time.Time { return statusNow }
			// A stored ENFORCE policy must not leak into the report.
			if _, err := s.SetNetworkPolicy(npAdminCtx(), &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "acme", Mode: stEnforce}}); err != nil {
				t.Fatal(err)
			}
			s.SetEnforcementArmed(true)
			if tc.src != nil {
				s.SetAppliedStateSource(tc.src)
			}
			resp, err := s.GetNetworkPolicyStatus(npAdminCtx(), &pb.GetNetworkPolicyStatusRequest{Tenant: "acme"})
			if err != nil {
				t.Fatal(err)
			}
			st := resp.GetStatus()
			if st.GetState() != tc.want {
				t.Errorf("state = %v, want %v", st.GetState(), tc.want)
			}
			if st.GetEffectiveMode() != stUnset || st.GetEffectiveEgressMode() != stUnset {
				t.Errorf("modes = %v/%v, want UNSPECIFIED (unknown)", st.GetEffectiveMode(), st.GetEffectiveEgressMode())
			}
			if got := st.GetLastReconciledAt() != nil; got != tc.wantAt {
				t.Errorf("last_reconciled_at set = %v, want %v", got, tc.wantAt)
			}
		})
	}
}

// Boxes whose config could not be loaded are counted, not hidden; a tenant
// with none loaded is NOT_LOADED.
func TestAppliedFromPass_CountsBoxesNotLoaded(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme"})}
	views := []containerView{
		{Name: "acme-a", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true},
		{Name: "acme-b", Tenant: "acme", TenantID: 1, Ifindex: 12, HasVeth: true, Running: true}, // attach fails
		{Name: "acme-c", Tenant: "acme", TenantID: 1, Running: true},                             // veth not resolved
		{Name: "acme-d", Tenant: "acme", TenantID: 1},                                            // stopped: not counted
		{Name: "bob-a", Tenant: "bob", TenantID: 2, Ifindex: 21, HasVeth: true, Running: true},   // only box fails
	}
	got := appliedPass(t, views, policies, true, 12, 21)
	if a := got["acme"]; a.BoxesLoaded != 1 || a.BoxesNotLoaded != 2 {
		t.Errorf("acme = %+v, want loaded=1 not_loaded=2", a)
	}
	if b := got["bob"]; b.BoxesLoaded != 0 || b.BoxesNotLoaded != 1 {
		t.Errorf("bob = %+v, want loaded=0 not_loaded=1", b)
	}
	st := npStatusFor(t, fakeAppliedSource{fresh(got["bob"])}, true, "bob")
	if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED || st.GetEffectiveMode() != stUnset {
		t.Errorf("bob status = %v mode %v, want NOT_LOADED/unknown", st.GetState(), st.GetEffectiveMode())
	}
	if st.GetBoxesNotLoaded() != 1 {
		t.Errorf("bob boxes_not_loaded = %d, want 1", st.GetBoxesNotLoaded())
	}
	// acme has 1 of 3 running boxes loaded: partially loaded, never LOADED.
	st = npStatusFor(t, fakeAppliedSource{fresh(got["acme"])}, true, "acme")
	if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_PARTIALLY_LOADED {
		t.Errorf("acme status = %v, want PARTIALLY_LOADED", st.GetState())
	}
}

// LOADED means every running box of the tenant is loaded: 0 of N is
// NOT_LOADED with unknown modes, k of N is PARTIALLY_LOADED with the loaded
// boxes' modes, N of N is LOADED.
func TestNetworkPolicyStatus_LoadedCoverage(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", Mode: stEnforce})}
	views := []containerView{
		{Name: "acme-a", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true},
		{Name: "acme-b", Tenant: "acme", TenantID: 1, Ifindex: 12, HasVeth: true, Running: true},
		{Name: "acme-c", Tenant: "acme", TenantID: 1, Ifindex: 13, HasVeth: true, Running: true},
	}
	for _, tc := range []struct {
		name          string
		failed        []int
		want          pb.NetworkPolicyAppliedState
		wantMode      pb.NetworkPolicyMode
		loaded, notLd uint32
	}{
		{"0 of 3", []int{11, 12, 13}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED, stUnset, 0, 3},
		{"1 of 3", []int{12, 13}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_PARTIALLY_LOADED, stEnforce, 1, 2},
		{"2 of 3", []int{13}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_PARTIALLY_LOADED, stEnforce, 2, 1},
		{"3 of 3", nil, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED, stEnforce, 3, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applied := appliedPass(t, views, policies, true, tc.failed...)
			st := npStatusFor(t, fakeAppliedSource{fresh(applied["acme"])}, true, "acme")
			if st.GetState() != tc.want {
				t.Errorf("state = %v, want %v", st.GetState(), tc.want)
			}
			if st.GetEffectiveMode() != tc.wantMode || st.GetEffectiveEgressMode() != tc.wantMode {
				t.Errorf("modes = %v/%v, want %v", st.GetEffectiveMode(), st.GetEffectiveEgressMode(), tc.wantMode)
			}
			if st.GetBoxesLoaded() != tc.loaded || st.GetBoxesNotLoaded() != tc.notLd {
				t.Errorf("boxes = %d/%d, want %d/%d", st.GetBoxesLoaded(), st.GetBoxesNotLoaded(), tc.loaded, tc.notLd)
			}
		})
	}
}

// A reconciler whose passes keep failing leaves its last record in place; past
// three reconcile intervals the status is STALE with unknown modes and counts,
// but the time of the last good pass stays visible.
func TestNetworkPolicyStatus_StaleReconciler(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", Mode: stEnforce})}
	views := []containerView{{Name: "acme-a", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}}
	applied := appliedPass(t, views, policies, true)["acme"]
	threshold := staleAfterPasses * defaultNetPolicyReconcileInterval

	for _, tc := range []struct {
		name     string
		age      time.Duration
		interval time.Duration
		want     pb.NetworkPolicyAppliedState
	}{
		{"fresh", 0, defaultNetPolicyReconcileInterval, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED},
		{"at the threshold", threshold, defaultNetPolicyReconcileInterval, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED},
		{"past the threshold", threshold + time.Second, defaultNetPolicyReconcileInterval, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_STALE},
		{"hours old", 3 * time.Hour, defaultNetPolicyReconcileInterval, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_STALE},
		// The threshold follows the enforcer's actual interval.
		{"slow interval, same age", threshold + time.Second, time.Minute, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := statusNow.Add(-tc.age)
			snap := appliedSnapshot{Running: true, Reconciled: true, Found: true, Tenant: applied, ReconciledAt: at, Interval: tc.interval}
			st := npStatusFor(t, fakeAppliedSource{snap}, true, "acme")
			if st.GetState() != tc.want {
				t.Fatalf("state = %v, want %v", st.GetState(), tc.want)
			}
			if st.GetLastReconciledAt().AsTime() != at.UTC() {
				t.Errorf("last_reconciled_at = %v, want %v", st.GetLastReconciledAt().AsTime(), at.UTC())
			}
			if tc.want != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_STALE {
				if st.GetEffectiveMode() != stEnforce {
					t.Errorf("fresh: effective mode = %v, want ENFORCE", st.GetEffectiveMode())
				}
				return
			}
			if st.GetEffectiveMode() != stUnset || st.GetEffectiveEgressMode() != stUnset {
				t.Errorf("stale: modes = %v/%v, want UNSPECIFIED (unknown)", st.GetEffectiveMode(), st.GetEffectiveEgressMode())
			}
			if st.GetBoxesLoaded() != 0 || st.GetBoxesNotLoaded() != 0 {
				t.Errorf("stale: boxes = %d/%d, want unset", st.GetBoxesLoaded(), st.GetBoxesNotLoaded())
			}
		})
	}
}

// IPv6 is always uncovered; domain refresh lag only when the loaded policy has
// domain entries.
func TestNetworkPolicyStatus_UncoveredPaths(t *testing.T) {
	views := []containerView{{Name: "acme-container", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}}
	ipv6 := pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_IPV6
	lag := pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG

	plain := appliedPass(t, views, map[string]netpolicy.CompiledPolicy{"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", EgressCidrs: []string{"192.0.2.0/24"}})}, true)
	st := npStatusFor(t, fakeAppliedSource{fresh(plain["acme"])}, true, "acme")
	if got := st.GetUncoveredPaths(); !slices.Equal(got, []pb.NetworkPolicyUncoveredPath{ipv6}) {
		t.Errorf("no domains: uncovered = %v, want [IPV6]", got)
	}

	doms := appliedPass(t, views, map[string]netpolicy.CompiledPolicy{"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", EgressDomains: []string{"example.com"}})}, true)
	st = npStatusFor(t, fakeAppliedSource{fresh(doms["acme"])}, true, "acme")
	if got := st.GetUncoveredPaths(); !slices.Equal(got, []pb.NetworkPolicyUncoveredPath{ipv6, lag}) {
		t.Errorf("with domains: uncovered = %v, want [IPV6 DOMAIN_REFRESH_LAG]", got)
	}

	// Not running: IPv6 is still a fact about the program; nothing loaded has domains.
	st = npStatusFor(t, nil, false, "acme")
	if got := st.GetUncoveredPaths(); !slices.Equal(got, []pb.NetworkPolicyUncoveredPath{ipv6}) {
		t.Errorf("enforcer off: uncovered = %v, want [IPV6]", got)
	}
}

func TestNetworkPolicyStatus_Errors(t *testing.T) {
	s := newNPServer()
	userCtx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := s.GetNetworkPolicyStatus(userCtx, &pb.GetNetworkPolicyStatusRequest{Tenant: "alice"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("non-admin: %v, want PermissionDenied", err)
	}
	if _, err := s.GetNetworkPolicyStatus(npAdminCtx(), &pb.GetNetworkPolicyStatusRequest{Tenant: " "}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty tenant: %v, want InvalidArgument", err)
	}
}

// The enforcer reports not-running until Start has loaded the program, then
// answers from the last pass's applied map only.
func TestNetworkPolicyEnforcer_AppliedState(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, nil, nil, nil, nil, false)
	if snap := e.AppliedState("acme"); snap.Running || snap.Reconciled || snap.Found {
		t.Fatalf("unstarted enforcer = %+v, want all false", snap)
	}
	e.mu.Lock()
	e.running = true
	e.mu.Unlock()
	if snap := e.AppliedState("acme"); !snap.Running || snap.Reconciled {
		t.Fatalf("started, no pass = %+v, want running and not reconciled", snap)
	}
	e.recordApplied(map[string]tenantApplied{"acme": {Mode: 2, EgressMode: 1, BoxesLoaded: 1}}, statusNow)
	if snap := e.AppliedState("acme"); !snap.Reconciled || !snap.Found || snap.Tenant.Mode != 2 || snap.Tenant.EgressMode != 1 {
		t.Errorf("after a pass = %+v", snap)
	}
	snap := e.AppliedState("other")
	if !snap.Reconciled || snap.Found {
		t.Errorf("unknown tenant after a pass = %+v, want reconciled and not found", snap)
	}
	if !snap.ReconciledAt.Equal(statusNow) || snap.Interval != defaultNetPolicyReconcileInterval {
		t.Errorf("pass time/interval = %v/%v, want %v/%v", snap.ReconciledAt, snap.Interval, statusNow, defaultNetPolicyReconcileInterval)
	}
}

// Stop drops the last run's record, so a later Start reports "not reconciled"
// until its own first pass instead of the previous run's state.
func TestNetworkPolicyEnforcer_StopClearsApplied(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, nil, nil, nil, nil, false)
	e.mu.Lock()
	e.running = true
	e.mu.Unlock()
	e.recordApplied(map[string]tenantApplied{"acme": {Mode: 2, BoxesLoaded: 1}}, statusNow)
	e.Stop()
	e.mu.Lock()
	e.running = true // a later Start, before its first pass
	e.mu.Unlock()
	if snap := e.AppliedState("acme"); snap.Reconciled || snap.Found {
		t.Errorf("restarted before a pass = %+v, want not reconciled", snap)
	}
}

// recordApplied (the reconcile loop) and AppliedState (the RPC) run on
// different goroutines; under -race this pins the locking.
func TestNetworkPolicyEnforcer_AppliedStateConcurrent(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, nil, nil, nil, nil, false)
	e.mu.Lock()
	e.running = true
	e.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 200 {
			e.recordApplied(map[string]tenantApplied{"acme": {Mode: 2, BoxesLoaded: i + 1}}, statusNow.Add(time.Duration(i)))
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			if snap := e.AppliedState("acme"); snap.Found && snap.Tenant.BoxesLoaded == 0 {
				t.Errorf("torn read: %+v", snap)
			}
		}
	}()
	wg.Wait()
}

// A loaded egress-mode byte of 0 means "follow mode" in the kernel (#2970), so
// it is reported as the effective mode, not as unknown.
func TestBuildPolicyStatus_EgressModeZeroFollowsMode(t *testing.T) {
	snap := fresh(tenantApplied{Mode: 2, EgressMode: 0, BoxesLoaded: 1})
	st := buildPolicyStatus("acme", snap, true, statusNow)
	if st.GetEffectiveMode() != stEnforce || st.GetEffectiveEgressMode() != stEnforce {
		t.Errorf("effective mode=%v egress=%v, want ENFORCE/ENFORCE", st.GetEffectiveMode(), st.GetEffectiveEgressMode())
	}
	snap.Tenant.Mode = 7 // a byte the program would not act on
	st = buildPolicyStatus("acme", snap, true, statusNow)
	if st.GetEffectiveMode() != stUnset || st.GetEffectiveEgressMode() != stUnset {
		t.Errorf("unknown byte: effective mode=%v egress=%v, want UNSPECIFIED for both", st.GetEffectiveMode(), st.GetEffectiveEgressMode())
	}
}
