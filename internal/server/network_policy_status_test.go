package server

import (
	"context"
	"slices"
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

// appliedPass runs one reconcile's plan through appliedFromPass, with every
// planned veth loaded unless listed in failed.
func appliedPass(t *testing.T, views []containerView, policies map[string]netpolicy.CompiledPolicy, armed bool, failed ...int) map[string]tenantApplied {
	t.Helper()
	plan := planReconcile(views, policies, armed)
	loaded := make(map[int]bool, len(plan.vethPolicy))
	for ifindex := range plan.vethPolicy {
		loaded[ifindex] = !slices.Contains(failed, ifindex)
	}
	return appliedFromPass(views, plan, loaded, policies, time.Unix(1700000000, 0))
}

func npStatusFor(t *testing.T, src appliedStateSource, armed bool, tenant string) *pb.NetworkPolicyStatus {
	t.Helper()
	s := newNPServer()
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
		st := npStatusFor(t, fakeAppliedSource{appliedSnapshot{Running: true, Reconciled: true, Tenant: applied["acme"], Found: true}}, tc.armed, "acme")
		if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED {
			t.Fatalf("armed=%v: state = %v, want LOADED", tc.armed, st.GetState())
		}
		if st.GetEffectiveMode() != tc.want || st.GetEffectiveEgressMode() != tc.want {
			t.Errorf("armed=%v: effective mode=%v egress=%v, want %v for both", tc.armed, st.GetEffectiveMode(), st.GetEffectiveEgressMode(), tc.want)
		}
		if st.GetEnforcementArmed() != tc.armed {
			t.Errorf("armed=%v: enforcement_armed = %v", tc.armed, st.GetEnforcementArmed())
		}
		if st.GetLastAppliedAt().AsTime() != time.Unix(1700000000, 0).UTC() {
			t.Errorf("armed=%v: last_applied_at = %v", tc.armed, st.GetLastAppliedAt().AsTime())
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
	st := npStatusFor(t, fakeAppliedSource{appliedSnapshot{Running: true, Reconciled: true, Tenant: applied["acme"], Found: true}}, true, "acme")
	if st.GetEffectiveMode() != stEnforce || st.GetEffectiveEgressMode() != stLogOnly {
		t.Errorf("effective mode=%v egress=%v, want ENFORCE/LOG_ONLY", st.GetEffectiveMode(), st.GetEffectiveEgressMode())
	}
}

// Nothing applied means unknown modes, never a guess from the stored policy.
func TestNetworkPolicyStatus_UnknownWhenNothingApplied(t *testing.T) {
	cases := []struct {
		name string
		src  appliedStateSource
		want pb.NetworkPolicyAppliedState
	}{
		{"no enforcer configured", nil, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING},
		{"enforcer not started", fakeAppliedSource{appliedSnapshot{}}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING},
		{"no reconcile pass yet", fakeAppliedSource{appliedSnapshot{Running: true}}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_UNSPECIFIED},
		{"no box of the tenant loaded", fakeAppliedSource{appliedSnapshot{Running: true, Reconciled: true}}, pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newNPServer()
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
			if st.GetLastAppliedAt() != nil {
				t.Errorf("last_applied_at = %v, want unset", st.GetLastAppliedAt())
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
	st := npStatusFor(t, fakeAppliedSource{appliedSnapshot{Running: true, Reconciled: true, Tenant: got["bob"], Found: true}}, true, "bob")
	if st.GetState() != pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED || st.GetEffectiveMode() != stUnset {
		t.Errorf("bob status = %v mode %v, want NOT_LOADED/unknown", st.GetState(), st.GetEffectiveMode())
	}
	if st.GetBoxesNotLoaded() != 1 {
		t.Errorf("bob boxes_not_loaded = %d, want 1", st.GetBoxesNotLoaded())
	}
}

// IPv6 is always uncovered; domain refresh lag only when the loaded policy has
// domain entries.
func TestNetworkPolicyStatus_UncoveredPaths(t *testing.T) {
	views := []containerView{{Name: "acme-container", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}}
	ipv6 := pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_IPV6
	lag := pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG

	plain := appliedPass(t, views, map[string]netpolicy.CompiledPolicy{"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", EgressCidrs: []string{"192.0.2.0/24"}})}, true)
	st := npStatusFor(t, fakeAppliedSource{appliedSnapshot{Running: true, Reconciled: true, Tenant: plain["acme"], Found: true}}, true, "acme")
	if got := st.GetUncoveredPaths(); !slices.Equal(got, []pb.NetworkPolicyUncoveredPath{ipv6}) {
		t.Errorf("no domains: uncovered = %v, want [IPV6]", got)
	}

	doms := appliedPass(t, views, map[string]netpolicy.CompiledPolicy{"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", EgressDomains: []string{"example.com"}})}, true)
	st = npStatusFor(t, fakeAppliedSource{appliedSnapshot{Running: true, Reconciled: true, Tenant: doms["acme"], Found: true}}, true, "acme")
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
	e.recordApplied(map[string]tenantApplied{"acme": {Mode: 2, EgressMode: 1, BoxesLoaded: 1}})
	if snap := e.AppliedState("acme"); !snap.Reconciled || !snap.Found || snap.Tenant.Mode != 2 || snap.Tenant.EgressMode != 1 {
		t.Errorf("after a pass = %+v", snap)
	}
	if snap := e.AppliedState("other"); !snap.Reconciled || snap.Found {
		t.Errorf("unknown tenant after a pass = %+v, want reconciled and not found", snap)
	}
}

// A loaded egress-mode byte of 0 means "follow mode" in the kernel (#2970), so
// it is reported as the effective mode, not as unknown.
func TestBuildPolicyStatus_EgressModeZeroFollowsMode(t *testing.T) {
	snap := appliedSnapshot{Running: true, Reconciled: true, Found: true, Tenant: tenantApplied{
		Mode: 2, EgressMode: 0, BoxesLoaded: 1, AppliedAt: time.Unix(1700000000, 0),
	}}
	st := buildPolicyStatus("acme", snap, true)
	if st.GetEffectiveMode() != stEnforce || st.GetEffectiveEgressMode() != stEnforce {
		t.Errorf("effective mode=%v egress=%v, want ENFORCE/ENFORCE", st.GetEffectiveMode(), st.GetEffectiveEgressMode())
	}
	snap.Tenant.Mode = 7 // a byte the program would not act on
	st = buildPolicyStatus("acme", snap, true)
	if st.GetEffectiveMode() != stUnset || st.GetEffectiveEgressMode() != stUnset {
		t.Errorf("unknown byte: effective mode=%v egress=%v, want UNSPECIFIED for both", st.GetEffectiveMode(), st.GetEffectiveEgressMode())
	}
}
