package server

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// appliedPassOnObject is appliedPass for a loaded object that does or does not
// read the egress_mode byte (#2987), returning the tenants whose split mode the
// object cannot honour.
func appliedPassOnObject(t *testing.T, views []containerView, policies map[string]netpolicy.CompiledPolicy, supportsEgressMode bool) (map[string]tenantApplied, map[uint32]bool) {
	t.Helper()
	plan := planReconcile(views, policies, true)
	ignored := foldEgressModeForObject(&plan, supportsEgressMode)
	loaded := make(map[int]bool, len(plan.vethPolicy))
	for ifindex := range plan.vethPolicy {
		loaded[ifindex] = true
	}
	return appliedFromPass(views, plan, loaded, policies, nil, nil), ignored
}

// An object built before #2974 ignores egress_mode and applies `mode` to the
// allow-list, so the status reports `mode` as the effective egress mode — for
// both splits — and never the requested one. A current object keeps the split.
func TestNetworkPolicyStatus_ObjectWithoutEgressModeReportsMode(t *testing.T) {
	views := []containerView{{Name: "acme-container", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}}
	for _, tc := range []struct {
		name               string
		mode, egress       pb.NetworkPolicyMode
		supportsEgressMode bool
		wantEgress         pb.NetworkPolicyMode
		wantIgnored        bool
	}{
		{"old object, log_only/enforce", stLogOnly, stEnforce, false, stLogOnly, true},
		{"old object, enforce/log_only", stEnforce, stLogOnly, false, stEnforce, true},
		{"old object, no split", stEnforce, stUnset, false, stEnforce, false},
		{"current object, log_only/enforce", stLogOnly, stEnforce, true, stEnforce, false},
		{"current object, enforce/log_only", stEnforce, stLogOnly, true, stLogOnly, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policies := map[string]netpolicy.CompiledPolicy{
				"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", Mode: tc.mode, EgressMode: tc.egress}),
			}
			applied, ignored := appliedPassOnObject(t, views, policies, tc.supportsEgressMode)
			st := npStatusFor(t, fakeAppliedSource{fresh(applied["acme"])}, true, "acme")
			if st.GetEffectiveMode() != tc.mode {
				t.Errorf("effective mode = %v, want %v", st.GetEffectiveMode(), tc.mode)
			}
			if st.GetEffectiveEgressMode() != tc.wantEgress {
				t.Errorf("effective egress mode = %v, want %v", st.GetEffectiveEgressMode(), tc.wantEgress)
			}
			if ignored[1] != tc.wantIgnored {
				t.Errorf("tenant reported as ignored = %v, want %v (ignored=%v)", ignored[1], tc.wantIgnored, ignored)
			}
		})
	}
}

// The fold rewrites only the egress byte, and only for veths whose split the
// object cannot honour; every other field the kernel reads is untouched.
func TestFoldEgressModeForObject_OnlyRewritesTheEgressByte(t *testing.T) {
	split := netbpf.PolicyConfig{TenantID: 1, Mode: netbpf.ModeLogOnly, AllowIntra: 1, AllowMetadata: 1, EgressMode: netbpf.ModeEnforce}
	same := netbpf.PolicyConfig{TenantID: 2, Mode: netbpf.ModeEnforce, EgressMode: netbpf.ModeEnforce}
	follow := netbpf.PolicyConfig{TenantID: 3, Mode: netbpf.ModeEnforce} // 0 = follow mode
	plan := reconcilePlan{vethPolicy: map[int]netbpf.PolicyConfig{11: split, 12: same, 13: follow}}

	ignored := foldEgressModeForObject(&plan, false)

	want := split
	want.EgressMode = netbpf.ModeLogOnly
	if got := plan.vethPolicy[11]; got != want {
		t.Errorf("split veth = %+v, want %+v", got, want)
	}
	if got := plan.vethPolicy[12]; got != same {
		t.Errorf("unsplit veth = %+v, want unchanged %+v", got, same)
	}
	if got := plan.vethPolicy[13]; got != follow {
		t.Errorf("follow-mode veth = %+v, want unchanged %+v", got, follow)
	}
	if len(ignored) != 1 || !ignored[1] {
		t.Errorf("ignored = %v, want only tenant 1", ignored)
	}

	// A current object keeps the plan as built.
	plan = reconcilePlan{vethPolicy: map[int]netbpf.PolicyConfig{11: split}}
	if ignored := foldEgressModeForObject(&plan, true); len(ignored) != 0 || plan.vethPolicy[11] != split {
		t.Errorf("supported object: ignored=%v veth=%+v, want none and %+v", ignored, plan.vethPolicy[11], split)
	}
}

// The warning names the tenant once per split, not on every reconcile pass; a
// tenant whose split is cleared and later set again is warned again.
func TestNetworkPolicyEnforcer_WarnsOnceWhenObjectIgnoresEgressMode(t *testing.T) {
	e := &NetworkPolicyEnforcer{}
	names := map[uint32]string{1: "acme", 2: "globex"}
	warn := func(ignored map[uint32]bool) string {
		return captureLog(t, func() { e.warnEgressModeIgnored(ignored, names) })
	}

	first := warn(map[uint32]bool{1: true})
	if strings.Count(first, "\n") != 1 || !strings.Contains(first, "egress_mode") || !strings.Contains(first, `"acme"`) {
		t.Fatalf("first pass log = %q, want one egress_mode warning naming acme", first)
	}
	if got := warn(map[uint32]bool{1: true}); got != "" {
		t.Errorf("second pass with the same split logged again: %q", got)
	}
	if got := warn(map[uint32]bool{2: true}); strings.Contains(got, `"acme"`) || !strings.Contains(got, `"globex"`) {
		t.Errorf("new tenant pass log = %q, want a warning for globex only", got)
	}
	warn(map[uint32]bool{})
	if got := warn(map[uint32]bool{1: true}); !strings.Contains(got, `"acme"`) {
		t.Errorf("re-split after clearing logged %q, want a fresh warning for acme", got)
	}
}
