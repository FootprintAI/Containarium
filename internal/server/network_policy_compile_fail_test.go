package server

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3518: a tenant whose egress or deny rules fail to compile (a non-IPv4 CIDR)
// must not have its kernel sets emptied or replaced by a partial set. The pass
// keeps the last good set for that tenant, reports the failure, and leaves
// other tenants alone.
func TestPlanReconcile_CompileFailureKeepsLastGoodSet(t *testing.T) {
	v4 := netip.MustParsePrefix("203.0.113.0/24")
	v6 := netip.MustParsePrefix("2001:db8::/32")
	good := netip.MustParsePrefix("198.51.100.0/24")

	views := []containerView{
		{Name: "a-box", Tenant: "a", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true},
		{Name: "b-box", Tenant: "b", TenantID: 2, Ifindex: 12, HasVeth: true, Running: true},
	}
	// Tenant b is healthy throughout; its sets must follow its policy.
	bPolicy := netpolicy.CompiledPolicy{
		Tenant:      "b",
		EgressCIDRs: []netip.Prefix{good},
		DenyRules:   []netpolicy.DenyRule{{CIDR: v4}},
	}
	// What a previous pass installed for tenant a (its last good policy).
	lastGoodEgress := netbpf.EgressEntry{PrefixLen: 32 + 24, TenantID: 1, Addr: good.Addr().As4()}
	lastGoodDeny := netbpf.DenyEntry{PrefixLen: 32 + 24, TenantID: 1, Addr: v4.Addr().As4()}

	tests := []struct {
		name    string
		aPolicy netpolicy.CompiledPolicy
	}{
		{
			name: "one non-IPv4 deny CIDR next to a valid one",
			aPolicy: netpolicy.CompiledPolicy{
				Tenant:      "a",
				EgressCIDRs: []netip.Prefix{good},
				DenyRules:   []netpolicy.DenyRule{{CIDR: v4}, {CIDR: v6}},
			},
		},
		{
			name: "one non-IPv4 egress CIDR next to a valid one",
			aPolicy: netpolicy.CompiledPolicy{
				Tenant:      "a",
				EgressCIDRs: []netip.Prefix{good, v6},
				DenyRules:   []netpolicy.DenyRule{{CIDR: v4}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := map[string]netpolicy.CompiledPolicy{"a": tc.aPolicy, "b": bPolicy}
			egressInstalled := map[netbpf.EgressEntry]bool{lastGoodEgress: true}
			denyInstalled := map[netbpf.DenyKey]netbpf.DenyEntry{lastGoodDeny.Key(): lastGoodDeny}

			plan := planReconcile(views, policies, true)

			f, failed := plan.compileFailed[1]
			if !failed {
				t.Errorf("tenant a's compile error was dropped: compileFailed = %v", plan.compileFailed)
			}
			if f.Tenant != "a" || f.Err == nil || !strings.Contains(f.Err.Error(), "not IPv4") {
				t.Errorf("compileFailed[1] = %+v, want tenant %q with the IPv4 error", f, "a")
			}
			if _, bad := plan.compileFailed[2]; bad {
				t.Errorf("healthy tenant b is reported failed: %v", plan.compileFailed)
			}

			holdLastGood(&plan, egressInstalled, denyInstalled)

			// Applying the plan must not delete tenant a's installed entries
			// nor add a partial set for it.
			addE, delE := diffEgress(egressInstalled, plan.egress)
			for _, e := range append(addE, delE...) {
				if e.TenantID == 1 {
					t.Errorf("egress change %+v for the failed tenant; its last good set must be held", e)
				}
			}
			upD, delD := diffDeny(denyInstalled, plan.deny)
			for _, d := range upD {
				if d.TenantID == 1 {
					t.Errorf("deny upsert %+v for the failed tenant; its last good set must be held", d)
				}
			}
			if slices.Contains(delD, lastGoodDeny.Key()) {
				t.Error("the failed tenant's installed deny entry would be deleted: its deny list empties")
			}

			// Tenant b still gets its own compiled sets.
			if !slices.Contains(plan.egress, netbpf.EgressEntry{PrefixLen: 32 + 24, TenantID: 2, Addr: good.Addr().As4()}) {
				t.Errorf("healthy tenant b lost its egress entry: %v", plan.egress)
			}
			if !slices.ContainsFunc(plan.deny, func(d netbpf.DenyEntry) bool { return d.TenantID == 2 }) {
				t.Errorf("healthy tenant b lost its deny entry: %v", plan.deny)
			}
		})
	}
}

// A failed compile is visible in the enforcement status, in both the loaded
// and the not-loaded state.
func TestPolicyStatus_CompileFailureIsVisible(t *testing.T) {
	views := []containerView{
		{Name: "a-box", Tenant: "a", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true},
		{Name: "c-box", Tenant: "c", TenantID: 3, Ifindex: 13, HasVeth: true, Running: true},
	}
	plan := reconcilePlan{
		vethPolicy: map[int]netbpf.PolicyConfig{
			11: {TenantID: 1, Mode: netbpf.ModeEnforce},
			13: {TenantID: 3, Mode: netbpf.ModeEnforce},
		},
		compileFailed: map[uint32]compileFailure{1: {Tenant: "a"}},
	}
	tests := []struct {
		name   string
		loaded map[int]bool
		tenant string
		want   bool
	}{
		{"failed tenant, loaded", map[int]bool{11: true, 13: true}, "a", true},
		{"failed tenant, not loaded", map[int]bool{13: true}, "a", true},
		{"healthy tenant", map[int]bool{11: true, 13: true}, "c", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			applied := appliedFromPass(views, plan, tc.loaded, nil, nil, nil)
			a, found := applied[tc.tenant]
			snap := appliedSnapshot{Running: true, Reconciled: true, Found: found, Tenant: a, ReconciledAt: time.Unix(100, 0)}
			st := buildPolicyStatus(tc.tenant, snap, true, time.Unix(100, 0), false)
			got := slices.Contains(st.GetUncoveredPaths(), pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_POLICY_COMPILE_FAILED)
			if got != tc.want {
				t.Errorf("POLICY_COMPILE_FAILED in %v = %v, want %v", st.GetUncoveredPaths(), got, tc.want)
			}
		})
	}
}

// The failure is logged once per change, naming the tenant quoted, and its
// recovery once.
func TestNoteCompileFailures_LogsOncePerChange(t *testing.T) {
	seen := map[uint32]compileFailure{}
	errA := compileFailure{Tenant: "a\nforged", Err: errString("netbpf: deny CIDR 2001:db8::/32 is not IPv4")}
	errB := compileFailure{Tenant: "a\nforged", Err: errString("netbpf: egress CIDR 2001:db8::/32 is not IPv4")}

	steps := []struct {
		name   string
		failed map[uint32]compileFailure
		lines  int
	}{
		{"first failure", map[uint32]compileFailure{1: errA}, 1},
		{"same failure again", map[uint32]compileFailure{1: errA}, 0},
		{"different error", map[uint32]compileFailure{1: errB}, 1},
		{"recovered", nil, 1},
		{"still healthy", nil, 0},
	}
	for _, s := range steps {
		lines := noteCompileFailures(seen, s.failed)
		if len(lines) != s.lines {
			t.Fatalf("%s: logged %d line(s) %q, want %d", s.name, len(lines), lines, s.lines)
		}
		for _, l := range lines {
			if !strings.Contains(l, `"a\nforged"`) {
				t.Errorf("%s: line %q does not quote the tenant", s.name, l)
			}
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
