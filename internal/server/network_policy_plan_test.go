package server

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func compiled(t *testing.T, p *pb.NetworkPolicy) netpolicy.CompiledPolicy {
	t.Helper()
	c, err := netpolicy.Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func TestResolveTenant(t *testing.T) {
	cases := []struct {
		label, cloudOrgID, name, want string
	}{
		{"acme", "", "cld-1a2b3c", "acme"},          // label wins for a cloud-named container
		{"acme", "", "alice-container", "acme"},     // label wins over name
		{"", "", "alice-container", "alice"},        // fall back to name convention
		{"  ", "", "alice-container", "alice"},      // blank label ignored
		{"", "", "cld-1a2b3c", ""},                  // cloud name, no label → unmanaged
		{" tenant7 ", "", "x-container", "tenant7"}, // label trimmed
		{"", "org-42", "cld-1a2b3c", "org-42"},      // push-mode (OSS-primary): no tenant label, cloud_org_id fills in
		{"acme", "org-42", "cld-1a2b3c", "acme"},    // explicit tenant label still wins over cloud_org_id
		{"", " org-42 ", "cld-1a2b3c", "org-42"},    // cloud_org_id trimmed
		{"", "", "", ""},                            // nothing at all → unmanaged
	}
	for _, c := range cases {
		if got := resolveTenant(c.label, c.cloudOrgID, c.name); got != c.want {
			t.Errorf("resolveTenant(%q, %q, %q) = %q, want %q", c.label, c.cloudOrgID, c.name, got, c.want)
		}
	}
}

func TestTenantOf(t *testing.T) {
	cases := map[string]string{
		"alice-container": "alice",
		"bob-container":   "bob",
		"weird":           "",
		"-container":      "",
		"a-b-container":   "a-b",
	}
	for name, want := range cases {
		if got := tenantOf(name); got != want {
			t.Errorf("tenantOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestPlanReconcile(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{
		"alice": compiled(t, &pb.NetworkPolicy{
			Tenant:           "alice",
			AllowIntraTenant: true,
			EgressCidrs:      []string{"8.8.8.8/32"},
		}),
		// bob has no stored policy → Phase A default applies.
	}
	views := []containerView{
		// alice running with veth + IP
		{Name: "alice-container", Tenant: "alice", TenantID: 1, IP: [4]byte{10, 100, 0, 10}, HasIP: true, Ifindex: 11, HasVeth: true, Running: true},
		// alice second container (same tenant) → egress emitted once
		{Name: "alice-web-container", Tenant: "alice", TenantID: 1, IP: [4]byte{10, 100, 0, 11}, HasIP: true, Ifindex: 12, HasVeth: true, Running: true},
		// bob running, no policy → default log-only config, no egress
		{Name: "bob-container", Tenant: "bob", TenantID: 2, IP: [4]byte{10, 100, 0, 20}, HasIP: true, Ifindex: 20, HasVeth: true, Running: true},
		// stopped container → IP mapped but no veth_policy/attach
		{Name: "carol-container", Tenant: "carol", TenantID: 3, IP: [4]byte{10, 100, 0, 30}, HasIP: true, Running: false},
	}

	plan := planReconcile(views, policies, true)

	// ip_tenant: all four containers with IPs.
	if len(plan.ipTenant) != 4 {
		t.Errorf("ipTenant size = %d, want 4: %v", len(plan.ipTenant), plan.ipTenant)
	}
	if plan.ipTenant[[4]byte{10, 100, 0, 30}] != 3 {
		t.Errorf("stopped carol IP should still map to tenant 3")
	}

	// veth_policy: only the 3 running+veth containers.
	if len(plan.vethPolicy) != 3 {
		t.Fatalf("vethPolicy size = %d, want 3: %v", len(plan.vethPolicy), plan.vethPolicy)
	}
	if _, ok := plan.vethPolicy[20]; !ok {
		t.Error("bob's veth (ifindex 20) should be present with default config")
	}
	if cfg := plan.vethPolicy[11]; cfg.TenantID != 1 || cfg.AllowIntra != 1 || cfg.Mode != netbpf.ModeLogOnly {
		t.Errorf("alice veth cfg = %+v, want tenant=1 allowIntra=1 logOnly", cfg)
	}
	if cfg := plan.vethPolicy[20]; cfg.TenantID != 2 || cfg.AllowIntra != 0 {
		t.Errorf("bob default cfg = %+v, want tenant=2 allowIntra=0", cfg)
	}
	// #2618: the program validates a box's source address against box_ip and
	// seeds inbound flows only for a veth whose box_ip is known, so every running
	// veth with a resolved IP carries it — with a stored policy or on the default.
	if cfg := plan.vethPolicy[11]; cfg.BoxIP != [4]byte{10, 100, 0, 10} {
		t.Errorf("alice veth cfg.BoxIP = %v, want 10.100.0.10", cfg.BoxIP)
	}
	if cfg := plan.vethPolicy[20]; cfg.BoxIP != [4]byte{10, 100, 0, 20} {
		t.Errorf("bob default cfg.BoxIP = %v, want 10.100.0.20", cfg.BoxIP)
	}
	if plan.ifName[11] != "alice-container" {
		t.Errorf("ifName[11] = %q, want alice-container", plan.ifName[11])
	}

	// egress: alice's single CIDR, emitted exactly once despite two alice containers.
	if len(plan.egress) != 1 {
		t.Fatalf("egress size = %d, want 1 (alice 8.8.8.8/32 once): %v", len(plan.egress), plan.egress)
	}
	e := plan.egress[0]
	if e.TenantID != 1 || e.Addr != [4]byte{8, 8, 8, 8} || e.PrefixLen != 32+32 {
		t.Errorf("egress entry = %+v, want tenant=1 8.8.8.8 prefixlen=64", e)
	}
}

func TestPlanReconcile_EnforceGuard(t *testing.T) {
	policies := map[string]netpolicy.CompiledPolicy{
		"alice": compiled(t, &pb.NetworkPolicy{
			Tenant: "alice",
			Mode:   pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		}),
	}
	views := []containerView{
		{Name: "alice-container", Tenant: "alice", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true},
	}

	// Guard off → ENFORCE downgraded to LOG_ONLY (no accidental blackhole).
	off := planReconcile(views, policies, false)
	if off.vethPolicy[11].Mode != netbpf.ModeLogOnly {
		t.Errorf("enforce-disabled: mode = %d, want ModeLogOnly", off.vethPolicy[11].Mode)
	}

	// Guard on → ENFORCE preserved.
	on := planReconcile(views, policies, true)
	if on.vethPolicy[11].Mode != netbpf.ModeEnforce {
		t.Errorf("enforce-armed: mode = %d, want ModeEnforce", on.vethPolicy[11].Mode)
	}
}

func TestDiffEgress(t *testing.T) {
	a := netbpf.EgressEntry{PrefixLen: 64, TenantID: 1, Addr: [4]byte{8, 8, 8, 8}}
	b := netbpf.EgressEntry{PrefixLen: 64, TenantID: 1, Addr: [4]byte{1, 1, 1, 1}}
	c := netbpf.EgressEntry{PrefixLen: 40, TenantID: 2, Addr: [4]byte{10, 0, 0, 0}}

	installed := map[netbpf.EgressEntry]bool{a: true, b: true}
	desired := []netbpf.EgressEntry{a, c} // keep a, drop b, add c

	toAdd, toDel := diffEgress(installed, desired)
	if len(toAdd) != 1 || toAdd[0] != c {
		t.Errorf("toAdd = %+v, want [c]", toAdd)
	}
	if len(toDel) != 1 || toDel[0] != b {
		t.Errorf("toDel = %+v, want [b]", toDel)
	}

	// Converged state → no churn.
	add2, del2 := diffEgress(map[netbpf.EgressEntry]bool{a: true, c: true}, []netbpf.EgressEntry{a, c})
	if len(add2) != 0 || len(del2) != 0 {
		t.Errorf("converged diff should be empty, got add=%v del=%v", add2, del2)
	}
}

// TestPlanReconcile_EgressMode: egress_mode reaches the BPF config on its own,
// unset follows mode, and the daemon-wide enforce guard downgrades both modes.
func TestPlanReconcile_EgressMode(t *testing.T) {
	const (
		unset   = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED
		logOnly = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
		enforce = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
	)
	cases := []struct {
		name           string
		mode, egress   pb.NetworkPolicyMode
		armed          bool
		wantMode, want uint8
	}{
		{"unset follows enforce", enforce, unset, true, netbpf.ModeEnforce, netbpf.ModeEnforce},
		{"unset follows log-only", logOnly, unset, true, netbpf.ModeLogOnly, netbpf.ModeLogOnly},
		{"cross-tenant enforce, egress log-only", enforce, logOnly, true, netbpf.ModeEnforce, netbpf.ModeLogOnly},
		{"cross-tenant log-only, egress enforce", logOnly, enforce, true, netbpf.ModeLogOnly, netbpf.ModeEnforce},
		{"guard off downgrades both", enforce, enforce, false, netbpf.ModeLogOnly, netbpf.ModeLogOnly},
		{"guard off downgrades a followed egress", enforce, unset, false, netbpf.ModeLogOnly, netbpf.ModeLogOnly},
		{"guard off downgrades egress-only enforce", logOnly, enforce, false, netbpf.ModeLogOnly, netbpf.ModeLogOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies := map[string]netpolicy.CompiledPolicy{
				"alice": compiled(t, &pb.NetworkPolicy{Tenant: "alice", Mode: tc.mode, EgressMode: tc.egress}),
			}
			views := []containerView{{Name: "alice-container", Tenant: "alice", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}}
			cfg := planReconcile(views, policies, tc.armed).vethPolicy[11]
			if cfg.Mode != tc.wantMode || cfg.EgressMode != tc.want {
				t.Errorf("mode=%d egress=%d, want mode=%d egress=%d", cfg.Mode, cfg.EgressMode, tc.wantMode, tc.want)
			}
		})
	}

	// A container with no stored policy gets the Phase A default for both.
	views := []containerView{{Name: "bob-container", Tenant: "bob", TenantID: 2, Ifindex: 20, HasVeth: true, Running: true}}
	cfg := planReconcile(views, nil, true).vethPolicy[20]
	if cfg.Mode != netbpf.ModeLogOnly || cfg.EgressMode != netbpf.ModeLogOnly {
		t.Errorf("default cfg = %+v, want log-only for both modes", cfg)
	}
}

// #2577 stage 1: a tenant with no stored policy is planned from the default
// allow-list, in log-only, even when the host arms enforcement.
func TestPlanReconcile_DefaultPolicyIsLogOnlyEvenWhenArmed(t *testing.T) {
	def, err := netpolicy.DefaultPolicy("acme", netpolicy.DefaultEgressExtras{CIDRs: []string{"10.9.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	views := []containerView{{Name: "acme-container", Tenant: "acme", TenantID: 7, IP: [4]byte{10, 0, 0, 5}, HasIP: true, Ifindex: 11, HasVeth: true, Running: true}}
	plan := planReconcile(views, map[string]netpolicy.CompiledPolicy{"acme": def}, true)
	cfg := plan.vethPolicy[11]
	if cfg.Mode != netbpf.ModeLogOnly || cfg.EgressMode != netbpf.ModeLogOnly {
		t.Errorf("default policy under an armed host: mode=%v egress=%v, want log-only for both", cfg.Mode, cfg.EgressMode)
	}
	if len(plan.egress) == 0 {
		t.Error("the default allow-list produced no egress entries")
	}
}

func TestWithDefaultPolicies(t *testing.T) {
	stored := netpolicy.CompiledPolicy{Tenant: "has-policy", Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE}
	policies := map[string]netpolicy.CompiledPolicy{"has-policy": stored}
	views := []containerView{
		{Name: "a", Tenant: "has-policy"},
		{Name: "b", Tenant: "no-policy"},
		{Name: "c", Tenant: "no-policy"},
		{Name: "d", Tenant: ""}, // unmanaged: never guessed into a tenant
	}
	build := func(tenant string) (netpolicy.CompiledPolicy, bool) {
		return netpolicy.CompiledPolicy{Tenant: tenant, LogOnly: true}, true
	}
	got := withDefaultPolicies(policies, views, build)
	if got["has-policy"].Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE {
		t.Error("a stored policy must win over the default")
	}
	if _, ok := got["no-policy"]; !ok {
		t.Error("a tenant with no stored policy must get the default")
	}
	if _, ok := got[""]; ok {
		t.Error("an unresolved tenant must not get a policy")
	}
	if _, ok := policies["no-policy"]; ok {
		t.Error("withDefaultPolicies must not mutate its input")
	}
	if g := withDefaultPolicies(policies, views, nil); len(g) != 1 {
		t.Errorf("a nil builder (default posture off) must add nothing, got %d policies", len(g))
	}
}

func TestDefaultPolicyFor_OffAndOn(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", nil, nil, nil, nil, nil, true)
	e.SetImplicitGateway(netip.MustParseAddr("10.0.3.1"))
	if _, ok := e.defaultPolicyFor("acme"); ok {
		t.Error("the default posture must be off until SetDefaultEgress")
	}
	if err := e.SetDefaultEgress(netpolicy.DefaultEgressExtras{CIDRs: []string{"nope"}}); err == nil {
		t.Error("SetDefaultEgress must refuse an unparseable extra")
	}
	if _, ok := e.defaultPolicyFor("acme"); ok {
		t.Error("a refused SetDefaultEgress must leave the posture off")
	}
	if err := e.SetDefaultEgress(netpolicy.DefaultEgressExtras{}); err != nil {
		t.Fatal(err)
	}
	c, ok := e.defaultPolicyFor("acme")
	if !ok || !c.LogOnly {
		t.Fatalf("defaultPolicyFor = %+v, %v; want a log-only policy", c, ok)
	}
	if !slices.Contains(c.EgressCIDRs, netip.MustParsePrefix("10.0.3.1/32")) {
		t.Errorf("the DNS resolver (bridge gateway) must be implicitly allowed: %v", c.EgressCIDRs)
	}
}

// The default posture, end to end through the enforcer: an armed host still
// plans log-only for both modes for a tenant with no stored policy.
func TestDefaultPosture_ThroughEnforcerStaysLogOnlyWhenArmed(t *testing.T) {
	e := NewNetworkPolicyEnforcer("", NewMemNetworkPolicyStore(), nil, nil, nil, nil, true)
	e.SetImplicitGateway(netip.MustParseAddr("10.0.3.1"))
	if err := e.SetDefaultEgress(netpolicy.DefaultEgressExtras{}); err != nil {
		t.Fatal(err)
	}
	views := []containerView{{Name: "acme-container", Tenant: "acme", TenantID: 7, Ifindex: 11, HasVeth: true, Running: true}}
	plan := planReconcile(views, withDefaultPolicies(nil, views, e.defaultPolicyFor), true)
	cfg, ok := plan.vethPolicy[11]
	if !ok {
		t.Fatal("no veth policy planned")
	}
	if cfg.Mode != netbpf.ModeLogOnly || cfg.EgressMode != netbpf.ModeLogOnly {
		t.Errorf("mode=%v egress=%v, want log-only for both on an armed host", cfg.Mode, cfg.EgressMode)
	}
	if len(plan.egress) == 0 {
		t.Error("the implicit resolver allow produced no egress entries")
	}
}

// Extras are normalized once and the same names are resolved and looked up:
// a mixed-case, trailing-dot extra must end up cached under the name the
// policy looks it up by.
func TestRefreshDomains_ResolvesDefaultAndNormalizedExtraDomains(t *testing.T) {
	f := &fakeIPResolver{results: map[string][]netip.Addr{
		"gateway.example.com": addrs("10.9.0.5"),
		"github.com":          addrs("140.82.112.3"),
	}}
	e := NewNetworkPolicyEnforcer("", NewMemNetworkPolicyStore(), nil, nil, nil, nil, false)
	e.ctx = context.Background()
	e.resolver = NewDomainResolver(f)
	if err := e.SetDefaultEgress(netpolicy.DefaultEgressExtras{Domains: []string{"Gateway.Example.com."}}); err != nil {
		t.Fatal(err)
	}
	e.refreshDomains(true)
	c, ok := e.defaultPolicyFor("acme")
	if !ok {
		t.Fatal("default policy off")
	}
	for _, want := range []string{"10.9.0.5/32", "140.82.112.3/32"} {
		if !slices.Contains(c.EgressCIDRs, netip.MustParsePrefix(want)) {
			t.Errorf("%s not folded into the default allow-list: %v", want, c.EgressCIDRs)
		}
	}
}
