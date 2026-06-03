package server

import (
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

	plan := planReconcile(views, policies)

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
