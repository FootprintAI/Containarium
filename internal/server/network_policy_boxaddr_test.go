package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// #2618 B1: gather() must take the address the program validates a box
// against (view.HostIP -> policy_cfg.box_ip) from the host — the NIC's static
// ipv4.address or the bridge's DHCP lease — and never from c.IPAddress, which
// is what the guest configured on itself. A guest-side address change must not
// move box_ip; a box the host knows no address for gets none.
func TestGather_BoxAddressIsHostKnownNotGuestReported(t *testing.T) {
	veth := firstHostIface(t)
	const mac = "00:16:3e:aa:bb:cc"
	leaseDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(leaseDir, "testbr0"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLease := func(ip string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(leaseDir, "testbr0", "dnsmasq.leases"), []byte("0 "+mac+" "+ip+" web *\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeLease("10.100.0.7")

	insp := &fakeInspector{
		containers: []incus.ContainerInfo{{Name: "web-container", State: "running", IPAddress: "10.100.0.42"}},
		veth:       veth, rawCalls: map[string]int{},
		network: "testbr0", hwaddr: mac,
	}
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), insp, nil, nil, false)
	e.ctx = context.Background()
	e.leaseDir = leaseDir

	view := func() containerView {
		t.Helper()
		views, _, err := e.gather(context.Background())
		if err != nil || len(views) != 1 {
			t.Fatalf("gather: %v (%d views)", err, len(views))
		}
		return views[0]
	}

	// Lease: the host's answer, not the guest's.
	v := view()
	if !v.HasVeth {
		t.Fatalf("view has no veth: %+v", v)
	}
	if !v.HasHostIP || v.HostIP != [4]byte{10, 100, 0, 7} {
		t.Fatalf("HostIP = %v (%v), want the leased 10.100.0.7", v.HostIP, v.HasHostIP)
	}
	if !v.HasIP || v.IP != [4]byte{10, 100, 0, 42} {
		t.Errorf("guest IP = %v, want 10.100.0.42 kept for ip_tenant", v.IP)
	}

	// Root in the box renumbers its own interface: the instance state changes,
	// box_ip does not.
	insp.containers[0].IPAddress = "10.100.0.99"
	if v = view(); v.HostIP != [4]byte{10, 100, 0, 7} || v.IP != [4]byte{10, 100, 0, 99} {
		t.Errorf("after a guest-side change: HostIP = %v IP = %v, want host .7 / guest .99", v.HostIP, v.IP)
	}
	plan := planReconcile([]containerView{v}, nil, true)
	if cfg := plan.vethPolicy[v.Ifindex]; cfg.BoxIP != [4]byte{10, 100, 0, 7} {
		t.Errorf("box_ip = %v after a guest-side change, want the host-leased .7", cfg.BoxIP)
	}

	// A static device address beats the lease.
	insp.staticIP = "10.100.0.5"
	e.vethCache = map[string]vethInfo{} // re-inspect, as a restart would
	if v = view(); v.HostIP != [4]byte{10, 100, 0, 5} {
		t.Errorf("HostIP with ipv4.address = %v, want 10.100.0.5", v.HostIP)
	}

	// Neither source: unknown. The guest-reported address is NOT a fallback,
	// so the program cannot validate this box and never seeds from it.
	insp.staticIP = ""
	writeLease("10.100.0.8") // for another MAC
	if err := os.WriteFile(filepath.Join(leaseDir, "testbr0", "dnsmasq.leases"), []byte("0 00:16:3e:00:00:01 10.100.0.8 other *\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.vethCache = map[string]vethInfo{}
	if v = view(); v.HasHostIP {
		t.Errorf("HostIP = %v with no host source, want unknown (no guest fallback)", v.HostIP)
	}
	plan = planReconcile([]containerView{v}, nil, true)
	if cfg := plan.vethPolicy[v.Ifindex]; cfg.BoxIP != [4]byte{} {
		t.Errorf("box_ip = %v with no host source, want 0", cfg.BoxIP)
	}
}

// #2618 B2: the control plane and an instance with no tenant are not policed,
// but every instance on the bridge gets a validate-only veth entry so the
// receiving side can tell a container frame from the host's. They never enter
// a tenant's status.
func TestGather_ValidateOnlyEntriesForUnpolicedInstances(t *testing.T) {
	veth := firstHostIface(t)
	insp := &fakeInspector{
		containers: []incus.ContainerInfo{
			{Name: "controlplane-container", State: "running", IPAddress: "10.100.0.200", Role: incus.RoleControlPlane},
			{Name: "cld-tenant-container", State: "running", IPAddress: "10.100.0.10"},
		},
		veth: veth, rawCalls: map[string]int{},
		network: "testbr0", staticIP: "10.100.0.200",
	}
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), insp, nil, nil, false)
	e.ctx = context.Background()
	e.leaseDir = t.TempDir()

	views, _, err := e.gather(context.Background())
	if err != nil || len(views) != 2 {
		t.Fatalf("gather: %v (%d views)", err, len(views))
	}
	var cp, tenant containerView
	for _, v := range views {
		if v.Name == "controlplane-container" {
			cp = v
		} else {
			tenant = v
		}
	}
	if !cp.ValidateOnly || cp.Tenant != "" || !cp.HasVeth || !cp.HasHostIP {
		t.Fatalf("control plane view = %+v, want validate-only with veth and host IP", cp)
	}
	if tenant.ValidateOnly {
		t.Fatalf("tenant view = %+v, must not be validate-only", tenant)
	}
	// Both views resolve the same host interface in this fixture; give the
	// control plane its own ifindex so the plan can hold both.
	cp.Ifindex = tenant.Ifindex + 1000
	plan := planReconcile([]containerView{cp, tenant}, map[string]netpolicy.CompiledPolicy{}, true)
	if cfg := plan.vethPolicy[cp.Ifindex]; cfg != netbpf.ValidateOnlyConfig([4]byte{10, 100, 0, 200}) {
		t.Errorf("control plane cfg = %+v, want ValidateOnlyConfig(10.100.0.200)", cfg)
	}
	if _, tagged := plan.ipTenant[[4]byte{10, 100, 0, 200}]; tagged {
		t.Error("control plane must stay out of ip_tenant (#780)")
	}
	loaded := map[int]bool{cp.Ifindex: true, tenant.Ifindex: true}
	applied := appliedFromPass([]containerView{cp, tenant}, plan, loaded, map[string]netpolicy.CompiledPolicy{}, nil, nil)
	if _, ok := applied[""]; ok {
		t.Errorf("applied state has an entry for the empty tenant: %+v", applied)
	}
	if a := applied[tenant.Tenant]; a.BoxesLoaded != 1 {
		t.Errorf("tenant applied = %+v, want 1 box loaded", a)
	}
}
