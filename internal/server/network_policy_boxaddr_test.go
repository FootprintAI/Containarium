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

// #2618 B1 + S4: gather() takes the address the program validates a box against
// (view.HostIP -> policy_cfg.box_ip) from the host — the NIC's static
// ipv4.address, else the bridge's DHCP lease — and never from c.IPAddress alone,
// which is what the guest configured on itself. A lease counts only when it
// agrees with the guest-reported address: a neighbour can move a lease with a
// forged DHCP release/request naming another box's MAC, and the guest can
// renumber itself; either disagreement makes the address UNKNOWN (fail closed),
// never a guess from one side.
func TestGather_BoxAddressIsHostKnownNotGuestReported(t *testing.T) {
	veth := firstHostIface(t)
	const mac = "00:16:3e:aa:bb:cc"
	dataDir := t.TempDir() // stands in for the Incus data dir; leases live under <data dir>/networks
	leaseDir := filepath.Join(dataDir, "networks")
	if err := os.MkdirAll(filepath.Join(leaseDir, "testbr0"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLease := func(entries string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(leaseDir, "testbr0", "dnsmasq.leases"), []byte(entries), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeLease("0 " + mac + " 10.100.0.7 web *\n")

	insp := &fakeInspector{
		containers: []incus.ContainerInfo{{Name: "web-container", State: "running", IPAddress: "10.100.0.7"}},
		veth:       veth, rawCalls: map[string]int{},
		network: "testbr0", hwaddr: mac,
	}
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), insp, nil, nil, false)
	e.ctx = context.Background()
	e.SetIncusDataDir(dataDir)
	if e.leaseDir != leaseDir {
		t.Fatalf("leaseDir = %q, want %q (derived from the Incus data dir)", e.leaseDir, leaseDir)
	}

	view := func() containerView {
		t.Helper()
		views, _, err := e.gather(context.Background())
		if err != nil || len(views) != 1 {
			t.Fatalf("gather: %v (%d views)", err, len(views))
		}
		return views[0]
	}

	// Lease and guest agree: the address is known. The guest IP is still kept
	// separately for ip_tenant.
	v := view()
	if !v.HasVeth {
		t.Fatalf("view has no veth: %+v", v)
	}
	if !v.HasHostIP || v.HostIP != [4]byte{10, 100, 0, 7} || !v.HasIP || v.IP != [4]byte{10, 100, 0, 7} {
		t.Fatalf("view = %+v, want HostIP and IP = 10.100.0.7", v)
	}
	if e.addrWarned["web-container"] {
		t.Error("warned about an unknown address although it is known")
	}

	// Root in the box renumbers its own interface: the guest report changes, the
	// lease does not — the address becomes UNKNOWN (not the new guest value, not
	// the stale lease), and the daemon warns once.
	insp.containers[0].IPAddress = "10.100.0.99"
	if v = view(); v.HasHostIP || v.IP != [4]byte{10, 100, 0, 99} {
		t.Errorf("after a guest-side renumber: HostIP = %v (%v) IP = %v, want unknown / guest .99", v.HostIP, v.HasHostIP, v.IP)
	}
	if !e.addrWarned["web-container"] {
		t.Error("expected a once-only warning that the host knows no address")
	}
	plan := planReconcile([]containerView{v}, nil, true)
	if cfg := plan.vethPolicy[v.Ifindex]; cfg.BoxIP != [4]byte{} {
		t.Errorf("box_ip = %v after a guest-side change, want 0 (fail closed)", cfg.BoxIP)
	}
	insp.containers[0].IPAddress = "10.100.0.7"
	if v = view(); !v.HasHostIP || e.addrWarned["web-container"] {
		t.Errorf("after the guest agrees again: HasHostIP=%v warned=%v, want known and warning cleared", v.HasHostIP, e.addrWarned["web-container"])
	}

	// Lease poisoning: a neighbour moves this MAC's lease to another address
	// (forged DHCP release/request). The guest still really has .7, so the box's
	// genuine traffic must NOT become "spoofed": the address is unknown rather
	// than the attacker's choice. (Leases are re-read every pass.)
	writeLease("0 " + mac + " 10.100.0.200 web *\n")
	if v = view(); v.HasHostIP {
		t.Errorf("poisoned lease was trusted: HostIP = %v, want unknown", v.HostIP)
	}
	writeLease("0 " + mac + " 10.100.0.7 web *\n")

	// A static device address beats both and needs no agreement.
	insp.staticIP = "10.100.0.5"
	insp.containers[0].IPAddress = "10.100.0.42"
	e.vethCache = map[string]vethInfo{} // re-inspect, as a restart would
	if v = view(); !v.HasHostIP || v.HostIP != [4]byte{10, 100, 0, 5} {
		t.Errorf("HostIP with ipv4.address = %v (%v), want 10.100.0.5", v.HostIP, v.HasHostIP)
	}

	// No static address and a lease for a different MAC only: unknown — the
	// guest-reported address is never a fallback.
	insp.staticIP = ""
	writeLease("0 00:16:3e:00:00:01 10.100.0.8 other *\n")
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
