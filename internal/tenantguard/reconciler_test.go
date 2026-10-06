package tenantguard

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/footprintai/containarium/internal/nicguard"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeBackend is the smallest incus.Backend the reconciler needs, with
// every write counted: "writes nothing when converged" is the property
// most of these tests pin.
type fakeBackend struct {
	*incus.UnavailableBackend

	containers  []incus.ContainerInfo
	listErr     error
	firewall    string
	noBridgeACL bool // Incus 6.0.0: no network_bridge_acl_devices extension

	acls    map[string]api.NetworkACL
	devices map[string]map[string]map[string]string // container → device → keys

	created  []string
	updated  []string
	deleted  []string
	nicAdds  []string
	keyWrite []string
	aclErr   error
}

func newFakeBackend(firewall string, containers ...incus.ContainerInfo) *fakeBackend {
	return &fakeBackend{
		UnavailableBackend: incus.NewUnavailableBackend(),
		containers:         containers,
		firewall:           firewall,
		acls:               map[string]api.NetworkACL{},
		devices:            map[string]map[string]map[string]string{},
	}
}

func (f *fakeBackend) ListContainers() ([]incus.ContainerInfo, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]incus.ContainerInfo(nil), f.containers...), nil
}

func (f *fakeBackend) GetServerInfo() (*api.Server, error) {
	exts := []string{"network_acl", "network_bridge_acl", "network_bridge_acl_devices"}
	if f.noBridgeACL {
		exts = []string{"network_acl", "network_bridge_acl"} // Incus 6.0.0
	}
	return &api.Server{
		ServerUntrusted: api.ServerUntrusted{APIExtensions: exts},
		Environment:     api.ServerEnvironment{Firewall: f.firewall, ServerVersion: "7.4"},
	}, nil
}

func (f *fakeBackend) GetNetworkACL(name string) (*api.NetworkACL, error) {
	acl, ok := f.acls[name]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := acl
	return &cp, nil
}

func toAPI(cfg incus.ACLConfig) api.NetworkACL {
	var in []api.NetworkACLRule
	for _, r := range cfg.IngressRules {
		in = append(in, api.NetworkACLRule{Action: r.Action, Source: r.Source, Destination: r.Destination,
			Protocol: r.Protocol, DestinationPort: r.DestinationPort, Description: r.Description, State: "enabled"})
	}
	return api.NetworkACL{
		NetworkACLPost: api.NetworkACLPost{Name: cfg.Name},
		NetworkACLPut:  api.NetworkACLPut{Description: cfg.Description, Ingress: in},
	}
}

func (f *fakeBackend) CreateNetworkACL(cfg incus.ACLConfig) error {
	if f.aclErr != nil {
		return f.aclErr
	}
	if _, exists := f.acls[cfg.Name]; exists {
		return errors.New("already exists")
	}
	f.acls[cfg.Name] = toAPI(cfg)
	f.created = append(f.created, cfg.Name)
	return nil
}

func (f *fakeBackend) UpdateNetworkACL(name string, cfg incus.ACLConfig) error {
	if f.aclErr != nil {
		return f.aclErr
	}
	if _, exists := f.acls[name]; !exists {
		return errors.New("not found")
	}
	f.acls[name] = toAPI(cfg)
	f.updated = append(f.updated, name)
	return nil
}

func (f *fakeBackend) ListNetworkACLs() ([]api.NetworkACL, error) {
	out := make([]api.NetworkACL, 0, len(f.acls))
	for _, a := range f.acls {
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeBackend) DeleteNetworkACL(name string) error {
	for _, devs := range f.devices {
		for _, dev := range devs {
			for _, n := range strings.Split(dev["security.acls"], ",") {
				if n == name {
					return errors.New("acl in use")
				}
			}
		}
	}
	delete(f.acls, name)
	f.deleted = append(f.deleted, name)
	return nil
}

func (f *fakeBackend) EnsureNICDevice(container string, want incus.NICDevice) error {
	if f.devices[container] == nil {
		f.devices[container] = map[string]map[string]string{}
	}
	if _, ok := f.devices[container][want.Name]; ok {
		return nil
	}
	f.devices[container][want.Name] = map[string]string{"type": "nic", "name": want.Name, "network": want.Network}
	f.nicAdds = append(f.nicAdds, container+"/"+want.Name)
	return nil
}

func (f *fakeBackend) SetDeviceConfig(container, device string, keys map[string]string) error {
	dev, ok := f.devices[container][device]
	if !ok {
		return errors.New("device " + device + " not instance-local on " + container)
	}
	changed := false
	for k, v := range keys {
		if dev[k] != v {
			dev[k] = v
			changed = true
		}
	}
	if changed {
		f.keyWrite = append(f.keyWrite, container+"/"+device)
	}
	return nil
}

func (f *fakeBackend) writes() int {
	return len(f.created) + len(f.updated) + len(f.deleted) + len(f.nicAdds) + len(f.keyWrite)
}

func core(name string, role incus.Role, ip string) incus.ContainerInfo {
	return incus.ContainerInfo{Name: name, Role: role, IPAddress: ip, State: "Running"}
}

// box is a tenant container named by convention (<tenant>-container).
func box(tenant, ip string) incus.ContainerInfo {
	return incus.ContainerInfo{Name: tenant + "-container", IPAddress: ip, State: "Running"}
}

// cloudBox is a cloud-created container: an opaque name and the
// cloud_org_id attribution label.
func cloudBox(name, org, ip string) incus.ContainerInfo {
	return incus.ContainerInfo{Name: name, IPAddress: ip, State: "Running", Labels: map[string]string{incus.CloudOrgIDLabel: org}}
}

func twoTenantHost() *fakeBackend {
	return newFakeBackend("nftables",
		core("containarium-core-postgres", incus.RolePostgres, "10.100.0.242"),
		core("containarium-core-caddy", incus.RoleCaddy, "10.100.0.241"),
		box("alice", "10.100.0.17"),
		cloudBox("cld-1a2b3c", "org-a", "10.100.0.18"),
		cloudBox("cld-4d5e6f", "org-a", "10.100.0.19"),
		box("bob", "10.100.0.33"),
	)
}

func enforceCfg() Config {
	return Config{Mode: nicguard.ModeEnforce, Bridge: "incusbr0", BridgeCIDR: "10.100.0.1/24", NICDevice: "eth0"}
}

func srcSet(acl api.NetworkACL) map[string]bool {
	out := map[string]bool{}
	for _, r := range acl.Ingress {
		out[r.Source] = true
	}
	return out
}

func TestReconcile_FirstPassGuardsEveryTenantBox(t *testing.T) {
	f := twoTenantHost()
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}

	want := []string{ACLName("alice"), ACLName("org-a"), ACLName("bob")}
	sort.Strings(want)
	got := append([]string(nil), f.created...)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("created ACLs = %v, want %v", got, want)
	}

	// org-a's ACL admits host, caddy and both org-a boxes; not alice, bob
	// or postgres.
	orgA := srcSet(f.acls[ACLName("org-a")])
	for _, s := range []string{"10.100.0.1/32", "10.100.0.241/32", "10.100.0.18/32", "10.100.0.19/32"} {
		if !orgA[s] {
			t.Errorf("org-a ACL missing %s: %v", s, orgA)
		}
	}
	for _, s := range []string{"10.100.0.17/32", "10.100.0.33/32", "10.100.0.242/32"} {
		if orgA[s] {
			t.Errorf("org-a ACL must not admit %s", s)
		}
	}

	// Every tenant NIC is instance-local with the guard keys; core NICs are
	// untouched.
	for _, c := range []string{"alice-container", "cld-1a2b3c", "cld-4d5e6f", "bob-container"} {
		dev := f.devices[c]["eth0"]
		if dev == nil {
			t.Fatalf("%s: eth0 not made instance-local", c)
		}
		if dev["security.acls.default.ingress.action"] != "drop" || dev["security.acls.default.egress.action"] != "allow" || dev["security.acls"] == "" {
			t.Errorf("%s: guard keys = %v", c, dev)
		}
	}
	if f.devices["containarium-core-postgres"] != nil || f.devices["containarium-core-caddy"] != nil {
		t.Error("core NICs must not be touched by the tenant guard")
	}

	st := r.Status()
	if st.Tenants != 3 || len(st.Entries) != 4 || st.LastError != "" {
		t.Errorf("status = %+v", st)
	}
	for _, e := range st.Entries {
		if !e.Attached {
			t.Errorf("entry not attached: %+v", e)
		}
	}
}

func TestReconcile_SecondPassWritesNothing(t *testing.T) {
	f := twoTenantHost()
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := f.writes()
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.writes() != before {
		t.Errorf("converged pass wrote: created=%v updated=%v deleted=%v nic=%v keys=%v", f.created, f.updated, f.deleted, f.nicAdds, f.keyWrite)
	}
}

func TestReconcile_NewSiblingUpdatesExactlyOneACL(t *testing.T) {
	f := twoTenantHost()
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.containers = append(f.containers, box("alice", "")) // duplicate name is fine for the fake; use a distinct one
	f.containers[len(f.containers)-1].Name = "alice-db-container"
	f.containers[len(f.containers)-1].Labels = map[string]string{incus.CloudOrgIDLabel: "alice"}
	f.containers[len(f.containers)-1].IPAddress = "10.100.0.20"
	f.updated = nil
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.updated) != 1 || f.updated[0] != ACLName("alice") {
		t.Errorf("updated = %v, want only alice's ACL", f.updated)
	}
	if !srcSet(f.acls[ACLName("alice")])["10.100.0.20/32"] {
		t.Error("alice's ACL does not admit the new sibling")
	}
	if srcSet(f.acls[ACLName("bob")])["10.100.0.20/32"] {
		t.Error("bob's ACL admits alice's new box")
	}
}

func TestReconcile_LastBoxGoneDeletesTenantACL(t *testing.T) {
	f := twoTenantHost()
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// bob leaves the host (container and its NIC are gone).
	var keep []incus.ContainerInfo
	for _, c := range f.containers {
		if c.Name != "bob-container" {
			keep = append(keep, c)
		}
	}
	f.containers = keep
	delete(f.devices, "bob-container")
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != ACLName("bob") {
		t.Errorf("deleted = %v, want bob's ACL", f.deleted)
	}
	if _, still := f.acls[ACLName("alice")]; !still {
		t.Error("alice's ACL was removed")
	}
}

func TestReconcile_UnsupportedFirewall(t *testing.T) {
	f := twoTenantHost()
	f.firewall = "xtables"
	r := NewReconciler(f, enforceCfg())
	err := r.ReconcileOnce(context.Background())
	if !errors.Is(err, nicguard.ErrUnsupportedFirewall) {
		t.Fatalf("err = %v, want ErrUnsupportedFirewall", err)
	}
	if f.writes() != 0 {
		t.Errorf("wrote on an unsupported driver: %d writes", f.writes())
	}
	st := r.Status()
	if st.LastError == "" || st.FirewallDriver != "xtables" || st.StaleSince.IsZero() || !st.Unsupported {
		t.Errorf("status = %+v", st)
	}
}

func TestReconcile_IncusWithoutBridgeACLs(t *testing.T) {
	f := twoTenantHost()
	f.noBridgeACL = true
	r := NewReconciler(f, enforceCfg())
	err := r.ReconcileOnce(context.Background())
	if !errors.Is(err, nicguard.ErrUnsupportedIncus) {
		t.Fatalf("err = %v, want ErrUnsupportedIncus", err)
	}
	if f.writes() != 0 {
		t.Errorf("wrote on an Incus without bridge ACLs: %d writes", f.writes())
	}
	if st := r.Status(); !st.Unsupported {
		t.Errorf("status.Unsupported = false; %+v", st)
	}
}

// On a host that cannot carry NIC ACLs at all, Prepare must not turn the
// missing capability into an outage: the create proceeds unguarded and the
// gap is reported, while a capable host still fails closed.
func TestPrepare_UnsupportedHostIsFailOpen(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*fakeBackend)
	}{
		{"xtables driver", func(f *fakeBackend) { f.firewall = "xtables" }},
		{"incus without network_bridge_acl", func(f *fakeBackend) { f.noBridgeACL = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := twoTenantHost()
			tc.mut(f)
			r := NewReconciler(f, enforceCfg())
			if err := r.Prepare(context.Background(), "cld-new", "org-new"); err != nil {
				t.Fatalf("Prepare on an unsupported host must not refuse the create: %v", err)
			}
			if f.writes() != 0 {
				t.Errorf("wrote on an unsupported host: %d writes", f.writes())
			}
		})
	}
}

func TestReconcile_ACLWriteFailureIsPerTenant(t *testing.T) {
	f := twoTenantHost()
	r := NewReconciler(f, enforceCfg())
	f.aclErr = errors.New("incus: boom")
	err := r.ReconcileOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	// No ACL could be written, so nothing may be attached — attaching a
	// missing ACL would be refused by Incus anyway.
	if len(f.keyWrite) != 0 {
		t.Errorf("attached NICs although ACLs failed: %v", f.keyWrite)
	}
	st := r.Status()
	for _, e := range st.Entries {
		if e.Attached || e.LastError == "" {
			t.Errorf("entry should carry the error: %+v", e)
		}
	}
}

func TestReconcile_UnresolvedIsReportedNotGuessed(t *testing.T) {
	f := newFakeBackend("nftables",
		box("alice", "10.100.0.17"),
		incus.ContainerInfo{Name: "mystery", IPAddress: "10.100.0.50", State: "Running"},
	)
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := r.Status()
	if len(st.Unresolved) != 1 || st.Unresolved[0] != "mystery" {
		t.Errorf("Unresolved = %v", st.Unresolved)
	}
	if f.devices["mystery"] != nil {
		t.Error("an unresolved container must not be guarded under a guessed tenant")
	}
	// ...and alice's ACL must not admit it either.
	if srcSet(f.acls[ACLName("alice")])["10.100.0.50/32"] {
		t.Error("alice's ACL admits the unresolved container")
	}
}

func TestReconcile_OffWritesNothing(t *testing.T) {
	f := twoTenantHost()
	cfg := enforceCfg()
	cfg.Mode = nicguard.ModeOff
	r := NewReconciler(f, cfg)
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.writes() != 0 {
		t.Errorf("off mode wrote %d times", f.writes())
	}
	if r.Status().Mode != nicguard.ModeOff {
		t.Errorf("status mode = %q", r.Status().Mode)
	}
}

// Prepare: a box that was just created (not yet listed with an address)
// gets its tenant's ACL created and attached before it starts, so there is
// no window in which co-tenants can reach it.
func TestPrepare_FirstBoxOfATenant(t *testing.T) {
	f := twoTenantHost()
	r := NewReconciler(f, enforceCfg())
	f.containers = append(f.containers, incus.ContainerInfo{Name: "cld-new", State: "Stopped"})
	if err := r.Prepare(context.Background(), "cld-new", "org-new"); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	acl, ok := f.acls[ACLName("org-new")]
	if !ok {
		t.Fatal("tenant ACL not created")
	}
	s := srcSet(acl)
	if !s["10.100.0.1/32"] || !s["10.100.0.241/32"] {
		t.Errorf("ACL lacks host/caddy: %v", s)
	}
	for _, other := range []string{"10.100.0.17/32", "10.100.0.18/32", "10.100.0.33/32"} {
		if s[other] {
			t.Errorf("new tenant's ACL admits a foreign box %s", other)
		}
	}
	dev := f.devices["cld-new"]["eth0"]
	if dev == nil || dev["security.acls"] != ACLName("org-new") || dev["security.acls.default.ingress.action"] != "drop" {
		t.Errorf("NIC not guarded at birth: %v", dev)
	}
}

func TestPrepare_FailsClosed(t *testing.T) {
	f := twoTenantHost()
	r := NewReconciler(f, enforceCfg())
	f.aclErr = errors.New("incus: boom")
	if err := r.Prepare(context.Background(), "cld-new", "org-new"); err == nil {
		t.Fatal("expected Prepare to fail when the ACL cannot be written")
	}
	if f.devices["cld-new"] != nil {
		t.Error("NIC must not be touched when the ACL failed")
	}
	f.aclErr = nil
	if err := r.Prepare(context.Background(), "cld-new", ""); err == nil {
		t.Error("expected an error for an empty tenant")
	}
}

func TestPrepare_OffIsNoop(t *testing.T) {
	f := twoTenantHost()
	cfg := enforceCfg()
	cfg.Mode = nicguard.ModeOff
	r := NewReconciler(f, cfg)
	if err := r.Prepare(context.Background(), "cld-new", "org-new"); err != nil {
		t.Fatal(err)
	}
	if f.writes() != 0 {
		t.Errorf("off mode wrote %d times", f.writes())
	}
}
