package coreguard

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeBackend is the smallest incus.Backend the reconciler needs: a
// container list, a server info, an ACL store and per-container NIC
// devices — with every write counted, because "writes nothing when
// converged" is the property most of these tests pin.
type fakeBackend struct {
	*incus.UnavailableBackend

	containers []incus.ContainerInfo
	listErr    error
	firewall   string

	acls    map[string]api.NetworkACL
	devices map[string]map[string]map[string]string // container → device → keys

	created  []string // ACL names
	updated  []string // ACL names
	nicAdds  []string // "container/device"
	keyWrite []string // "container/device"
	aclErr   error    // injected on Create/Update
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
	out := make([]incus.ContainerInfo, len(f.containers))
	copy(out, f.containers)
	return out, nil
}

func (f *fakeBackend) GetServerInfo() (*api.Server, error) {
	return &api.Server{
		ServerUntrusted: api.ServerUntrusted{APIExtensions: []string{"network_acl", "network_bridge_acl"}},
		Environment:     api.ServerEnvironment{Firewall: f.firewall},
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

// EnsureNICDevice mirrors the real client: a write only when the device
// is not already instance-local.
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

// SetDeviceConfig mirrors the real client: refuses a device that is not
// instance-local, writes only when a key differs.
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
	return len(f.created) + len(f.updated) + len(f.nicAdds) + len(f.keyWrite)
}

func core(name string, role incus.Role, ip string) incus.ContainerInfo {
	return incus.ContainerInfo{Name: name, Role: role, IPAddress: ip, State: "Running"}
}

func tenant(name, ip string) incus.ContainerInfo {
	return incus.ContainerInfo{Name: name, IPAddress: ip, State: "Running"}
}

func fullHost() *fakeBackend {
	return newFakeBackend("nftables",
		core("containarium-core-postgres", incus.RolePostgres, "10.100.0.242"),
		core("containarium-core-victoriametrics", incus.RoleVictoriaMetrics, "10.100.0.243"),
		core("containarium-core-caddy", incus.RoleCaddy, "10.100.0.241"),
		core("cloud-control-plane", incus.RoleControlPlane, "10.100.0.200"),
		tenant("alice-container", "10.100.0.17"),
	)
}

func enforceCfg() Config {
	return Config{Mode: ModeEnforce, Bridge: "incusbr0", BridgeCIDR: "10.100.0.1/24", NICDevice: "eth0"}
}

func TestReconcile_CreatesMissingACLsAndAttaches(t *testing.T) {
	f := fullHost()
	r := NewReconciler(f, enforceCfg())

	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}

	wantACLs := []string{ACLName(incus.RolePostgres), ACLName(incus.RoleVictoriaMetrics), ACLName(incus.RoleCaddy)}
	sort.Strings(wantACLs)
	got := append([]string(nil), f.created...)
	sort.Strings(got)
	if len(got) != len(wantACLs) {
		t.Fatalf("created ACLs = %v, want %v", got, wantACLs)
	}
	for i := range wantACLs {
		if got[i] != wantACLs[i] {
			t.Errorf("created[%d] = %q, want %q", i, got[i], wantACLs[i])
		}
	}

	// Postgres ACL carries the host + victoriametrics rules (the table).
	pg := f.acls[ACLName(incus.RolePostgres)]
	srcs := map[string]bool{}
	for _, rule := range pg.Ingress {
		srcs[rule.Source] = true
	}
	if !srcs["10.100.0.1/32"] || !srcs["10.100.0.243/32"] || len(pg.Ingress) != 2 {
		t.Errorf("postgres ACL rules = %+v", pg.Ingress)
	}

	// Every core NIC is instance-local and carries the guard keys.
	for _, c := range []string{"containarium-core-postgres", "containarium-core-victoriametrics", "containarium-core-caddy"} {
		dev := f.devices[c]["eth0"]
		if dev == nil {
			t.Fatalf("%s: eth0 not made instance-local", c)
		}
		want := map[string]string{
			"security.acls":                        ACLName(f.roleOf(c)),
			"security.acls.default.ingress.action": "drop",
			"security.acls.default.ingress.logged": "true",
			"security.acls.default.egress.action":  "allow",
		}
		for k, v := range want {
			if dev[k] != v {
				t.Errorf("%s eth0[%q] = %q, want %q", c, k, dev[k], v)
			}
		}
	}

	// Neither the tenant nor the control plane is touched.
	for _, c := range []string{"alice-container", "cloud-control-plane"} {
		if _, ok := f.devices[c]; ok {
			t.Errorf("%s must not be touched by the guard", c)
		}
	}

	st := r.Status()
	if st.Mode != ModeEnforce || st.FirewallDriver != "nftables" || !st.StaleSince.IsZero() {
		t.Errorf("status = %+v", st)
	}
	if len(st.Entries) != 3 {
		t.Fatalf("status entries = %+v, want 3", st.Entries)
	}
	for _, e := range st.Entries {
		if !e.Attached || e.LastError != "" {
			t.Errorf("entry %+v not attached cleanly", e)
		}
	}
}

func (f *fakeBackend) roleOf(container string) incus.Role {
	for _, c := range f.containers {
		if c.Name == container {
			return c.Role
		}
	}
	return incus.RoleNone
}

func TestReconcile_IdempotentSecondPassWritesNothing(t *testing.T) {
	f := fullHost()
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := f.writes()
	if before == 0 {
		t.Fatal("first pass wrote nothing — fixture is wrong")
	}

	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.writes() != before {
		t.Fatalf("second pass wrote: created=%v updated=%v nicAdds=%v keys=%v", f.created, f.updated, f.nicAdds, f.keyWrite)
	}
}

func TestReconcile_UpdatesOnlyOnDrift(t *testing.T) {
	f := fullHost()
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.created, f.updated = nil, nil

	// victoriametrics moves: only the ACLs that reference its address
	// (postgres) must change.
	for i := range f.containers {
		if f.containers[i].Role == incus.RoleVictoriaMetrics {
			f.containers[i].IPAddress = "10.100.0.99"
		}
	}
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 0 {
		t.Errorf("unexpected creates: %v", f.created)
	}
	if len(f.updated) != 1 || f.updated[0] != ACLName(incus.RolePostgres) {
		t.Fatalf("updated = %v, want only the postgres ACL", f.updated)
	}
	pg := f.acls[ACLName(incus.RolePostgres)]
	found := false
	for _, rule := range pg.Ingress {
		if rule.Source == "10.100.0.99/32" {
			found = true
		}
		if rule.Source == "10.100.0.243/32" {
			t.Errorf("stale victoriametrics address still allowed: %+v", rule)
		}
	}
	if !found {
		t.Errorf("postgres ACL not re-rendered with the new address: %+v", pg.Ingress)
	}
}

func TestReconcile_ListErrorWritesNothing(t *testing.T) {
	f := fullHost()
	f.listErr = errors.New("incus socket gone")
	r := NewReconciler(f, enforceCfg())

	err := r.ReconcileOnce(context.Background())
	if !errors.Is(err, f.listErr) {
		t.Fatalf("err = %v, want wrapping the list error", err)
	}
	if f.writes() != 0 {
		t.Fatalf("wrote on a failed read: created=%v nic=%v", f.created, f.nicAdds)
	}
	st := r.Status()
	if st.StaleSince.IsZero() || st.LastError == "" {
		t.Errorf("status must record staleness: %+v", st)
	}

	// Recovery clears staleness.
	f.listErr = nil
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); !st.StaleSince.IsZero() || st.LastError != "" {
		t.Errorf("status still stale after a good pass: %+v", st)
	}
}

func TestReconcile_ModeOffWritesNothingButReportsStatus(t *testing.T) {
	f := fullHost()
	cfg := enforceCfg()
	cfg.Mode = ModeOff
	r := NewReconciler(f, cfg)

	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("off mode must not error: %v", err)
	}
	if f.writes() != 0 {
		t.Fatalf("off mode wrote: created=%v nic=%v", f.created, f.nicAdds)
	}
	if st := r.Status(); st.Mode != ModeOff {
		t.Errorf("status mode = %q, want off", st.Mode)
	}
}

func TestReconcile_UnsupportedFirewallDriverRefuses(t *testing.T) {
	f := fullHost()
	f.firewall = "xtables"
	r := NewReconciler(f, enforceCfg())

	err := r.ReconcileOnce(context.Background())
	if !errors.Is(err, ErrUnsupportedFirewall) {
		t.Fatalf("err = %v, want ErrUnsupportedFirewall", err)
	}
	if f.writes() != 0 {
		t.Fatalf("attached ACLs on a driver that cannot enforce them: created=%v nic=%v", f.created, f.nicAdds)
	}
	if st := r.Status(); st.FirewallDriver != "xtables" || st.LastError == "" {
		t.Errorf("status = %+v", st)
	}
}

func TestReconcile_CoreWithoutIPIsSkippedThisPass(t *testing.T) {
	f := fullHost()
	for i := range f.containers {
		if f.containers[i].Role == incus.RoleVictoriaMetrics {
			f.containers[i].IPAddress = "" // still booting
		}
	}
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("a booting core container must not fail the pass: %v", err)
	}
	if _, ok := f.acls[ACLName(incus.RoleVictoriaMetrics)]; ok {
		t.Error("ACL rendered for a container with no address")
	}
	pg := f.acls[ACLName(incus.RolePostgres)]
	if len(pg.Ingress) != 1 || pg.Ingress[0].Source != "10.100.0.1/32" {
		t.Errorf("postgres should have only the host rule this pass: %+v", pg.Ingress)
	}
	var vmEntry *Entry
	for i := range r.Status().Entries {
		if r.Status().Entries[i].Role == incus.RoleVictoriaMetrics {
			vmEntry = &r.Status().Entries[i]
		}
	}
	if vmEntry == nil || vmEntry.Attached || vmEntry.LastError == "" {
		t.Errorf("status must say why victoriametrics is not guarded yet: %+v", vmEntry)
	}

	// Next pass, it has an address: its ACL appears and postgres picks it up.
	for i := range f.containers {
		if f.containers[i].Role == incus.RoleVictoriaMetrics {
			f.containers[i].IPAddress = "10.100.0.243"
		}
	}
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.acls[ACLName(incus.RoleVictoriaMetrics)]; !ok {
		t.Error("victoriametrics ACL not created once it had an address")
	}
	if pg := f.acls[ACLName(incus.RolePostgres)]; len(pg.Ingress) != 2 {
		t.Errorf("postgres not re-rendered with the victoriametrics rule: %+v", pg.Ingress)
	}
}

func TestReconcile_UnknownRoleGetsEmptyACLAndIsReported(t *testing.T) {
	f := fullHost()
	f.containers = append(f.containers, core("containarium-core-mystery", incus.Role("core-mystery"), "10.100.0.250"))
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	acl, ok := f.acls[ACLName(incus.Role("core-mystery"))]
	if !ok {
		t.Fatal("unknown role must still get an ACL so it default-drops")
	}
	if len(acl.Ingress) != 0 {
		t.Errorf("unknown role has allows: %+v", acl.Ingress)
	}
	if dev := f.devices["containarium-core-mystery"]["eth0"]; dev == nil || dev["security.acls"] != acl.Name {
		t.Errorf("unknown role not attached: %v", dev)
	}
	if st := r.Status(); len(st.UnknownRoles) != 1 || st.UnknownRoles[0] != "core-mystery" {
		t.Errorf("status.UnknownRoles = %v", st.UnknownRoles)
	}
}

func TestReconcile_ACLWriteErrorIsRecordedAndRetried(t *testing.T) {
	f := fullHost()
	f.aclErr = errors.New("incus: acl api unavailable")
	r := NewReconciler(f, enforceCfg())

	if err := r.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("expected the pass to report the write failure")
	}
	if len(f.nicAdds) != 0 {
		t.Errorf("must not attach a NIC to an ACL that failed to be written: %v", f.nicAdds)
	}
	for _, e := range r.Status().Entries {
		if e.Attached || e.LastError == "" {
			t.Errorf("entry %+v should carry the write error", e)
		}
	}

	f.aclErr = nil
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("retry after the error cleared: %v", err)
	}
	if len(f.created) != 3 {
		t.Errorf("retry did not create the ACLs: %v", f.created)
	}
}

func TestParseBridge(t *testing.T) {
	tests := []struct {
		in         string
		wantBridge string
		wantGW     string
		wantErr    bool
	}{
		{"10.100.0.1/24", "10.100.0.0/24", "10.100.0.1", false}, // incus ipv4.address form
		{"10.100.0.0/24", "10.100.0.0/24", "10.100.0.1", false}, // network form: gateway is base+1 by incus convention
		{"10.0.3.1/24", "10.0.3.0/24", "10.0.3.1", false},
		{"", "", "", true},
		{"nonsense", "", "", true},
		{"fd00::1/64", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			bridge, gw, err := parseBridge(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if bridge.String() != tc.wantBridge || gw.String() != tc.wantGW {
				t.Errorf("parseBridge(%q) = %s, %s; want %s, %s", tc.in, bridge, gw, tc.wantBridge, tc.wantGW)
			}
		})
	}
}

// Unset arms the guard (it is a boundary, not optional hardening — see
// docs/architecture/tenant-network-guard.md, Rollout); only an explicit
// off-word disables. The full table lives in internal/nicguard.
func TestParseMode(t *testing.T) {
	tests := []struct {
		in   string
		want Mode
	}{
		{"enforce", ModeEnforce},
		{"", ModeEnforce},
		{"off", ModeOff},
		{"1", ModeEnforce},
		{"Enforce", ModeEnforce},
	}
	for _, tc := range tests {
		if got := ParseMode(tc.in); got != tc.want {
			t.Errorf("ParseMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
