package coreguard

import (
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// fullInputs is a backend with every core role present, a control plane
// co-located on the bridge, and the daemon at the bridge gateway — the
// richest topology the table has to render.
func fullInputs() Inputs {
	return Inputs{
		BridgeCIDR:  netip.MustParsePrefix("10.100.0.0/24"),
		HostGateway: netip.MustParseAddr("10.100.0.1"),
		Core: map[incus.Role]netip.Addr{
			incus.RolePostgres:        netip.MustParseAddr("10.100.0.242"),
			incus.RoleVictoriaMetrics: netip.MustParseAddr("10.100.0.243"),
			incus.RoleOTelCollector:   netip.MustParseAddr("10.100.0.244"),
			incus.RoleSecurity:        netip.MustParseAddr("10.100.0.245"),
			incus.RoleGuacamole:       netip.MustParseAddr("10.100.0.246"),
			incus.RoleCaddy:           netip.MustParseAddr("10.100.0.241"),
		},
		ControlPlane: []netip.Addr{netip.MustParseAddr("10.100.0.200")},
	}
}

// rule is the comparable shape a test pins: who may reach which tcp ports.
type rule struct{ src, ports string }

func rulesOf(acl incus.ACLConfig) []rule {
	out := make([]rule, 0, len(acl.IngressRules))
	for _, r := range acl.IngressRules {
		out = append(out, rule{src: r.Source, ports: r.DestinationPort})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ports != out[j].ports {
			return out[i].ports < out[j].ports
		}
		return out[i].src < out[j].src
	})
	return out
}

func TestCompute_RoleTable(t *testing.T) {
	const (
		host   = "10.100.0.1/32"
		bridge = "10.100.0.0/24"
		cp     = "10.100.0.200/32"
		caddy  = "10.100.0.241/32"
		vm     = "10.100.0.243/32"
	)
	tests := []struct {
		role incus.Role
		want []rule
	}{
		{incus.RolePostgres, []rule{{host, "5432"}, {vm, "5432"}}},
		{incus.RoleVictoriaMetrics, []rule{{host, "3000"}, {caddy, "3000"}, {host, "8428,8880,9093,9094"}, {cp, "8428,8880,9093,9094"}}},
		{incus.RoleOTelCollector, []rule{{host, "13133,8888"}, {bridge, "4317,4318"}}},
		{incus.RoleCaddy, []rule{{host, "2019"}, {bridge, "80,443"}}},
		{incus.RoleSecurity, []rule{}},
		{incus.RoleGuacamole, []rule{{host, "8080"}, {caddy, "8080"}}},
	}

	pol, err := Compute(fullInputs())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if len(pol.UnknownRoles) != 0 {
		t.Fatalf("unexpected unknown roles: %v", pol.UnknownRoles)
	}
	if got, want := len(pol.ACLs), len(tests); got != want {
		t.Fatalf("Compute produced %d ACLs, want %d: %v", got, want, keysOf(pol.ACLs))
	}

	for _, tc := range tests {
		t.Run(string(tc.role), func(t *testing.T) {
			acl, ok := pol.ACLs[tc.role]
			if !ok {
				t.Fatalf("no ACL for %s", tc.role)
			}
			if acl.Name != ACLName(tc.role) {
				t.Errorf("ACL name = %q, want %q", acl.Name, ACLName(tc.role))
			}
			if len(acl.EgressRules) != 0 {
				t.Errorf("egress rules must be empty (egress is left open via the NIC default), got %v", acl.EgressRules)
			}
			got := rulesOf(acl)
			want := append([]rule(nil), tc.want...)
			sort.Slice(want, func(i, j int) bool {
				if want[i].ports != want[j].ports {
					return want[i].ports < want[j].ports
				}
				return want[i].src < want[j].src
			})
			if len(got) != len(want) {
				t.Fatalf("rules = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("rule[%d] = %v, want %v (all: %v)", i, got[i], want[i], got)
				}
			}
			for _, r := range acl.IngressRules {
				if r.Action != "allow" || r.Protocol != "tcp" {
					t.Errorf("rule %+v: every table rule is an explicit tcp allow", r)
				}
			}
		})
	}
}

// The whole point of the guard: the tenant bridge may reach exactly two
// things — the OTLP receiver and Caddy's public ports — and nothing on the
// data plane, whatever the rest of the table says.
func TestCompute_TenantCIDRNeverReachesDataPlane(t *testing.T) {
	in := fullInputs()
	pol, err := Compute(in)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	allowed := map[string]bool{
		string(incus.RoleOTelCollector) + ":4317,4318": true,
		string(incus.RoleCaddy) + ":80,443":            true,
	}
	seen := map[string]bool{}
	for role, acl := range pol.ACLs {
		for _, r := range acl.IngressRules {
			if r.Source != in.BridgeCIDR.String() {
				continue
			}
			key := string(role) + ":" + r.DestinationPort
			seen[key] = true
			if !allowed[key] {
				t.Errorf("bridge CIDR may reach %s — a tenant can reach the data plane", key)
			}
		}
	}
	for key := range allowed {
		if !seen[key] {
			t.Errorf("expected an intended bridge-wide rule for %s, none rendered", key)
		}
	}
}

func TestCompute_NoWildcardSources(t *testing.T) {
	pol, err := Compute(fullInputs())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	for role, acl := range pol.ACLs {
		for _, r := range acl.IngressRules {
			switch {
			case r.Source == "", r.Source == "0.0.0.0/0", r.Source == "::/0",
				strings.HasPrefix(r.Source, "@"):
				t.Errorf("%s: rule %+v has a wildcard source", role, r)
			case r.DestinationPort == "":
				t.Errorf("%s: rule %+v has no destination port", role, r)
			}
		}
	}
}

func TestCompute_UnknownRoleFailsClosed(t *testing.T) {
	in := fullInputs()
	in.Core[incus.Role("core-mystery")] = netip.MustParseAddr("10.100.0.250")

	pol, err := Compute(in)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	acl, ok := pol.ACLs[incus.Role("core-mystery")]
	if !ok {
		t.Fatal("an unknown core role must still get an ACL (so it is attached and default-drops)")
	}
	if len(acl.IngressRules) != 0 {
		t.Errorf("unknown role must have no allows, got %v", acl.IngressRules)
	}
	if len(pol.UnknownRoles) != 1 || pol.UnknownRoles[0] != "core-mystery" {
		t.Errorf("UnknownRoles = %v, want [core-mystery]", pol.UnknownRoles)
	}
}

// The control plane is platform infrastructure that tenants legitimately
// call and that must reach every box (#780); it is a *source* in the table,
// never a guarded subject. Listing it under Core must not produce an ACL.
func TestCompute_ControlPlaneIsNotASubject(t *testing.T) {
	in := fullInputs()
	in.Core[incus.RoleControlPlane] = netip.MustParseAddr("10.100.0.200")

	pol, err := Compute(in)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if _, ok := pol.ACLs[incus.RoleControlPlane]; ok {
		t.Error("control plane must not get a guard ACL")
	}
	if len(pol.UnknownRoles) != 0 {
		t.Errorf("control plane is known, not unknown: %v", pol.UnknownRoles)
	}
}

func TestCompute_MissingPeerOmitsRule(t *testing.T) {
	t.Run("no victoriametrics → postgres has only the host rule", func(t *testing.T) {
		in := fullInputs()
		delete(in.Core, incus.RoleVictoriaMetrics)
		pol, err := Compute(in)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		got := rulesOf(pol.ACLs[incus.RolePostgres])
		if len(got) != 1 || got[0] != (rule{"10.100.0.1/32", "5432"}) {
			t.Errorf("postgres rules = %v, want only the host gateway", got)
		}
	})
	t.Run("no control plane → victoriametrics has no control-plane rule", func(t *testing.T) {
		in := fullInputs()
		in.ControlPlane = nil
		pol, err := Compute(in)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		for _, r := range pol.ACLs[incus.RoleVictoriaMetrics].IngressRules {
			if r.Source == "10.100.0.200/32" {
				t.Errorf("control-plane rule rendered with no control plane present: %+v", r)
			}
		}
	})
	t.Run("no caddy → grafana has only the host rule", func(t *testing.T) {
		in := fullInputs()
		delete(in.Core, incus.RoleCaddy)
		pol, err := Compute(in)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		for _, r := range rulesOf(pol.ACLs[incus.RoleVictoriaMetrics]) {
			if r.ports == "3000" && r.src != "10.100.0.1/32" {
				t.Errorf("grafana rule %v with no caddy present", r)
			}
		}
	})
	t.Run("two control planes → two rules", func(t *testing.T) {
		in := fullInputs()
		in.ControlPlane = append(in.ControlPlane, netip.MustParseAddr("10.100.0.201"))
		pol, err := Compute(in)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		n := 0
		for _, r := range pol.ACLs[incus.RoleVictoriaMetrics].IngressRules {
			if r.Source == "10.100.0.200/32" || r.Source == "10.100.0.201/32" {
				n++
			}
		}
		if n != 2 {
			t.Errorf("control-plane rules = %d, want 2", n)
		}
	})
}

func TestCompute_RejectsBadInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Inputs)
	}{
		{"zero bridge", func(in *Inputs) { in.BridgeCIDR = netip.Prefix{} }},
		{"IPv6 bridge", func(in *Inputs) {
			in.BridgeCIDR = netip.MustParsePrefix("fd00::/64")
			in.HostGateway = netip.MustParseAddr("fd00::1")
		}},
		{"zero gateway", func(in *Inputs) { in.HostGateway = netip.Addr{} }},
		{"gateway outside the bridge", func(in *Inputs) { in.HostGateway = netip.MustParseAddr("192.168.1.1") }},
		{"core IP outside the bridge", func(in *Inputs) { in.Core[incus.RolePostgres] = netip.MustParseAddr("10.200.0.5") }},
		{"core IP zero", func(in *Inputs) { in.Core[incus.RolePostgres] = netip.Addr{} }},
		{"control plane outside the bridge", func(in *Inputs) { in.ControlPlane = []netip.Addr{netip.MustParseAddr("10.200.0.5")} }},
		{"core IP equals the gateway", func(in *Inputs) { in.Core[incus.RolePostgres] = in.HostGateway }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := fullInputs()
			tc.mutate(&in)
			if _, err := Compute(in); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestCompute_IsDeterministic(t *testing.T) {
	a, err := Compute(fullInputs())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		b, err := Compute(fullInputs())
		if err != nil {
			t.Fatal(err)
		}
		for role := range a.ACLs {
			ra, rb := a.ACLs[role].IngressRules, b.ACLs[role].IngressRules
			if len(ra) != len(rb) {
				t.Fatalf("%s: rule count differs between runs", role)
			}
			for j := range ra {
				if ra[j] != rb[j] {
					t.Fatalf("%s: rule order differs between runs — a reconciler would see phantom drift", role)
				}
			}
		}
	}
}

func TestACLName(t *testing.T) {
	tests := []struct {
		role incus.Role
		want string
	}{
		{incus.RolePostgres, "containarium-core-guard-postgres"},
		{incus.RoleVictoriaMetrics, "containarium-core-guard-victoriametrics"},
		{incus.Role("core-mystery"), "containarium-core-guard-mystery"},
	}
	for _, tc := range tests {
		if got := ACLName(tc.role); got != tc.want {
			t.Errorf("ACLName(%q) = %q, want %q", tc.role, got, tc.want)
		}
	}
}

func keysOf(m map[incus.Role]incus.ACLConfig) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}
