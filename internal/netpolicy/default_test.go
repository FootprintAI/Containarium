package netpolicy

import (
	"net/netip"
	"slices"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The default posture (#2577 stage 1) is observe-only by construction: a
// tenant with no stored policy must never be moved to enforce by it.
func TestDefaultPolicy_IsLogOnlyAllowList(t *testing.T) {
	got, err := DefaultPolicy("acme", DefaultEgressExtras{})
	if err != nil {
		t.Fatalf("DefaultPolicy: %v", err)
	}
	if got.Tenant != "acme" {
		t.Errorf("Tenant = %q, want acme", got.Tenant)
	}
	if !got.LogOnly || got.Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY {
		t.Errorf("Mode = %v LogOnly = %v, want LOG_ONLY", got.Mode, got.LogOnly)
	}
	if got.EffectiveEgressMode() != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY {
		t.Errorf("EffectiveEgressMode = %v, want LOG_ONLY", got.EffectiveEgressMode())
	}
	if got.EgressPreset != pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY {
		t.Errorf("EgressPreset = %v, want ALLOW_LIST_ONLY so the DNS resolver is implicit", got.EgressPreset)
	}
	if got.AllowMetadata {
		t.Error("the default must not allow the cloud metadata service")
	}
}

func TestDefaultPolicy_CoversTheDocumentedClasses(t *testing.T) {
	got, err := DefaultPolicy("acme", DefaultEgressExtras{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"github.com", "registry.npmjs.org", "pypi.org", "proxy.golang.org", "deb.debian.org"} {
		if !slices.Contains(got.EgressDomains, d) {
			t.Errorf("default allow-list is missing %q", d)
		}
	}
}

// The model gateway and control plane are deployment-specific, so the
// operator supplies them; they join the built-ins rather than replacing them.
func TestDefaultPolicy_ExtrasAreAdded(t *testing.T) {
	got, err := DefaultPolicy("acme", DefaultEgressExtras{
		Domains: []string{"Gateway.Example.com."},
		CIDRs:   []string{"10.9.0.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.EgressDomains, "gateway.example.com") {
		t.Errorf("extra domain not normalized+added: %v", got.EgressDomains)
	}
	if !slices.Contains(got.EgressCIDRs, netip.MustParsePrefix("10.9.0.0/24")) {
		t.Errorf("extra CIDR not added: %v", got.EgressCIDRs)
	}
	if !slices.Contains(got.EgressDomains, "github.com") {
		t.Error("extras must not replace the built-ins")
	}
}

func TestDefaultPolicy_BadExtraIsAnError(t *testing.T) {
	if _, err := DefaultPolicy("acme", DefaultEgressExtras{CIDRs: []string{"not-a-cidr"}}); err == nil {
		t.Error("an unparseable extra CIDR must be reported, not dropped")
	}
	if _, err := DefaultPolicy("acme", DefaultEgressExtras{Domains: []string{"https://x.example.com"}}); err == nil {
		t.Error("an extra domain with a scheme must be reported")
	}
	// The BPF compile is IPv4-only and its error would be swallowed by the plan,
	// emptying every no-policy tenant's allow-list: refuse it up front.
	if _, err := DefaultPolicy("acme", DefaultEgressExtras{CIDRs: []string{"2001:db8::/32"}}); err == nil {
		t.Error("an IPv6 extra CIDR must be refused")
	}
	if _, err := DefaultPolicy("  ", DefaultEgressExtras{}); err == nil {
		t.Error("an empty tenant must be refused")
	}
}

func TestDefaultEgressDomains_SortedAndUnique(t *testing.T) {
	d := DefaultEgressDomains()
	if !slices.IsSorted(d) {
		t.Error("DefaultEgressDomains must be sorted")
	}
	if len(slices.Compact(slices.Clone(d))) != len(d) {
		t.Error("DefaultEgressDomains has duplicates")
	}
	// A caller must not be able to mutate the built-in list.
	d[0] = "mutated.example.com"
	if DefaultEgressDomains()[0] == "mutated.example.com" {
		t.Error("DefaultEgressDomains returns shared backing storage")
	}
}

func TestParseDefaultEgress(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		enabled bool
	}{
		{"", true}, {"on", true}, {"log_only", true}, {"typo", true}, // a typo must not silently drop the posture
		{"off", false}, {" OFF ", false}, {"0", false}, {"false", false}, {"disabled", false},
	} {
		on, _ := ParseDefaultEgress(tc.mode, "", "")
		if on != tc.enabled {
			t.Errorf("ParseDefaultEgress(%q) enabled = %v, want %v", tc.mode, on, tc.enabled)
		}
	}
	_, x := ParseDefaultEgress("", " a.example.com, ,b.example.com ", "10.0.0.0/8,, 192.168.0.0/16")
	if !slices.Equal(x.Domains, []string{"a.example.com", "b.example.com"}) || !slices.Equal(x.CIDRs, []string{"10.0.0.0/8", "192.168.0.0/16"}) {
		t.Errorf("extras = %+v", x)
	}
}
