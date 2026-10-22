package netpolicy

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func row(t time.Time, dst string, proto, dport int, dropped, vpatch bool) DenyRow {
	b := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}
	return DenyRow{Time: t, Detail: `{"src":"10.0.0.5","dst":"` + dst + `","proto":` + itoa(proto) +
		`,"dport":` + itoa(dport) + `,"dropped":` + b(dropped) + `,"virtual_patch":` + b(vpatch) + `}`}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestAggregateDenies_GroupsCountsAndOrders(t *testing.T) {
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	rows := []DenyRow{
		row(t0, "140.82.112.3", 6, 443, false, false),
		row(t0.Add(time.Minute), "140.82.112.3", 6, 443, true, false),
		row(t0.Add(2*time.Minute), "140.82.112.3", 6, 443, false, false),
		row(t0, "8.8.8.8", 17, 53, false, false),
		row(t0, "140.82.112.3", 6, 22, false, false), // same IP, different port: separate row
	}
	got := AggregateDenies(rows, nil)
	if len(got) != 3 {
		t.Fatalf("got %d destinations: %+v", len(got), got)
	}
	if got[0].IP.String() != "140.82.112.3" || got[0].Port != 443 || got[0].Proto != "tcp" || got[0].Count != 3 {
		t.Errorf("busiest = %+v", got[0])
	}
	if !got[0].Dropped {
		t.Error("one dropped flow must mark the destination dropped")
	}
	if !got[0].LastSeen.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("LastSeen = %v", got[0].LastSeen)
	}
	if got[1].Count != 1 || got[2].Count != 1 {
		t.Errorf("tail = %+v", got[1:])
	}
}

func TestAggregateDenies_SkipsVirtualPatchGarbageAndAllowed(t *testing.T) {
	t0 := time.Now()
	rows := []DenyRow{
		row(t0, "1.2.3.4", 6, 6379, true, true), // operator's deliberate block
		{Time: t0, Detail: "not json"},
		{Time: t0, Detail: `{"dst":"not-an-ip"}`},
		{Time: t0, Detail: `{"dst":"2001:db8::1"}`}, // IPv6: out of scope
		row(t0, "10.1.2.3", 6, 80, false, false),    // already allowed below
		row(t0, "9.9.9.9", 17, 53, false, false),
	}
	allowed := func(ip netip.Addr) bool { return netip.MustParsePrefix("10.0.0.0/8").Contains(ip) }
	got := AggregateDenies(rows, allowed)
	if len(got) != 1 || got[0].IP.String() != "9.9.9.9" {
		t.Fatalf("got %+v", got)
	}
}

func TestAggregateDenies_ProtocolLabelsAndPortBounds(t *testing.T) {
	t0 := time.Now()
	got := AggregateDenies([]DenyRow{
		row(t0, "5.5.5.5", 1, 0, false, false),
		row(t0, "5.5.5.6", 47, 0, false, false),
		row(t0, "5.5.5.7", 6, 70000, false, false),
	}, nil)
	labels := map[string]string{}
	for _, d := range got {
		labels[d.IP.String()] = d.Proto
	}
	if labels["5.5.5.5"] != "icmp" || labels["5.5.5.6"] != "47" || labels["5.5.5.7"] != "tcp" {
		t.Errorf("labels = %v", labels)
	}
	for _, d := range got {
		if d.IP.String() == "5.5.5.7" && d.Port != 0 {
			t.Errorf("out-of-range port must collapse to 0, got %d", d.Port)
		}
	}
}

func TestCompiledPolicy_Allows(t *testing.T) {
	c, err := Compile(&pb.NetworkPolicy{Tenant: "a", EgressCidrs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	gw := []netip.Prefix{netip.MustParsePrefix("10.100.0.1/32")}
	if !c.Allows(netip.MustParseAddr("10.2.3.4"), nil) {
		t.Error("egress CIDR must allow")
	}
	if c.Allows(netip.MustParseAddr("11.0.0.1"), nil) {
		t.Error("uncovered address must not be allowed")
	}
	if !c.Allows(netip.MustParseAddr("10.100.0.1"), gw) {
		t.Error("implicit prefix must allow")
	}
	if c.Allows(netip.MustParseAddr("192.168.0.1"), gw) {
		t.Error("implicit prefix must not widen beyond itself")
	}
}

func TestEgressPreset_CompileRoundTripAndImplicit(t *testing.T) {
	gw := netip.MustParseAddr("10.100.0.1")
	// No preset: nothing implicit, round-trips as unspecified.
	c, err := Compile(&pb.NetworkPolicy{Tenant: "a"})
	if err != nil || len(ImplicitEgress(c, gw)) != 0 || c.ToProto().GetEgressPreset() != pb.EgressPreset_EGRESS_PRESET_UNSPECIFIED {
		t.Fatalf("no-preset: %v %v", err, ImplicitEgress(c, gw))
	}
	// Preset: the resolver is implicit, and the preset survives ToProto.
	c, err = Compile(&pb.NetworkPolicy{Tenant: "a", EgressPreset: pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY,
		Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE})
	if err != nil {
		t.Fatal(err)
	}
	imp := ImplicitEgress(c, gw)
	if len(imp) != 1 || imp[0].String() != "10.100.0.1/32" {
		t.Fatalf("implicit = %v", imp)
	}
	if c.ToProto().GetEgressPreset() != pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY {
		t.Error("preset lost in ToProto")
	}
	// The preset must not widen the stored lists.
	if len(c.EgressCIDRs) != 0 {
		t.Errorf("preset must not write into EgressCIDRs: %v", c.EgressCIDRs)
	}
	// Unknown gateway: nothing implicit rather than a bogus entry.
	if got := ImplicitEgress(c, netip.Addr{}); len(got) != 0 {
		t.Errorf("zero gateway produced %v", got)
	}
	if got := ImplicitEgress(c, netip.MustParseAddr("fe80::1")); len(got) != 0 {
		t.Errorf("IPv6 gateway produced %v", got)
	}
	// Unknown enum value is rejected.
	if _, err := Compile(&pb.NetworkPolicy{Tenant: "a", EgressPreset: pb.EgressPreset(99)}); err == nil {
		t.Error("unknown preset must be rejected")
	}
}
