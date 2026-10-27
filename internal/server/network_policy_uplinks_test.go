package server

import (
	"fmt"
	"strings"
	"testing"
)

// #2618 B5: the uplinks whose unmarked frames may seed an inbound flow are the
// host's default-route interfaces, read from /proc/net/route.
func TestParseDefaultRouteIfaces(t *testing.T) {
	in := strings.Join([]string{
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
		"eth0\t00000000\t0100640A\t0003\t0\t0\t100\t00000000\t0\t0\t0",
		"incusbr0\t00F3400A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0", // the bridge: not a default route
		"wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0",     // a second default route
		"eth0\t00000000\t0200640A\t0003\t0\t0\t200\t00000000\t0\t0\t0",   // duplicate iface
		"garbage",
	}, "\n")
	got := parseDefaultRouteIfaces(strings.NewReader(in))
	want := []string{"eth0", "wg0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("default-route ifaces = %v, want %v", got, want)
	}
	if got := parseDefaultRouteIfaces(strings.NewReader("")); len(got) != 0 {
		t.Errorf("empty table = %v, want none", got)
	}
	if got := splitCSV(" eth1, , ens5 "); strings.Join(got, ",") != "eth1,ens5" {
		t.Errorf("splitCSV = %v", got)
	}
}

type fakeTrusted struct{ set map[int]bool }

func (f *fakeTrusted) SetTrustedIface(i int) error    { f.set[i] = true; return nil }
func (f *fakeTrusted) DeleteTrustedIface(i int) error { delete(f.set, i); return nil }

func newUplinkRig() (*uplinkReconciler, *fakeTrusted, map[int]bool, *[]string) {
	var lines []string
	u := &uplinkReconciler{logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}
	return u, &fakeTrusted{set: map[int]bool{}}, map[int]bool{}, &lines
}

func mastersOf(m map[string]string) func(string) string {
	return func(v string) string { return m[v] }
}

// #3185 SF1: the common single-NIC host (default route on eth0, instances on a
// separate bridge) must keep trusting its uplink.
func TestUplinks_SingleNICHostStillTrusted(t *testing.T) {
	u, ap, inst, lines := newUplinkRig()
	cands := []uplinkIface{{"eth0", 2}}
	veths := []string{"veth1", "veth2"}
	u.converge(cands, veths, mastersOf(map[string]string{"veth1": "incusbr0", "veth2": "incusbr0"}), ap, inst)
	if !ap.set[2] || !inst[2] {
		t.Fatalf("eth0 not trusted: kernel=%v installed=%v", ap.set, inst)
	}
	for _, l := range *lines {
		if strings.Contains(l, "refusing") {
			t.Errorf("unexpected refusal: %s", l)
		}
	}
}

// #3185 SF1: a bridged uplink (default route on the bridge the veths are on) and
// an operator typo naming the instance bridge are both refused, with a warning
// logged once; an already-installed entry is removed.
func TestUplinks_RefuseBridgeCarryingVeths(t *testing.T) {
	masters := mastersOf(map[string]string{"veth1": "br0"})
	cands := []uplinkIface{{"br0", 5}, {"eth1", 3}}
	u, ap, inst, lines := newUplinkRig()
	inst[5], ap.set[5] = true, true // trusted before the veth was seen
	u.converge(cands, []string{"veth1"}, masters, ap, inst)
	u.converge(cands, []string{"veth1"}, masters, ap, inst)
	if ap.set[5] || inst[5] {
		t.Errorf("br0 still trusted: kernel=%v installed=%v", ap.set, inst)
	}
	if !ap.set[3] {
		t.Errorf("unrelated eth1 not trusted: %v", ap.set)
	}
	warns := 0
	for _, l := range *lines {
		if strings.Contains(l, "refusing to trust \"br0\"") {
			warns++
		}
	}
	if warns != 1 {
		t.Errorf("want exactly 1 refusal warning, got %d: %v", warns, *lines)
	}
	// A managed veth named directly is refused too.
	_, refused := refuseVethCarriers([]uplinkIface{{"veth1", 9}}, []string{"veth1"}, masters)
	if len(refused) != 1 {
		t.Errorf("veth itself not refused: %v", refused)
	}
}

// #3185 SF1: the trusted set is logged when it changes, not every pass.
func TestUplinks_LogsTrustedSetOnChangeOnly(t *testing.T) {
	u, ap, inst, lines := newUplinkRig()
	m := mastersOf(nil)
	count := func() int {
		n := 0
		for _, l := range *lines {
			if strings.Contains(l, "trusted uplinks changed") {
				n++
			}
		}
		return n
	}
	u.converge([]uplinkIface{{"eth0", 2}}, nil, m, ap, inst)
	u.converge([]uplinkIface{{"eth0", 2}}, nil, m, ap, inst)
	if count() != 1 {
		t.Fatalf("want 1 log after identical passes, got %d: %v", count(), *lines)
	}
	u.converge([]uplinkIface{{"eth0", 2}, {"wg0", 7}}, nil, m, ap, inst)
	if count() != 2 || !strings.Contains((*lines)[len(*lines)-1], "[eth0,wg0]") {
		t.Fatalf("change not logged: %v", *lines)
	}
}
