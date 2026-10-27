package server

import (
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
