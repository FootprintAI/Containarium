package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

func mastersOf(m map[string]string) func(string) (string, error) {
	return func(v string) (string, error) { return m[v], nil }
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
	_, refused, _ := refuseVethCarriers([]uplinkIface{{"veth1", 9}}, []string{"veth1"}, masters)
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

// fakeSysfs points sysClassNet at a temp dir: ifaces maps veth -> master name
// ("" = no master link).
func fakeSysfs(t *testing.T, ifaces map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for v, m := range ifaces {
		if err := os.MkdirAll(filepath.Join(dir, v), 0o755); err != nil {
			t.Fatal(err)
		}
		if m != "" {
			if err := os.Symlink("../"+m, filepath.Join(dir, v, "master")); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := sysClassNet
	sysClassNet = dir
	t.Cleanup(func() { sysClassNet = old })
}

// #3185 review: masterOfIface reads the real link layout; ENOENT (no master, or
// the veth vanished) is not an error, anything else is.
func TestMasterOfIface(t *testing.T) {
	fakeSysfs(t, map[string]string{"vethA": "incusbr0", "vethB": ""})
	if m, err := masterOfIface("vethA"); m != "incusbr0" || err != nil {
		t.Errorf("vethA = %q, %v", m, err)
	}
	if m, err := masterOfIface("vethB"); m != "" || err != nil {
		t.Errorf("no master = %q, %v", m, err)
	}
	if m, err := masterOfIface("gone"); m != "" || err != nil {
		t.Errorf("vanished veth = %q, %v (must not be an error)", m, err)
	}
	// A non-symlink master is unreadable as a link: an error, not "none".
	if err := os.WriteFile(filepath.Join(sysClassNet, "vethB", "master"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := masterOfIface("vethB"); err == nil {
		t.Error("unreadable master returned no error")
	}
}

// #3185 review: managedVethNames -> masterOfIface -> converge wiring against a
// fake sysfs. The applyTrustedUplinks line itself is not covered: it reads
// /proc/net/route and the concrete BPF loader.
func TestManagedVethNames_MasterLookup_Converge(t *testing.T) {
	fakeSysfs(t, map[string]string{"vethA": "br0"})
	cache := map[string]vethInfo{"box": {veth: "vethA"}}
	u, ap, inst, lines := newUplinkRig()
	u.converge([]uplinkIface{{"br0", 5}, {"eth0", 2}}, managedVethNames(cache), masterOfIface, ap, inst)
	if ap.set[5] || !ap.set[2] {
		t.Fatalf("want br0 refused and eth0 trusted via fake sysfs, got %v (%v)", ap.set, *lines)
	}
}

// #3185 review: an unreadable master fails closed for the pass: no new trust, the
// installed set untouched, one log line.
func TestUplinks_UnreadableMasterFailsClosed(t *testing.T) {
	boom := func(string) (string, error) { return "", errors.New("EIO") }
	u, ap, inst, lines := newUplinkRig()
	inst[2], ap.set[2] = true, true // legitimate, already installed
	cands := []uplinkIface{{"eth0", 2}, {"br0", 5}}
	u.converge(cands, []string{"vethA"}, boom, ap, inst)
	u.converge(cands, []string{"vethA"}, boom, ap, inst)
	if ap.set[5] || inst[5] {
		t.Errorf("new entry trusted despite unreadable master: %v", ap.set)
	}
	if !ap.set[2] || !inst[2] {
		t.Errorf("installed uplink was un-trusted: %v", ap.set)
	}
	if len(*lines) != 1 || !strings.Contains((*lines)[0], "EIO") {
		t.Errorf("want one error log, got %v", *lines)
	}
}

// #3185 review: with several unreadable veths the error text must not vary from
// pass to pass (vethCache is a map), or the log-once dedupe is defeated.
func TestUplinks_UnreadableMastersLogOnceAcrossPasses(t *testing.T) {
	cache := map[string]vethInfo{}
	for _, n := range []string{"b", "c", "a", "e", "d", "h", "g", "f"} {
		cache["box-"+n] = vethInfo{veth: "veth" + n}
	}
	boom := func(v string) (string, error) { return "", fmt.Errorf("EIO on %s", v) }
	u, ap, inst, lines := newUplinkRig()
	for i := 0; i < 30; i++ {
		u.converge([]uplinkIface{{"br0", 5}}, managedVethNames(cache), boom, ap, inst)
	}
	if len(*lines) != 1 {
		t.Fatalf("want exactly 1 log line over 30 passes, got %d: %v", len(*lines), *lines)
	}
}

// #3212: on an unreadable master, an installed entry whose interface is itself a
// directly-named managed veth is still un-trusted (known without a sysfs read);
// every other installed entry is kept, and nothing new is trusted.
func TestUplinks_UnreadableMasterDropsInstalledManagedVeth(t *testing.T) {
	boom := func(string) (string, error) { return "", errors.New("EIO") }
	u, ap, inst, lines := newUplinkRig()
	for _, i := range []int{2, 7, 9} { // eth0, vethA (managed), stale index with no candidate
		inst[i], ap.set[i] = true, true
	}
	cands := []uplinkIface{{"eth0", 2}, {"vethA", 7}, {"br0", 5}}
	u.converge(cands, []string{"vethA"}, boom, ap, inst)
	if ap.set[7] || inst[7] {
		t.Errorf("installed managed veth stayed trusted: kernel=%v installed=%v", ap.set, inst)
	}
	if !ap.set[2] || !inst[2] || !ap.set[9] || !inst[9] {
		t.Errorf("unrelated installed entries must be kept: kernel=%v installed=%v", ap.set, inst)
	}
	if ap.set[5] || inst[5] {
		t.Errorf("new trust added on error: %v", ap.set)
	}
	if len(*lines) != 1 {
		t.Errorf("want one error log, got %v", *lines)
	}
}

// #3251: masters read before the unreadable veth still identify carriers. With
// vethA -> br0 readable and vethB unreadable, an installed br0 is un-trusted
// (known carrier), while an unrelated installed uplink is kept and nothing new
// is trusted.
func TestUplinks_UnreadableMasterDropsInstalledKnownCarrierBridge(t *testing.T) {
	masterOf := func(v string) (string, error) {
		if v == "vethA" {
			return "br0", nil
		}
		return "", errors.New("EIO")
	}
	u, ap, inst, lines := newUplinkRig()
	for _, i := range []int{2, 5} { // eth0 (unrelated), br0 (known carrier)
		inst[i], ap.set[i] = true, true
	}
	cands := []uplinkIface{{"eth0", 2}, {"br0", 5}, {"br1", 6}}
	u.converge(cands, []string{"vethA", "vethB"}, masterOf, ap, inst)
	if ap.set[5] || inst[5] {
		t.Errorf("installed known-carrier bridge stayed trusted: kernel=%v installed=%v", ap.set, inst)
	}
	if !ap.set[2] || !inst[2] {
		t.Errorf("unrelated installed uplink must be kept: kernel=%v installed=%v", ap.set, inst)
	}
	if ap.set[6] || inst[6] {
		t.Errorf("new trust added on error: %v", ap.set)
	}
	if len(*lines) != 1 || !strings.Contains((*lines)[0], "EIO") {
		t.Errorf("want one error log, got %v", *lines)
	}
}

// #3251: same through the sysClassNet seam: vethB has no readable master (a
// regular file where the link should be), vethA's master br0 is still dropped.
func TestUplinks_UnreadableMasterKnownCarrierViaSysfs(t *testing.T) {
	fakeSysfs(t, map[string]string{"vethA": "br0", "vethB": ""})
	if err := os.WriteFile(filepath.Join(sysClassNet, "vethB", "master"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cache := map[string]vethInfo{"a": {veth: "vethA"}, "b": {veth: "vethB"}}
	u, ap, inst, _ := newUplinkRig()
	inst[5], ap.set[5] = true, true
	u.converge([]uplinkIface{{"br0", 5}}, managedVethNames(cache), masterOfIface, ap, inst)
	if ap.set[5] || inst[5] {
		t.Errorf("installed known-carrier bridge stayed trusted: kernel=%v installed=%v", ap.set, inst)
	}
}

// #3283: when the unreadable veth sorts first, a later veth's bridge is
// never identified as a carrier. Its installed trust remains (documented
// fail-open residue), but the error must not introduce any new trust.
func TestUplinks_UnreadableMasterKeepsInstalledLaterCarrierBridge(t *testing.T) {
	var read []string
	masterOf := func(v string) (string, error) {
		read = append(read, v)
		if v == "vethA" {
			return "", errors.New("EIO")
		}
		return "br0", nil
	}
	cache := map[string]vethInfo{"later": {veth: "vethB"}, "first": {veth: "vethA"}}
	u, ap, inst, _ := newUplinkRig()
	for _, i := range []int{2, 5} { // eth0 (unrelated), br0 (carrier via vethB)
		inst[i], ap.set[i] = true, true
	}
	cands := []uplinkIface{{"eth0", 2}, {"br0", 5}, {"br1", 6}}
	u.converge(cands, managedVethNames(cache), masterOf, ap, inst)
	if !ap.set[5] || !inst[5] {
		t.Errorf("installed later-carrier bridge must be kept: kernel=%v installed=%v", ap.set, inst)
	}
	if !ap.set[2] || !inst[2] {
		t.Errorf("unrelated installed uplink must be kept: kernel=%v installed=%v", ap.set, inst)
	}
	if ap.set[6] || inst[6] {
		t.Errorf("new trust added on error: kernel=%v installed=%v", ap.set, inst)
	}
	if !slices.Equal(read, []string{"vethA"}) {
		t.Errorf("master lookups = %v, want only the first unreadable vethA", read)
	}
}

// #3283: on error, refused contains only carriers identified before scanning
// stopped; it must not be discarded or include bridges from later veths.
func TestRefuseVethCarriers_UnreadableMasterReturnsPartialRefused(t *testing.T) {
	tests := []struct {
		name        string
		unreadable  string
		wantRefused []uplinkIface
		wantRead    []string
	}{
		{
			name:       "first master unreadable",
			unreadable: "vethA",
			wantRead:   []string{"vethA"},
		},
		{
			name:        "known carrier before unreadable master",
			unreadable:  "vethB",
			wantRefused: []uplinkIface{{"br0", 5}},
			wantRead:    []string{"vethA", "vethB"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readErr := errors.New("EIO")
			var read []string
			masters := map[string]string{"vethA": "br0", "vethB": "br1", "vethC": "br2"}
			masterOf := func(v string) (string, error) {
				read = append(read, v)
				if v == tt.unreadable {
					return "", readErr
				}
				return masters[v], nil
			}
			cands := []uplinkIface{{"eth0", 2}, {"br0", 5}, {"br1", 6}, {"br2", 7}}
			trusted, refused, err := refuseVethCarriers(cands, []string{"vethA", "vethB", "vethC"}, masterOf)
			if !errors.Is(err, readErr) {
				t.Errorf("err = %v, want the master lookup error", err)
			}
			if trusted != nil {
				t.Errorf("trusted = %v, want nil for an incomplete carrier set", trusted)
			}
			if !slices.Equal(refused, tt.wantRefused) {
				t.Errorf("refused = %v, want %v", refused, tt.wantRefused)
			}
			if !slices.Equal(read, tt.wantRead) {
				t.Errorf("master lookups = %v, want %v", read, tt.wantRead)
			}
		})
	}
}
