package network

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestStaleCaddyNATRules(t *testing.T) {
	// A representative `iptables -t nat -S` dump: the current Caddy IP is
	// 10.0.3.50; 10.0.3.111 is a stale (recreated-away) Caddy IP; and there's
	// a passthrough route (dport 50051) that must never be touched.
	save := `-P PREROUTING ACCEPT
-P POSTROUTING ACCEPT
-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 80 -j DNAT --to-destination 10.0.3.111:80
-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 443 -j DNAT --to-destination 10.0.3.111:443
-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 80 -j DNAT --to-destination 10.0.3.50:80
-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 443 -j DNAT --to-destination 10.0.3.50:443
-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 50051 -j DNAT --to-destination 10.0.3.150:50051
-A OUTPUT -d 127.0.0.0/8 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.111:443
-A OUTPUT -d 127.0.0.0/8 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.50:443
-A POSTROUTING -d 10.0.3.111/32 -j MASQUERADE
-A POSTROUTING -d 10.0.3.50/32 -j MASQUERADE
-A POSTROUTING -p tcp -d 10.0.3.150/32 --dport 50051 -j MASQUERADE`

	got := staleCaddyNATRules(save, "10.0.3.50")

	want := [][]string{
		{"-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-m", "tcp", "!", "-s", "10.0.3.0/24", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.3.111:80"},
		{"-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-m", "tcp", "!", "-s", "10.0.3.0/24", "--dport", "443", "-j", "DNAT", "--to-destination", "10.0.3.111:443"},
		{"-t", "nat", "-D", "OUTPUT", "-d", "127.0.0.0/8", "-p", "tcp", "-m", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", "10.0.3.111:443"},
		{"-t", "nat", "-D", "POSTROUTING", "-d", "10.0.3.111/32", "-j", "MASQUERADE"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("staleCaddyNATRules mismatch.\n got: %v\nwant: %v", got, want)
	}
}

func TestStaleCaddyNATRules_AllCurrentNoOp(t *testing.T) {
	// Every Caddy rule already points at the current IP — nothing to delete.
	save := `-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 80 -j DNAT --to-destination 10.0.3.50:80
-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 443 -j DNAT --to-destination 10.0.3.50:443
-A OUTPUT -d 127.0.0.0/8 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.50:443
-A POSTROUTING -d 10.0.3.50/32 -j MASQUERADE
-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 50051 -j DNAT --to-destination 10.0.3.150:50051`

	if got := staleCaddyNATRules(save, "10.0.3.50"); len(got) != 0 {
		t.Errorf("expected no stale rules, got %v", got)
	}
}

func TestStaleCaddyNATRules_LeavesPassthroughAlone(t *testing.T) {
	// A passthrough DNAT + its MASQUERADE on a non-Caddy IP must NOT be flagged,
	// even though their target IP differs from the Caddy IP, because their dport
	// isn't 80/443 (DNAT) and the masq carries -p/--dport.
	save := `-A PREROUTING -p tcp -m tcp ! -s 10.0.3.0/24 --dport 8080 -j DNAT --to-destination 10.0.3.200:8080
-A POSTROUTING -p tcp -d 10.0.3.200/32 --dport 8080 -j MASQUERADE`

	if got := staleCaddyNATRules(save, "10.0.3.50"); len(got) != 0 {
		t.Errorf("expected passthrough rules to be left alone, got %v", got)
	}
}

// The 80/443 DNAT is scoped to traffic addressed to the host itself and has
// no source exclusion, so a box on the bridge that opens the host's own
// address is DNAT'd to Caddy like any outside client (hairpin, #2732), while
// traffic merely passing through the host to some other address is not.
func TestCaddyPreRoutingRule_ScopedToLocalNoSourceExclusion(t *testing.T) {
	got := caddyPreRoutingRule(443, "10.0.3.50")
	want := []string{"PREROUTING", "-p", "tcp", "-m", "addrtype", "--dst-type", "LOCAL",
		"--dport", "443", "-j", "DNAT", "--to-destination", "10.0.3.50:443"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("caddyPreRoutingRule mismatch.\n got: %v\nwant: %v", got, want)
	}
	for _, a := range got {
		if a == "!" || a == "-s" {
			t.Errorf("rule still carries a source match, so bridge clients cannot hairpin: %v", got)
		}
	}
}

// On upgrade the pre-#2732 shape (`! -s <bridge>`) must be cleared even when
// it still points at the current Caddy IP, or a host keeps both shapes.
// Rules are in the order `iptables -t nat -S` actually prints them.
func TestLegacyCaddyPreRoutingRules(t *testing.T) {
	save := `-A PREROUTING ! -s 10.0.3.0/24 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.3.50:80
-A PREROUTING ! -s 10.0.3.0/24 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.111:443
-A PREROUTING -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 80 -j DNAT --to-destination 10.0.3.50:80
-A PREROUTING -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 443 -j DNAT --to-destination 10.0.3.50:443
-A PREROUTING ! -s 10.0.3.0/24 -p tcp -m tcp --dport 50051 -j DNAT --to-destination 10.0.3.150:50051
-A PREROUTING ! -s 192.168.50.0/24 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.50:443
-A OUTPUT -d 127.0.0.0/8 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.50:443
-A POSTROUTING -d 10.0.3.50/32 -j MASQUERADE`

	got := legacyCaddyPreRoutingRules(save, "10.0.3.0/24")

	// Both legacy 80/443 rules on our bridge subnet, whatever their target.
	// Not the new shape, not the passthrough on 50051, and not a `! -s` rule
	// for some other subnet (an operator's, not ours).
	want := [][]string{
		{"-t", "nat", "-D", "PREROUTING", "!", "-s", "10.0.3.0/24", "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.3.50:80"},
		{"-t", "nat", "-D", "PREROUTING", "!", "-s", "10.0.3.0/24", "-p", "tcp", "-m", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", "10.0.3.111:443"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("legacyCaddyPreRoutingRules mismatch.\n got: %v\nwant: %v", got, want)
	}
}

// A host already on the new shape has nothing to clear.
func TestLegacyCaddyPreRoutingRules_NewShapeNoOp(t *testing.T) {
	save := `-A PREROUTING -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 80 -j DNAT --to-destination 10.0.3.50:80
-A PREROUTING -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 443 -j DNAT --to-destination 10.0.3.50:443
-A OUTPUT -d 127.0.0.0/8 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.3.50:80
-A POSTROUTING -d 10.0.3.50/32 -j MASQUERADE`

	if got := legacyCaddyPreRoutingRules(save, "10.0.3.0/24"); len(got) != 0 {
		t.Errorf("expected nothing to clear on the new shape, got %v", got)
	}
}

// fakeNAT is an in-memory nat table behind PortForwarder.ipt. It records
// every call and, like iptables, fails -C/-D for a rule that is not there.
type fakeNAT struct {
	rules  []string // "<chain> <spec>", as `iptables -S` prints after "-A "
	calls  []string // "<op> <chain> <spec>"
	failOn string   // a call prefix that returns an error, e.g. "-A PREROUTING"
}

func (f *fakeNAT) ipt(args ...string) ([]byte, error) {
	op, rule := args[2], strings.Join(args[3:], " ")
	f.calls = append(f.calls, strings.TrimSpace(op+" "+rule))
	if f.failOn != "" && strings.HasPrefix(op+" "+rule, f.failOn) {
		return nil, fmt.Errorf("injected failure")
	}
	idx := -1
	for i, r := range f.rules {
		if r == rule {
			idx = i
		}
	}
	switch op {
	case "-S":
		var b strings.Builder
		for _, r := range f.rules {
			b.WriteString("-A " + r + "\n")
		}
		return []byte(b.String()), nil
	case "-A":
		f.rules = append(f.rules, rule)
		return nil, nil
	case "-C", "-D":
		if idx < 0 {
			return nil, fmt.Errorf("no such rule")
		}
		if op == "-D" {
			f.rules = append(f.rules[:idx], f.rules[idx+1:]...)
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected op %q", op)
}

func (f *fakeNAT) index(call string) int {
	for i, c := range f.calls {
		if c == call {
			return i
		}
	}
	return -1
}

const (
	legacy80  = "PREROUTING ! -s 10.0.3.0/24 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.3.50:80"
	legacy443 = "PREROUTING ! -s 10.0.3.0/24 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.50:443"
	legacyOld = "PREROUTING ! -s 10.0.3.0/24 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.111:443"
)

// On upgrade the new 80/443 rules go in before the old shape comes out, so
// inbound 80/443 always has a DNAT to the current Caddy. Each old rule is
// deleted exactly once, and a second run changes nothing.
func TestApplyRules_AddsNewShapeBeforeRemovingLegacy(t *testing.T) {
	f := &fakeNAT{rules: []string{legacyOld, legacy80, legacy443}}
	pf := NewPortForwarderWithNetwork("10.0.3.50", "10.0.3.0/24")
	pf.ipt = f.ipt

	if err := pf.applyRules(); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	for _, port := range []int{80, 443} {
		add := f.index("-A " + strings.Join(caddyPreRoutingRule(port, "10.0.3.50"), " "))
		if add < 0 {
			t.Fatalf("new :%d rule never added; calls: %v", port, f.calls)
		}
		for _, old := range []string{legacy80, legacy443} {
			if del := f.index("-D " + old); del < add {
				t.Errorf("legacy rule %q deleted at call %d, before the new :%d rule was added at %d", old, del, port, add)
			}
		}
	}
	for _, old := range []string{legacyOld, legacy80, legacy443} {
		n := 0
		for _, c := range f.calls {
			if c == "-D "+old {
				n++
			}
		}
		if n != 1 {
			t.Errorf("legacy rule %q deleted %d times, want 1", old, n)
		}
	}
	want := []string{
		strings.Join(caddyPreRoutingRule(80, "10.0.3.50"), " "),
		strings.Join(caddyPreRoutingRule(443, "10.0.3.50"), " "),
		"OUTPUT -p tcp -d 127.0.0.0/8 --dport 80 -j DNAT --to-destination 10.0.3.50:80",
		"OUTPUT -p tcp -d 127.0.0.0/8 --dport 443 -j DNAT --to-destination 10.0.3.50:443",
		"POSTROUTING -d 10.0.3.50 -j MASQUERADE",
	}
	if !reflect.DeepEqual(f.rules, want) {
		t.Errorf("final nat table mismatch.\n got: %v\nwant: %v", f.rules, want)
	}

	f.calls = nil
	if err := pf.applyRules(); err != nil {
		t.Fatalf("second applyRules: %v", err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "-A ") || strings.HasPrefix(c, "-D ") {
			t.Errorf("second run is not a no-op: %q", c)
		}
	}
}

// If the new rule cannot be added, the old shape stays and keeps serving
// inbound 80/443 instead of leaving the host with no DNAT at all.
func TestApplyRules_AddFailureKeepsLegacyShape(t *testing.T) {
	f := &fakeNAT{rules: []string{legacy80, legacy443}, failOn: "-A PREROUTING"}
	pf := NewPortForwarderWithNetwork("10.0.3.50", "10.0.3.0/24")
	pf.ipt = f.ipt

	if err := pf.applyRules(); err == nil {
		t.Fatal("applyRules succeeded although adding the PREROUTING rule failed")
	}
	if !reflect.DeepEqual(f.rules, []string{legacy80, legacy443}) {
		t.Errorf("legacy rules were removed although the new ones were never added: %v", f.rules)
	}
}

// The forwarder's subnet arrives in whatever form its caller has (Incus
// reports the bridge in gateway form, `a.b.c.1/24`), while `iptables -S`
// prints the network form (`a.b.c.0/24`). They must be compared as
// networks, or the old rule is never cleared on upgrade.
func TestLegacyCaddyPreRoutingRules_SubnetForms(t *testing.T) {
	const (
		ours24  = "-A PREROUTING ! -s 10.0.3.0/24 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.3.50:443"
		ours16  = "-A PREROUTING ! -s 10.20.0.0/16 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.20.0.50:443"
		other24 = "-A PREROUTING ! -s 10.20.5.0/24 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.20.0.50:80"
		oper    = "-A PREROUTING ! -s 198.51.100.0/24 -p tcp -m tcp --dport 443 -j DNAT --to-destination 203.0.113.7:443"
	)
	save := strings.Join([]string{ours24, ours16, other24, oper}, "\n")
	del := func(line string) []string { return append([]string{"-t", "nat", "-D"}, strings.Fields(line)[1:]...) }

	for _, tc := range []struct {
		name, subnet string
		want         [][]string
	}{
		{"gateway form /24", "10.0.3.1/24", [][]string{del(ours24)}},
		{"network form /24", "10.0.3.0/24", [][]string{del(ours24)}},
		{"gateway form /16", "10.20.0.1/16", [][]string{del(ours16)}},
		// Unparseable: leave every old rule in place (logged) rather than
		// guess, so nothing that might not be ours is deleted.
		{"unparseable subnet", "not-a-cidr", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := legacyCaddyPreRoutingRules(save, tc.subnet); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("subnet %q:\n got: %v\nwant: %v", tc.subnet, got, tc.want)
			}
		})
	}
}
