package network

import (
	"reflect"
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
