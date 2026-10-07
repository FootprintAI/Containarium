package hostcheck

import (
	"errors"
	"strings"
	"testing"
)

func TestNICGuardCheck(t *testing.T) {
	tests := []struct {
		name   string
		facts  nicGuardFacts
		err    error
		wantOK bool
		want   string // substring of Detail
	}{
		{"healthy host", nicGuardFacts{firewallDriver: "nftables", hasExtension: true, guarded: 3}, nil, true, "3 tenant container(s) guarded"},
		{"xtables driver", nicGuardFacts{firewallDriver: "xtables", hasExtension: true, guarded: 1}, nil, false, `driver is "xtables"`},
		{"incus 6.0.0", nicGuardFacts{firewallDriver: "nftables", hasExtension: false}, nil, false, "lacks the network_bridge_acl_devices"},
		{"unguarded tenants", nicGuardFacts{firewallDriver: "nftables", hasExtension: true, guarded: 1, unguarded: []string{"bob-container", "alice-container"}}, nil, false, "2 running tenant container(s) without"},
		{"probe error", nicGuardFacts{}, errors.New("incus query /1.0: no socket"), false, "could not determine"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := posturePaths{nicGuardProbe: func() (nicGuardFacts, error) { return tc.facts, tc.err }}
			c := nicGuardCheck(p)
			if c.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v (%s)", c.OK, tc.wantOK, c.Detail)
			}
			if !strings.Contains(c.Detail, tc.want) {
				t.Errorf("Detail = %q, want containing %q", c.Detail, tc.want)
			}
		})
	}
	// Unguarded names are sorted and capped so a big host stays readable.
	many := make([]string, 0, 9)
	for i := 9; i > 0; i-- {
		many = append(many, "t"+string(rune('0'+i))+"-container")
	}
	c := nicGuardCheck(posturePaths{nicGuardProbe: func() (nicGuardFacts, error) {
		return nicGuardFacts{firewallDriver: "nftables", hasExtension: true, unguarded: many}, nil
	}})
	if !strings.Contains(c.Detail, "t1-container, t2-container") || !strings.Contains(c.Detail, "… 4 more") {
		t.Errorf("Detail = %q", c.Detail)
	}
	if nicGuardCheck(posturePaths{}).Detail != "could not determine: no probe configured" {
		t.Error("nil probe must be reported, not treated as OK")
	}
}

func TestIsCoreContainerName(t *testing.T) {
	for name, want := range map[string]bool{
		"containarium-core-postgres": true, "core-caddy": true,
		"alice-container": false, "cld-1a2b3c": false, "coreutils-container": false,
	} {
		if got := isCoreContainerName(name); got != want {
			t.Errorf("isCoreContainerName(%q) = %v, want %v", name, got, want)
		}
	}
}
