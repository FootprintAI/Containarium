package traffic

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// hostAssigned is a hostAddr verifier backed by a fixed name -> host-assigned
// address table, standing in for the device config / DHCP lease lookup.
func hostAssigned(table map[string]string) func(name, guestIP string) bool {
	return func(name, guestIP string) bool {
		ip, ok := table[name]
		return ok && ip == guestIP
	}
}

// A box reports its address from inside its own netns, so root in the box can
// claim another box's address. Traffic is attributed by that address, so the
// claim must not move the other box's traffic onto the claiming box (#3690).
func TestRefresh_GuestClaimingAnotherBoxAddressDoesNotTakeIt(t *testing.T) {
	f := &fakeContainerLister{
		names: []string{"victim-container"},
		byName: map[string]*incus.ContainerInfo{
			"victim-container": {Name: "victim-container", IPAddress: "10.0.0.2"},
			"rogue-container":  {Name: "rogue-container", IPAddress: "10.0.0.2"},
		},
	}
	c := newCacheWithFake(f)
	c.hostAddr = hostAssigned(map[string]string{
		"victim-container": "10.0.0.2",
		"rogue-container":  "10.0.0.9",
	})

	if err := c.Refresh(); err != nil {
		t.Fatalf("Refresh() err = %v", err)
	}
	f.names = []string{"victim-container", "rogue-container"}
	if err := c.Refresh(); err != nil {
		t.Fatalf("Refresh() err = %v", err)
	}

	if got := c.LookupIP("10.0.0.2"); got != "victim-container" {
		t.Errorf("LookupIP(10.0.0.2) = %q, want victim-container (a guest claim must not take it)", got)
	}
	// Hard failure per box: the box whose reported address the host did not
	// assign gets no attribution at all, and the rest of the pass is unaffected.
	if got := c.LookupName("rogue-container"); got != "" {
		t.Errorf("LookupName(rogue-container) = %q, want empty (address not host-assigned)", got)
	}

	// Deleting the claiming box must not drop the victim's mapping either.
	f.names = []string{"victim-container"}
	if err := c.Refresh(); err != nil {
		t.Fatalf("Refresh() err = %v", err)
	}
	if got := c.LookupIP("10.0.0.2"); got != "victim-container" {
		t.Errorf("after the claiming box is deleted, LookupIP(10.0.0.2) = %q, want victim-container", got)
	}
}

// A cache with no way to check host assignment attributes nothing: it fails
// closed rather than trusting the guest's report.
func TestRefresh_NoHostAddrCheckAttributesNothing(t *testing.T) {
	f := &fakeContainerLister{
		names:  []string{"a-container"},
		byName: map[string]*incus.ContainerInfo{"a-container": {Name: "a-container", IPAddress: "10.0.0.1"}},
	}
	c := newCacheWithFake(f)
	c.hostAddr = nil

	if err := c.Refresh(); err != nil {
		t.Fatalf("Refresh() err = %v", err)
	}
	if got := c.LookupIP("10.0.0.1"); got != "" {
		t.Errorf("LookupIP(10.0.0.1) = %q, want empty without a host-address check", got)
	}
}
