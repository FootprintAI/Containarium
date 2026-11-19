package server

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// #3774: the source-IP map resolves a box's address through the host only. A
// guest-reported address counts only when the host's lease agrees with it, the
// same rule the policy path applies, and it never stands in for a missing lease.
func TestHostKnownAddress_LeaseMustAgreeWithGuest(t *testing.T) {
	const mac = "00:16:3e:aa:bb:cc"
	dataDir := t.TempDir()
	leaseDir := filepath.Join(dataDir, "networks")
	if err := os.MkdirAll(filepath.Join(leaseDir, "testbr0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaseDir, "testbr0", "dnsmasq.leases"),
		[]byte("0 "+mac+" 10.100.0.7 web *\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	insp := &fakeInspector{
		containers: []incus.ContainerInfo{{Name: "web-container", State: "running", IPAddress: "10.100.0.7"}},
		rawCalls:   map[string]int{},
		network:    "testbr0", hwaddr: mac,
	}
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), missingAware{insp}, nil, nil, false)
	e.SetIncusDataDir(dataDir)

	// Lease and guest agree: the host-known address is the lease's.
	got, ok := e.HostKnownAddress("web-container", netip.MustParseAddr("10.100.0.7"))
	if !ok || got != netip.MustParseAddr("10.100.0.7") {
		t.Fatalf("agreeing guest: got %v ok=%v, want 10.100.0.7", got, ok)
	}

	// The guest renumbers itself: the lease does not agree, so there is no
	// host-known address, and the guest's new value is not returned.
	if got, ok := e.HostKnownAddress("web-container", netip.MustParseAddr("10.100.0.99")); ok {
		t.Fatalf("disagreeing guest: got %v, want no host-known address", got)
	}

	// The host knows nothing about an unknown instance.
	if _, ok := e.HostKnownAddress("missing-container", netip.MustParseAddr("10.100.0.7")); ok {
		t.Fatal("unknown instance must have no host-known address")
	}
}

// missingAware makes an instance the fake does not know fail to inspect, the way
// Incus reports a missing instance.
type missingAware struct{ *fakeInspector }

func (m missingAware) GetRawInstance(name string) (map[string]string, string, error) {
	if name == "missing-container" {
		return nil, "", errors.New("instance not found")
	}
	return m.fakeInspector.GetRawInstance(name)
}
