package netbpf

import (
	"net/netip"
	"testing"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestCompileDeny(t *testing.T) {
	c := mustCompile(t, &pb.NetworkPolicy{
		Tenant: "alice",
		DenyRules: []*pb.NetworkPolicyDenyRule{
			{Cidr: "1.2.3.4", Port: 6379, Proto: "tcp"}, // host → /32, tcp/6379
			{Cidr: "10.0.0.0/8"},                        // any port/proto
		},
	})
	entries, err := CompileDeny(7, c)
	if err != nil {
		t.Fatalf("CompileDeny: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	// Sorted by CIDR string in Compile: "1.2.3.4/32" < "10.0.0.0/8".
	want := []DenyEntry{
		{PrefixLen: 32 + 32, TenantID: 7, Addr: [4]byte{1, 2, 3, 4}, Port: 6379, Proto: 6},
		{PrefixLen: 32 + 8, TenantID: 7, Addr: [4]byte{10, 0, 0, 0}, Port: 0, Proto: 0},
	}
	for i, w := range want {
		if entries[i] != w {
			t.Errorf("entry[%d] = %+v, want %+v", i, entries[i], w)
		}
	}
	// Key() drops the value (port/proto) so two rules on the same CIDR address the
	// same map slot.
	if entries[0].Key() != (DenyKey{PrefixLen: 64, TenantID: 7, Addr: [4]byte{1, 2, 3, 4}}) {
		t.Errorf("Key() = %+v", entries[0].Key())
	}
}

func TestCompileDeny_RejectsIPv6(t *testing.T) {
	c := netpolicy.CompiledPolicy{
		Tenant:    "alice",
		DenyRules: []netpolicy.DenyRule{{CIDR: netip.MustParsePrefix("2001:db8::/32")}},
	}
	if _, err := CompileDeny(1, c); err == nil {
		t.Fatal("expected error for IPv6 deny CIDR (Phase A is IPv4-only)")
	}
}

func TestCompileDeny_Empty(t *testing.T) {
	c := mustCompile(t, &pb.NetworkPolicy{Tenant: "alice"})
	entries, err := CompileDeny(1, c)
	if err != nil {
		t.Fatalf("CompileDeny: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("want no entries, got %+v", entries)
	}
}

// TestDenyByteLayout pins the wire encoding the BPF program reads: a 12-byte LPM
// key (prefixlen, tenant_id, addr) shared with egress_cidr, and a 4-byte value
// (port, proto, flags).
func TestDenyByteLayout(t *testing.T) {
	e := DenyEntry{PrefixLen: 64, TenantID: 7, Addr: [4]byte{1, 2, 3, 4}, Port: 6379, Proto: 6}
	key := denyKeyBytes(e.Key())
	if len(key) != 12 {
		t.Fatalf("deny key = %d bytes, want 12", len(key))
	}
	// addr bytes sit at [8:12] in network order, like egress.
	if key[8] != 1 || key[9] != 2 || key[10] != 3 || key[11] != 4 {
		t.Errorf("addr bytes = %v, want 1.2.3.4", key[8:12])
	}
	val := denyValueBytes(e)
	if len(val) != 4 {
		t.Fatalf("deny value = %d bytes, want 4", len(val))
	}
	if val[2] != 6 {
		t.Errorf("proto byte = %d, want 6", val[2])
	}
}
