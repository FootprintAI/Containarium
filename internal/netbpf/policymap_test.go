package netbpf

import (
	"net/netip"
	"testing"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func mustCompile(t *testing.T, p *pb.NetworkPolicy) netpolicy.CompiledPolicy {
	t.Helper()
	c, err := netpolicy.Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func TestCompileConfig(t *testing.T) {
	c := mustCompile(t, &pb.NetworkPolicy{
		Tenant:           "alice",
		AllowIntraTenant: true,
		Mode:             pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
	})
	got := CompileConfig(42, c)
	want := PolicyConfig{TenantID: 42, Mode: ModeEnforce, AllowIntra: 1}
	if got != want {
		t.Errorf("CompileConfig() = %+v, want %+v", got, want)
	}
}

func TestCompileConfig_Metadata(t *testing.T) {
	// Default: metadata denied (AllowMetadata 0).
	def := CompileConfig(1, mustCompile(t, &pb.NetworkPolicy{Tenant: "a"}))
	if def.AllowMetadata != 0 {
		t.Errorf("default AllowMetadata = %d, want 0 (deny)", def.AllowMetadata)
	}
	// Explicit opt-in.
	on := CompileConfig(1, mustCompile(t, &pb.NetworkPolicy{Tenant: "a", AllowMetadata: true}))
	if on.AllowMetadata != 1 {
		t.Errorf("opted-in AllowMetadata = %d, want 1", on.AllowMetadata)
	}
}

func TestCompileConfig_DefaultsLogOnly(t *testing.T) {
	// Unspecified mode resolves to LOG_ONLY in Compile; AllowIntra false.
	c := mustCompile(t, &pb.NetworkPolicy{Tenant: "bob"})
	got := CompileConfig(7, c)
	if got.Mode != ModeLogOnly {
		t.Errorf("Mode = %d, want ModeLogOnly(%d)", got.Mode, ModeLogOnly)
	}
	if got.AllowIntra != 0 {
		t.Errorf("AllowIntra = %d, want 0", got.AllowIntra)
	}
}

func TestCompileEgress(t *testing.T) {
	c := mustCompile(t, &pb.NetworkPolicy{
		Tenant:      "alice",
		EgressCidrs: []string{"10.0.0.0/8", "1.2.3.4/24"}, // 1.2.3.4/24 masks to 1.2.3.0/24
	})
	entries, err := CompileEgress(99, c)
	if err != nil {
		t.Fatalf("CompileEgress: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	// CompiledPolicy sorts CIDRs lexicographically by string: "1.2.3.0/24" < "10.0.0.0/8".
	want := []EgressEntry{
		{PrefixLen: 32 + 24, TenantID: 99, Addr: [4]byte{1, 2, 3, 0}},
		{PrefixLen: 32 + 8, TenantID: 99, Addr: [4]byte{10, 0, 0, 0}},
	}
	for i, w := range want {
		if entries[i] != w {
			t.Errorf("entry[%d] = %+v, want %+v", i, entries[i], w)
		}
	}
}

func TestCompileEgress_RejectsIPv6(t *testing.T) {
	c := netpolicy.CompiledPolicy{
		Tenant:      "alice",
		EgressCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}
	if _, err := CompileEgress(1, c); err == nil {
		t.Fatal("expected error for IPv6 egress CIDR (Phase A is IPv4-only)")
	}
}

func TestCompileEgress_Empty(t *testing.T) {
	c := mustCompile(t, &pb.NetworkPolicy{Tenant: "alice"})
	entries, err := CompileEgress(1, c)
	if err != nil {
		t.Fatalf("CompileEgress: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}
