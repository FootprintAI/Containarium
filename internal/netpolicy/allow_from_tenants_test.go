package netpolicy

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// allow_from_tenants is normalised on Compile (trim, drop empty, dedup,
// sort), round-trips through ToProto, and never names the tenant itself.
func TestCompile_AllowFromTenants(t *testing.T) {
	c, err := Compile(&pb.NetworkPolicy{Tenant: "alice", AllowFromTenants: []string{" bob ", "carol", "bob", "", "aaron"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aaron", "bob", "carol"}
	if strings.Join(c.AllowFromTenants, ",") != strings.Join(want, ",") {
		t.Errorf("AllowFromTenants = %v, want %v", c.AllowFromTenants, want)
	}
	if got := c.ToProto().GetAllowFromTenants(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ToProto AllowFromTenants = %v, want %v", got, want)
	}
	if _, err := Compile(&pb.NetworkPolicy{Tenant: "alice", AllowFromTenants: []string{"bob", "alice"}}); err == nil || !strings.Contains(err.Error(), "allow_intra_tenant") {
		t.Errorf("self in allow_from_tenants must be rejected and point at allow_intra_tenant, got %v", err)
	}
	c, err = Compile(&pb.NetworkPolicy{Tenant: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AllowFromTenants) != 0 || len(c.ToProto().GetAllowFromTenants()) != 0 {
		t.Errorf("empty stays empty: %v", c.AllowFromTenants)
	}
}
