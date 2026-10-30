package tenantguard

import (
	"context"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"testing"
)

func TestTenantReviewGuardMustSeparateAccountFromSharedTenant(t *testing.T) {
	admin := incus.ContainerInfo{Name: "admin-box-container", Tenant: "team-a", IPAddress: "10.100.0.18", State: "Running"}
	user := incus.ContainerInfo{Name: "team-a-container", Tenant: "account:team-a", IPAddress: "10.100.0.19", State: "Running"}
	f := newFakeBackend("nftables", admin, user)
	r := NewReconciler(f, enforceCfg())
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminACL := f.devices[admin.Name]["eth0"]["security.acls"]
	userACL := f.devices[user.Name]["eth0"]["security.acls"]
	if adminACL == userACL && srcSet(f.acls[adminACL])["10.100.0.19/32"] {
		t.Fatalf("same ACL %s permits account box into admin domain as sibling", adminACL)
	}
}

func TestTenantReviewAcceptedAccountPolicyMustReachACL(t *testing.T) {
	if err := incus.ValidateNetworkTenant("account:alice"); err != nil {
		t.Fatal(err)
	}
	f := newFakeBackend("nftables", incus.ContainerInfo{Name: "alice-container", Tenant: "account:alice", IPAddress: "10.100.0.17", State: "Running"}, box("bob", "10.100.0.33"))
	cfg := enforceCfg()
	cfg.Policies = PolicySourceFunc(func(context.Context) ([]*pb.NetworkPolicy, error) {
		return []*pb.NetworkPolicy{{Tenant: "account:alice", AllowFromTenants: []string{"bob"}}}, nil
	})
	r := NewReconciler(f, cfg)
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	acl := f.devices["alice-container"]["eth0"]["security.acls"]
	if !srcSet(f.acls[acl])["10.100.0.33/32"] {
		t.Fatal("accepted account:alice policy is not consumed by canonical alice Guard")
	}
}
