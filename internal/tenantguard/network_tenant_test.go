package tenantguard

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/nicguard"
)

func TestExplicitTenantRequiresEnforcedSupportedGuard(t *testing.T) {
	for _, kind := range []string{"off", "xtables", "old-incus"} {
		t.Run(kind, func(t *testing.T) {
			f := twoTenantHost()
			cfg := enforceCfg()
			switch kind {
			case "off":
				cfg.Mode = nicguard.ModeOff
			case "xtables":
				f.firewall = "xtables"
			case "old-incus":
				f.noBridgeACL = true
			}
			r := NewReconciler(f, cfg)
			if err := r.PrepareNetworkTenant(context.Background(), "new-container", "allinone"); err == nil {
				t.Fatal("explicit membership accepted without enforced NIC guard")
			}
			if f.writes() != 0 {
				t.Fatal("unsupported guard wrote ACL state")
			}
		})
	}
}

func TestExplicitTenantAttachesComputedACLToNewNIC(t *testing.T) {
	f := twoTenantHost()
	r := NewReconciler(f, enforceCfg())
	if err := r.PrepareNetworkTenant(context.Background(), "new-container", "team-a"); err != nil {
		t.Fatal(err)
	}
	acl := ACLName("team-a")
	if _, ok := f.acls[acl]; !ok {
		t.Fatal("required Tenant ACL not created")
	}
	if f.devices["new-container"]["eth0"]["security.acls"] != acl {
		t.Fatalf("wrong birth NIC ACL: %v", f.devices["new-container"])
	}
}
