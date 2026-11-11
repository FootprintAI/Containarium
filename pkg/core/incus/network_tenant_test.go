package incus

import "testing"

func TestValidateNetworkTenant(t *testing.T) {
	for _, name := range []string{"allinone", "app.dev", "team-a", "tenant_1"} {
		if err := ValidateNetworkTenant(name); err != nil {
			t.Fatalf("valid %q: %v", name, err)
		}
	}
	for _, name := range []string{"", " bad", "a/b", "core-postgres", "containarium-core-caddy", "A\\nB"} {
		if err := ValidateNetworkTenant(name); err == nil {
			t.Fatalf("unexpected valid network Tenant %q", name)
		}
	}
}
