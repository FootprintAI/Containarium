package incus

import (
	"fmt"
	"regexp"
	"strings"
)

var nativeNetworkTenantRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidateNetworkTenant accepts a bounded logical security-domain identifier.
// It is not a label-map key or an encryption tenant_id.
func ValidateNetworkTenant(key string) error {
	if key != strings.TrimSpace(key) || !nativeNetworkTenantRE.MatchString(key) {
		return fmt.Errorf("invalid network Tenant: expected 1-128 letters, digits, dot, underscore, colon or hyphen")
	}
	if strings.HasPrefix(key, "core-") || strings.HasPrefix(key, "containarium-core-") {
		return fmt.Errorf("reserved network Tenant")
	}
	return nil
}
