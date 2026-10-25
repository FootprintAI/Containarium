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

// NetworkTenantSource names the observed Provider input, independently of login.
type NetworkTenantSource string

const (
	NetworkTenantSourceNative  NetworkTenantSource = "NETWORK_TENANT_SOURCE_NATIVE"
	NetworkTenantSourceCloud   NetworkTenantSource = "NETWORK_TENANT_SOURCE_CLOUD_ORG_ID"
	NetworkTenantSourceName    NetworkTenantSource = "NETWORK_TENANT_SOURCE_NAME"
	NetworkTenantSourceUnknown NetworkTenantSource = "NETWORK_TENANT_SOURCE_UNSPECIFIED"
)

// NetworkTenantIdentity resolves only current Provider state, never request data.
func NetworkTenantIdentity(info *ContainerInfo) (string, NetworkTenantSource) {
	if info.NetworkTenantSource != "" {
		return info.Tenant, info.NetworkTenantSource
	}
	if info.InstanceType != "" && info.InstanceType != "container" {
		return "", NetworkTenantSourceUnknown
	}
	if strings.TrimSpace(info.Tenant) != "" {
		return strings.TrimSpace(info.Tenant), NetworkTenantSourceNative
	}
	if cloud := strings.TrimSpace(info.Labels[CloudOrgIDLabel]); cloud != "" {
		return cloud, NetworkTenantSourceCloud
	}
	if key := strings.TrimSuffix(info.Name, "-container"); key != "" {
		return key, NetworkTenantSourceName
	}
	return "", NetworkTenantSourceUnknown
}
