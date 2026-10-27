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

// NativeTenantContractID is the stable identifier of the capability handshake
// between a daemon and its clients (CLI, Host MCP, external gRPC consumers).
// A client that does not see this exact value must not rely on the additive
// CreateContainer network_tenant field. The identifier is deliberately
// provider-neutral: it names the contract, not any downstream integration.
const NativeTenantContractID = "native-network-tenant/v1"

// NativeTenantBackendScope is the only scope whose creation and membership
// evidence the contract v1 covers: this daemon's own local Linux LXC backend.
const NativeTenantBackendScope = "local-lxc"

// TenantAccessAbsentRevision is the expected_revision sentinel meaning "no
// policy exists for this destination yet". A grant may create the policy; a
// revoke naming it is rejected as a no-op.
const TenantAccessAbsentRevision = "absent"

// AccountNetworkTenantPrefix reserves the per-user namespace independently of
// administrator-managed shared domains. Never strip it for ACL or tenant IDs.
const AccountNetworkTenantPrefix = "account:"

// LegacyAccountPolicyKey supplies an optional egress-only compatibility lookup.
// The returned key must never be used as an account's enforcement identity.
func LegacyAccountPolicyKey(key string) (string, bool) {
	bare, ok := strings.CutPrefix(key, AccountNetworkTenantPrefix)
	return bare, ok && bare != ""
}

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
