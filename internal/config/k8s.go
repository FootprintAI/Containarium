package config

import (
	"fmt"
)

// CONTAINARIUM_K8S_* variable names — the single source of truth for the
// Kubernetes-backend namespace. Reference these instead of string literals.
const (
	EnvK8sKubeconfig               = "CONTAINARIUM_K8S_KUBECONFIG"
	EnvK8sGatewayNamespace         = "CONTAINARIUM_K8S_GATEWAY_NAMESPACE"
	EnvK8sGatewayHost              = "CONTAINARIUM_K8S_GATEWAY_HOST"
	EnvK8sGatewaySSHPort           = "CONTAINARIUM_K8S_GATEWAY_SSH_PORT"
	EnvK8sTenantNSPrefix           = "CONTAINARIUM_K8S_TENANT_NS_PREFIX"
	EnvK8sBoxImage                 = "CONTAINARIUM_K8S_BOX_IMAGE"
	EnvK8sStorageClass             = "CONTAINARIUM_K8S_STORAGE_CLASS"
	EnvK8sGatewayUpstreamPublicKey = "CONTAINARIUM_K8S_GATEWAY_UPSTREAM_PUBLIC_KEY"
	// #nosec G101 -- this is the NAME of an environment variable, not a credential value.
	EnvK8sGatewayUpstreamKeySecret = "CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET"
	EnvK8sInsecureIgnoreHostKey    = "CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY"
	EnvK8sDefaultMemoryRequest     = "CONTAINARIUM_K8S_DEFAULT_MEMORY_REQUEST"
	EnvK8sDefaultMemoryLimit       = "CONTAINARIUM_K8S_DEFAULT_MEMORY_LIMIT"
	EnvK8sDisableMemoryFloor       = "CONTAINARIUM_K8S_DISABLE_MEMORY_FLOOR"
)

// K8s defaults applied by LoadK8s when the variable is unset.
const (
	defaultK8sGatewayNamespace = "agent-gateway"
	defaultK8sTenantNSPrefix   = "tenant-"
	defaultK8sGatewaySSHPort   = 22
)

// K8s is the typed view of the CONTAINARIUM_K8S_* namespace — the wiring the
// daemon needs to drive the Kubernetes agent-box backend. Load it once at
// startup with LoadK8s; the server maps it onto pkg/core/box/k8s.Config (kept
// env-agnostic so that package stays free of this internal config dependency).
type K8s struct {
	// Kubeconfig is the path to a kubeconfig file; empty means in-cluster config
	// then the ambient loading rules. (EnvK8sKubeconfig)
	Kubeconfig string

	// GatewayNamespace is where the sshpiper Deployment + its LB Service live.
	// (EnvK8sGatewayNamespace; default "agent-gateway")
	GatewayNamespace string

	// GatewayHost is the public SSH endpoint agents connect to (the sshpiper LB).
	// (EnvK8sGatewayHost)
	GatewayHost string

	// GatewaySSHPort is the gateway SSH port. (EnvK8sGatewaySSHPort; default 22)
	GatewaySSHPort int

	// TenantNamespacePrefix prefixes each per-tenant namespace.
	// (EnvK8sTenantNSPrefix; default "tenant-")
	TenantNamespacePrefix string

	// BoxImage is the agent-box image (sshd + agent-box) each box runs.
	// (EnvK8sBoxImage)
	BoxImage string

	// StorageClass is the StorageClass for the box's data PVC; empty disables the
	// PVC. (EnvK8sStorageClass)
	StorageClass string

	// GatewayUpstreamPublicKey is the public key authorized on each box so
	// sshpiper can log in upstream. (EnvK8sGatewayUpstreamPublicKey)
	GatewayUpstreamPublicKey string

	// GatewayUpstreamKeySecret is the Secret (in GatewayNamespace) holding the
	// matching private key. (EnvK8sGatewayUpstreamKeySecret)
	GatewayUpstreamKeySecret string

	// InsecureIgnoreHostKey keeps the pre-pinning behavior (Pipe sets
	// ignore_hostkey). Default false = pin. (EnvK8sInsecureIgnoreHostKey)
	InsecureIgnoreHostKey bool

	// DefaultMemoryRequest / DefaultMemoryLimit override the per-box memory floor
	// applied when a box sets no valid memory. Empty = built-in defaults; an
	// invalid quantity degrades to the built-in default *in the backend*, so
	// these are intentionally not hard-validated here. (EnvK8sDefaultMemory*)
	DefaultMemoryRequest string
	DefaultMemoryLimit   string

	// DisableDefaultMemoryFloor turns the floor off entirely.
	// (EnvK8sDisableMemoryFloor)
	DisableDefaultMemoryFloor bool
}

// LoadK8s reads the CONTAINARIUM_K8S_* namespace from the environment once,
// applying the documented defaults.
func LoadK8s() K8s {
	return K8s{
		Kubeconfig:                getString(EnvK8sKubeconfig, ""),
		GatewayNamespace:          getString(EnvK8sGatewayNamespace, defaultK8sGatewayNamespace),
		GatewayHost:               getString(EnvK8sGatewayHost, ""),
		GatewaySSHPort:            getInt(EnvK8sGatewaySSHPort, defaultK8sGatewaySSHPort),
		TenantNamespacePrefix:     getString(EnvK8sTenantNSPrefix, defaultK8sTenantNSPrefix),
		BoxImage:                  getString(EnvK8sBoxImage, ""),
		StorageClass:              getString(EnvK8sStorageClass, ""),
		GatewayUpstreamPublicKey:  getString(EnvK8sGatewayUpstreamPublicKey, ""),
		GatewayUpstreamKeySecret:  getString(EnvK8sGatewayUpstreamKeySecret, ""),
		InsecureIgnoreHostKey:     getBool(EnvK8sInsecureIgnoreHostKey),
		DefaultMemoryRequest:      getString(EnvK8sDefaultMemoryRequest, ""),
		DefaultMemoryLimit:        getString(EnvK8sDefaultMemoryLimit, ""),
		DisableDefaultMemoryFloor: getBool(EnvK8sDisableMemoryFloor),
	}
}

// Validate reports configuration errors that should fail daemon startup. It is
// light by design: memory-floor quantities are resolved (and invalid ones
// degraded) in the backend, so only the gateway SSH port is checked here.
func (k K8s) Validate() error {
	if k.GatewaySSHPort < 1 || k.GatewaySSHPort > 65535 {
		return fmt.Errorf("%s=%d is not a valid TCP port (1-65535)", EnvK8sGatewaySSHPort, k.GatewaySSHPort)
	}
	return nil
}
