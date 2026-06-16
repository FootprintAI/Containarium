//go:build k8s

package server

import (
	"os"
	"strconv"

	"github.com/footprintai/containarium/pkg/core/box"
	boxk8s "github.com/footprintai/containarium/pkg/core/box/k8s"
	"github.com/footprintai/containarium/pkg/core/container"
)

// newBoxBackend selects the box runtime for the `containarium-k8s` build
// variant: the Kubernetes backend, configured from CONTAINARIUM_K8S_* env.
//
// mgr is intentionally unused — the K8s backend talks to the kube-apiserver,
// not incus. The server still constructs and holds a Manager for the
// non-lifecycle surface (Exec, config keys, security scan, app hosting) during
// the transition, so a K8s-only host today still needs incus reachable at
// startup; making that construction incus-free is a follow-up.
func newBoxBackend(_ *container.Manager) (box.BoxBackend, error) {
	port, _ := strconv.Atoi(os.Getenv("CONTAINARIUM_K8S_GATEWAY_SSH_PORT"))
	if port == 0 {
		port = 22
	}
	return boxk8s.New(boxk8s.Config{
		Kubeconfig:            os.Getenv("CONTAINARIUM_K8S_KUBECONFIG"),
		GatewayNamespace:      k8sEnvOr("CONTAINARIUM_K8S_GATEWAY_NAMESPACE", "agent-gateway"),
		GatewayHost:           os.Getenv("CONTAINARIUM_K8S_GATEWAY_HOST"),
		GatewaySSHPort:        port,
		TenantNamespacePrefix: k8sEnvOr("CONTAINARIUM_K8S_TENANT_NS_PREFIX", "tenant-"),
		BoxImage:              os.Getenv("CONTAINARIUM_K8S_BOX_IMAGE"),
		StorageClass:          os.Getenv("CONTAINARIUM_K8S_STORAGE_CLASS"),
	})
}

// k8sEnvOr returns the env var value or a default when unset. Defined here (in
// the k8s-tagged file) so it never collides with the default build.
func k8sEnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
