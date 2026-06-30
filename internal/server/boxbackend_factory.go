//go:build !windows

package server

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/footprintai/containarium/pkg/core/box"
	boxk8s "github.com/footprintai/containarium/pkg/core/box/k8s"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// RuntimeLXC and RuntimeK8s are the accepted values for CONTAINARIUM_RUNTIME /
// --runtime. LXC is the default for backward compatibility.
const (
	RuntimeLXC = "lxc"
	RuntimeK8s = "k8s"
)

// newManager constructs the daemon's container.Manager for the given runtime.
// For the lxc runtime a reachable incus is required (fatal on failure, as
// always). For the k8s runtime incus is optional — a failed connection degrades
// gracefully: box lifecycle goes through K8s; incus-only RPCs return errors.
func newManager(runtime string) (*container.Manager, error) {
	mgr, err := container.New()
	if err != nil {
		if runtime == RuntimeK8s {
			log.Printf("[k8s] incus not reachable (%v); box lifecycle uses the Kubernetes backend — legacy incus-only RPCs will return errors", err)
			return container.NewWithBackend(incus.NewUnavailableBackend()), nil
		}
		return nil, err
	}
	return mgr, nil
}

// newBoxBackend constructs the box-lifecycle backend for the given runtime.
// For lxc it wraps the Manager (today's default). For k8s it builds the
// Kubernetes backend from CONTAINARIUM_K8S_* env vars.
func newBoxBackend(runtime string, mgr *container.Manager) (box.BoxBackend, error) {
	switch runtime {
	case RuntimeK8s:
		return newK8sBackend()
	case RuntimeLXC, "":
		return boxlxc.New(mgr), nil
	default:
		return nil, fmt.Errorf("unknown runtime %q: must be %q or %q", runtime, RuntimeLXC, RuntimeK8s)
	}
}

func newK8sBackend() (box.BoxBackend, error) {
	port, _ := strconv.Atoi(os.Getenv("CONTAINARIUM_K8S_GATEWAY_SSH_PORT"))
	if port == 0 {
		port = 22
	}
	return boxk8s.New(boxk8s.Config{
		Kubeconfig:               os.Getenv("CONTAINARIUM_K8S_KUBECONFIG"),
		GatewayNamespace:         envOr("CONTAINARIUM_K8S_GATEWAY_NAMESPACE", "agent-gateway"),
		GatewayHost:              os.Getenv("CONTAINARIUM_K8S_GATEWAY_HOST"),
		GatewaySSHPort:           port,
		TenantNamespacePrefix:    envOr("CONTAINARIUM_K8S_TENANT_NS_PREFIX", "tenant-"),
		BoxImage:                 os.Getenv("CONTAINARIUM_K8S_BOX_IMAGE"),
		StorageClass:             os.Getenv("CONTAINARIUM_K8S_STORAGE_CLASS"),
		GatewayUpstreamPublicKey: os.Getenv("CONTAINARIUM_K8S_GATEWAY_UPSTREAM_PUBLIC_KEY"),
		GatewayUpstreamKeySecret: os.Getenv("CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET"),
		InsecureIgnoreHostKey:    os.Getenv("CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY") == "1",
		// Per-box default memory floor. Empty = built-in defaults (256Mi/1Gi);
		// an invalid quantity degrades to the built-in default. Disable turns the
		// floor off so boxes with no explicit memory run unconstrained.
		DefaultMemoryRequest:      os.Getenv("CONTAINARIUM_K8S_DEFAULT_MEMORY_REQUEST"),
		DefaultMemoryLimit:        os.Getenv("CONTAINARIUM_K8S_DEFAULT_MEMORY_LIMIT"),
		DisableDefaultMemoryFloor: os.Getenv("CONTAINARIUM_K8S_DISABLE_MEMORY_FLOOR") == "1",
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
