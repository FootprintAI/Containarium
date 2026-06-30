//go:build !windows

package server

import (
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/config"
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
	// The CONTAINARIUM_K8S_* namespace is read + defaulted once via internal/config
	// (typed, validated); pkg/core/box/k8s.Config stays env-agnostic, so we map
	// the fields across here.
	cfg := config.LoadK8s()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("k8s config: %w", err)
	}
	return boxk8s.New(boxk8s.Config{
		Kubeconfig:                cfg.Kubeconfig,
		GatewayNamespace:          cfg.GatewayNamespace,
		GatewayHost:               cfg.GatewayHost,
		GatewaySSHPort:            cfg.GatewaySSHPort,
		TenantNamespacePrefix:     cfg.TenantNamespacePrefix,
		BoxImage:                  cfg.BoxImage,
		StorageClass:              cfg.StorageClass,
		GatewayUpstreamPublicKey:  cfg.GatewayUpstreamPublicKey,
		GatewayUpstreamKeySecret:  cfg.GatewayUpstreamKeySecret,
		InsecureIgnoreHostKey:     cfg.InsecureIgnoreHostKey,
		DefaultMemoryRequest:      cfg.DefaultMemoryRequest,
		DefaultMemoryLimit:        cfg.DefaultMemoryLimit,
		DisableDefaultMemoryFloor: cfg.DisableDefaultMemoryFloor,
	})
}
