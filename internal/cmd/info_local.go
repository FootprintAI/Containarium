//go:build !containarium_client

package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// getSystemInfoLocal is showSystemInfo's local-mode branch: server info plus
// the full container list, both read directly from Incus.
func getSystemInfoLocal() (*incus.ServerInfo, []incus.ContainerInfo, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	serverInfo, err := mgr.GetServerInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get server info: %w", err)
	}

	containers, err := mgr.List()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list containers: %w", err)
	}

	return serverInfo, containers, nil
}

// getContainerInfoLocal is showContainerInfo's local-mode branch.
func getContainerInfoLocal(username string) (*incus.ContainerInfo, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	info, err := mgr.Get(username)
	if err != nil {
		return nil, fmt.Errorf("container not found: %w", err)
	}
	return info, nil
}
