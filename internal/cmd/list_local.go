//go:build !containarium_client

package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// listLocal lists containers from local Incus daemon
func listLocal() ([]incus.ContainerInfo, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	return mgr.List()
}
