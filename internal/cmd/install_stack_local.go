//go:build !containarium_client

package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/container"
)

func installStackLocal(username, stackID string) error {
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w", err)
	}

	if err := mgr.InstallStack(username, stackID); err != nil {
		return fmt.Errorf("failed to install stack: %w", err)
	}

	fmt.Printf("\n✓ Stack %q installed successfully on %s-container\n", stackID, username)
	return nil
}
