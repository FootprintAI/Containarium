//go:build !containarium_client

package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/container"
)

// deleteLocal deletes a container using local Incus daemon
func deleteLocal(username string, force bool) error {
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	return mgr.Delete(username, force)
}

// deleteJumpServerAccountLocal removes the local jump-server account after a
// local delete. Best-effort: prints a warning rather than failing the
// command — the container is already gone by the time this runs.
func deleteJumpServerAccountLocal(username string, verbose bool) {
	if verbose {
		fmt.Println("Removing jump server account...")
	}

	if err := container.DeleteJumpServerAccount(username, verbose); err != nil {
		// Don't fail the entire operation if jump server account deletion fails
		// Container is already deleted at this point
		fmt.Printf("Warning: Failed to delete jump server account for %s: %v\n", username, err)
		fmt.Println("You may need to manually remove the account with: sudo userdel -r " + username)
	} else {
		fmt.Printf("✓ Jump server account %s deleted\n", username)
	}
}
