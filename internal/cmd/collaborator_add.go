package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/spf13/cobra"
)

// validSSHKeyPrefixes lists all accepted SSH public key prefixes, including FIDO keys.
var validSSHKeyPrefixes = []string{
	"ssh-",
	"ecdsa-",
	"sk-ssh-",
	"sk-ecdsa-",
}

var (
	collaboratorSSHKeyFiles  []string
	collaboratorGrantSudo    bool
	collaboratorGrantRuntime bool
)

var collaboratorAddCmd = &cobra.Command{
	Use:   "add <owner-username> <collaborator-username>",
	Short: "Add a collaborator to a container",
	Long: `Add a collaborator to a container.

The collaborator will be able to:
1. SSH into the container via their own account
2. Switch to the container owner's account using 'sudo su - <owner>'
3. All sessions are logged for auditing

Use --sudo to grant full sudo access (not just su - owner).
Use --container-runtime to add the collaborator to docker/podman groups.

A jump server account will also be created for SSH ProxyJump access.

Examples:
  # Add bob as a collaborator to alice's container
  containarium collaborator add alice bob --ssh-key ~/.ssh/bob.pub

  # Add carol as a collaborator using a different SSH key
  containarium collaborator add alice carol --ssh-key /path/to/carol.pub

  # Authorize several of bob's keys (one per machine)
  containarium collaborator add alice bob --ssh-key ~/.ssh/bob-laptop.pub --ssh-key ~/.ssh/bob-desktop.pub`,
	Args: cobra.ExactArgs(2),
	RunE: runCollaboratorAdd,
}

func init() {
	collaboratorCmd.AddCommand(collaboratorAddCmd)
	collaboratorAddCmd.Flags().StringArrayVar(&collaboratorSSHKeyFiles, "ssh-key", nil, "path to collaborator's SSH public key file (required; repeat to authorize multiple keys)")
	_ = collaboratorAddCmd.MarkFlagRequired("ssh-key")
	collaboratorAddCmd.Flags().BoolVar(&collaboratorGrantSudo, "sudo", false, "grant full sudo access (not just su - owner)")
	collaboratorAddCmd.Flags().BoolVar(&collaboratorGrantRuntime, "container-runtime", false, "add collaborator to docker/podman groups")
}

func runCollaboratorAdd(cmd *cobra.Command, args []string) error {
	ownerUsername := args[0]
	collaboratorUsername := args[1]

	// Read + validate each SSH public key file. All are authorized so
	// the collaborator can connect from any of their machines (#369).
	var sshPublicKeys []string
	for _, keyFile := range collaboratorSSHKeyFiles {
		sshKeyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read SSH key file %q: %w", keyFile, err)
		}
		sshPublicKey := strings.TrimSpace(string(sshKeyBytes))
		if sshPublicKey == "" {
			return fmt.Errorf("SSH key file %q is empty", keyFile)
		}
		validKey := false
		for _, prefix := range validSSHKeyPrefixes {
			if strings.HasPrefix(sshPublicKey, prefix) {
				validKey = true
				break
			}
		}
		if !validKey {
			return fmt.Errorf("invalid SSH public key format in %q", keyFile)
		}
		sshPublicKeys = append(sshPublicKeys, sshPublicKey)
	}

	// Local mode only for now (requires PostgreSQL)
	return addCollaboratorLocal(ownerUsername, collaboratorUsername, sshPublicKeys)
}

func addCollaboratorLocal(ownerUsername, collaboratorUsername string, sshPublicKeys []string) error {
	// Create container manager
	containerMgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	// Check if container exists
	containerName := ownerUsername + "-container"
	if !containerMgr.ContainerExists(containerName) {
		return fmt.Errorf("container %q does not exist", containerName)
	}

	// Create collaborator store
	collaboratorStore, err := collaborator.NewStore(context.Background(), getPostgresConnString())
	if err != nil {
		return fmt.Errorf("failed to connect to collaborator database: %w\n(Is PostgreSQL running? Set CONTAINARIUM_POSTGRES_URL if using non-default location)", err)
	}
	defer collaboratorStore.Close()

	// Create collaborator manager
	collaboratorMgr := container.NewCollaboratorManager(containerMgr, collaboratorStore)

	// Add collaborator
	collab, err := collaboratorMgr.AddCollaborator(ownerUsername, collaboratorUsername, sshPublicKeys, collaboratorGrantSudo, collaboratorGrantRuntime)
	if err != nil {
		return fmt.Errorf("failed to add collaborator: %w", err)
	}

	fmt.Printf("Collaborator %s added to %s-container\n\n", collaboratorUsername, ownerUsername)
	fmt.Printf("Account name: %s\n", collab.AccountName)
	fmt.Printf("SSH command:  %s\n\n", collaboratorMgr.GenerateSSHCommand(ownerUsername, collaboratorUsername, "<jump-server-ip>"))
	if collab.HasSudo {
		fmt.Printf("Sudo access:  full (ALL commands)\n")
	} else {
		fmt.Printf("After connecting, use: sudo su - %s\n", ownerUsername)
	}
	if collab.HasContainerRuntime {
		fmt.Printf("Container runtime: docker/podman group membership granted\n")
	}
	fmt.Printf("Sessions are logged to: /var/log/sudo-io/%s/\n", collab.AccountName)

	return nil
}
