//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/pkg/core/container"
)

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

func removeCollaboratorLocal(ownerUsername, collaboratorUsername string) error {
	// Create container manager
	containerMgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	// Create collaborator store
	collaboratorStore, err := collaborator.NewStore(context.Background(), getPostgresConnString())
	if err != nil {
		return fmt.Errorf("failed to connect to collaborator database: %w\n(Is PostgreSQL running? Set CONTAINARIUM_POSTGRES_URL if using non-default location)", err)
	}
	defer collaboratorStore.Close()

	// Create collaborator manager
	collaboratorMgr := container.NewCollaboratorManager(containerMgr, collaboratorStore)

	// Remove collaborator
	if err := collaboratorMgr.RemoveCollaborator(ownerUsername, collaboratorUsername); err != nil {
		return fmt.Errorf("failed to remove collaborator: %w", err)
	}

	fmt.Printf("Collaborator %s removed from %s-container\n", collaboratorUsername, ownerUsername)
	return nil
}

// listCollaboratorsLocal returns []collaboratorRow, not []collaborator.Collaborator
// — the dispatcher (collaborator_list.go, no build tag) needs a signature
// that also exists under containarium_client (local_stubs_client.go's
// stub), and internal/collaborator imports pgx, which the client build
// must never link in. collaboratorRow is a plain cmd-package type with no
// such dependency.
func listCollaboratorsLocal(ownerUsername string) ([]collaboratorRow, error) {
	containerName := ownerUsername + "-container"

	// Create collaborator store
	collaboratorStore, err := collaborator.NewStore(context.Background(), getPostgresConnString())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to collaborator database: %w\n(Is PostgreSQL running? Set CONTAINARIUM_POSTGRES_URL if using non-default location)", err)
	}
	defer collaboratorStore.Close()

	// List collaborators
	collaborators, err := collaboratorStore.List(context.Background(), containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to list collaborators: %w", err)
	}

	rows := make([]collaboratorRow, 0, len(collaborators))
	for _, c := range collaborators {
		rows = append(rows, collaboratorRow{
			CollaboratorUsername: c.CollaboratorUsername,
			AccountName:          c.AccountName,
			CreatedAt:            c.CreatedAt,
			CreatedBy:            c.CreatedBy,
		})
	}
	return rows, nil
}
