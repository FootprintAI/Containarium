package container

import (
	"context"
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/ospkg"
	"github.com/footprintai/containarium/internal/ostype"
)

// CollaboratorManager handles collaborator operations for containers
type CollaboratorManager struct {
	manager *Manager
	store   *collaborator.Store
}

// NewCollaboratorManager creates a new collaborator manager
func NewCollaboratorManager(manager *Manager, store *collaborator.Store) *CollaboratorManager {
	return &CollaboratorManager{
		manager: manager,
		store:   store,
	}
}

// AddCollaborator adds a collaborator to a container
// This creates:
// 1. A user in the container with the name {container-name}-{collaborator-username}
// 2. Sudoers configuration allowing passwordless sudo su to the container owner
// 3. Session logging for audit trail
// 4. Jump server account for SSH ProxyJump access
// 5. Persistence record in PostgreSQL
func (cm *CollaboratorManager) AddCollaborator(ownerUsername, collaboratorUsername, sshPublicKey string, grantSudo, grantContainerRuntime bool) (*collaborator.Collaborator, error) {
	// Validate inputs
	if ownerUsername == "" {
		return nil, fmt.Errorf("owner username cannot be empty")
	}
	if collaboratorUsername == "" {
		return nil, fmt.Errorf("collaborator username cannot be empty")
	}
	if sshPublicKey == "" {
		return nil, fmt.Errorf("SSH public key cannot be empty")
	}

	// Validate owner username (same rules — prevents sudoers injection)
	if !isValidCollaboratorUsername(ownerUsername) {
		return nil, fmt.Errorf("invalid owner username: must contain only letters, numbers, dash, and underscore")
	}

	// Validate collaborator username
	if !isValidCollaboratorUsername(collaboratorUsername) {
		return nil, fmt.Errorf("invalid collaborator username: must contain only letters, numbers, dash, and underscore")
	}

	containerName := ownerUsername + "-container"
	accountName := containerName + "-" + collaboratorUsername

	// Validate account name length (Linux username limit is 32 characters)
	if len(accountName) > 32 {
		return nil, fmt.Errorf("account name %q exceeds Linux 32-character limit (%d chars); use shorter usernames", accountName, len(accountName))
	}

	// Check if container exists and is running
	info, err := cm.manager.incus.GetContainer(containerName)
	if err != nil {
		return nil, fmt.Errorf("container not found: %w", err)
	}
	if info.State != "Running" {
		return nil, fmt.Errorf("container must be running to add collaborator, current state: %s", info.State)
	}

	// Step 1: Create collaborator user in the container
	if err := cm.createCollaboratorUser(containerName, ownerUsername, accountName, sshPublicKey, grantSudo, grantContainerRuntime); err != nil {
		return nil, fmt.Errorf("failed to create collaborator user in container: %w", err)
	}

	// Step 2: Create jump server account for SSH ProxyJump access
	if err := CreateJumpServerAccount(accountName, sshPublicKey, true); err != nil {
		// Rollback: remove user from container
		_ = cm.removeCollaboratorUser(containerName, accountName)
		return nil, fmt.Errorf("failed to create jump server account: %w", err)
	}

	// Step 3: Store collaborator in database
	collab := &collaborator.Collaborator{
		ContainerName:        containerName,
		OwnerUsername:        ownerUsername,
		CollaboratorUsername: collaboratorUsername,
		AccountName:          accountName,
		SSHPublicKey:         sshPublicKey,
		CreatedAt:            time.Now(),
		CreatedBy:            ownerUsername,
		HasSudo:              grantSudo,
		HasContainerRuntime:  grantContainerRuntime,
	}

	if err := cm.store.Add(context.Background(), collab); err != nil {
		// Rollback: remove user from container and jump server
		_ = cm.removeCollaboratorUser(containerName, accountName)
		_ = DeleteJumpServerAccount(accountName, true)
		return nil, fmt.Errorf("failed to store collaborator: %w", err)
	}

	return collab, nil
}

// createCollaboratorUser creates a collaborator user inside the container
func (cm *CollaboratorManager) createCollaboratorUser(containerName, ownerUsername, accountName, sshPublicKey string, grantSudo, grantContainerRuntime bool) error {
	// Detect OS family from container labels or by probing
	info, err := cm.manager.incus.GetContainer(containerName)
	family := ostype.Debian
	if err == nil {
		if osLabel, ok := info.Labels[ostype.OSTypeLabelKey]; ok {
			family = ostype.FamilyFromLabel(osLabel)
		} else {
			family = ostype.DetectFamily(cm.manager.incus, containerName)
		}
	}
	pkgMgr := ospkg.ForFamily(family)

	// Create user (OS-aware: adduser on Debian, useradd on RHEL)
	gecos := fmt.Sprintf("Collaborator %s", accountName)
	if err := cm.manager.incus.Exec(containerName, pkgMgr.CreateUserCmd(accountName, gecos)); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Configure sudoers with session logging
	var sudoersContent string
	if grantSudo {
		sudoersContent = cm.generateFullSudoers(accountName)
	} else {
		sudoersContent = cm.generateCollaboratorSudoers(accountName, ownerUsername)
	}
	sudoersPath := fmt.Sprintf("/etc/sudoers.d/%s", accountName)

	if err := cm.manager.incus.WriteFile(containerName, sudoersPath, []byte(sudoersContent), "0440"); err != nil {
		return fmt.Errorf("failed to configure sudoers: %w", err)
	}

	// Create sudo I/O log directory
	logDir := fmt.Sprintf("/var/log/sudo-io/%s", accountName)
	if err := cm.manager.incus.Exec(containerName, []string{"mkdir", "-p", logDir}); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	if err := cm.manager.incus.Exec(containerName, []string{"chmod", "750", logDir}); err != nil {
		return fmt.Errorf("failed to set log directory permissions: %w", err)
	}

	// Grant container runtime access (add to docker and/or podman groups)
	if grantContainerRuntime {
		// Add to docker group (if it exists)
		_ = cm.manager.incus.Exec(containerName, []string{"usermod", "-aG", "docker", accountName})
		// Add to podman group (if it exists)
		_ = cm.manager.incus.Exec(containerName, []string{"usermod", "-aG", "podman", accountName})
	}

	// Setup SSH keys
	if err := cm.manager.addSSHKeys(containerName, accountName, []string{sshPublicKey}); err != nil {
		return fmt.Errorf("failed to add SSH keys: %w", err)
	}

	// Create logrotate config for sudo-io logs (if it doesn't exist)
	logrotateConfig := `/var/log/sudo-io/*/* {
    daily
    missingok
    rotate 90
    compress
    delaycompress
    notifempty
    create 640 root adm
}
`
	_ = cm.manager.incus.WriteFile(containerName, "/etc/logrotate.d/sudo-io", []byte(logrotateConfig), "0644")

	return nil
}

// generateFullSudoers generates sudoers configuration granting full sudo access with session logging
func (cm *CollaboratorManager) generateFullSudoers(accountName string) string {
	return fmt.Sprintf(`# Collaborator %s - full sudo access with session logging
Defaults:%s log_input, log_output
Defaults:%s iolog_dir=/var/log/sudo-io/%s
Defaults:%s iolog_file=%%{user}.%%{seq}

# Allow full passwordless sudo access
%s ALL=(ALL) NOPASSWD: ALL
`,
		accountName,
		accountName,
		accountName, accountName,
		accountName,
		accountName,
	)
}

// generateCollaboratorSudoers generates sudoers configuration with session logging
func (cm *CollaboratorManager) generateCollaboratorSudoers(accountName, ownerUsername string) string {
	// Enable I/O logging for full session capture
	// Logs are stored in /var/log/sudo-io/{accountName}/
	return fmt.Sprintf(`# Collaborator %s - can switch to %s with session logging
Defaults:%s log_input, log_output
Defaults:%s iolog_dir=/var/log/sudo-io/%s
Defaults:%s iolog_file=%%{user}.%%{seq}

# Allow passwordless switch to container owner only
%s ALL=(%s) NOPASSWD: /bin/su - %s
%s ALL=(%s) NOPASSWD: /usr/bin/su - %s
`,
		accountName, ownerUsername,
		accountName,
		accountName, accountName,
		accountName,
		accountName, ownerUsername, ownerUsername,
		accountName, ownerUsername, ownerUsername,
	)
}

// RemoveCollaborator removes a collaborator from a container
func (cm *CollaboratorManager) RemoveCollaborator(ownerUsername, collaboratorUsername string) error {
	containerName := ownerUsername + "-container"
	accountName := containerName + "-" + collaboratorUsername

	// Remove user from container (best effort)
	if err := cm.removeCollaboratorUser(containerName, accountName); err != nil {
		fmt.Printf("Warning: failed to remove user from container: %v\n", err)
	}

	// Remove jump server account
	if err := DeleteJumpServerAccount(accountName, true); err != nil {
		fmt.Printf("Warning: failed to remove jump server account: %v\n", err)
	}

	// Remove from database
	if err := cm.store.Remove(context.Background(), containerName, collaboratorUsername); err != nil {
		return fmt.Errorf("failed to remove collaborator from database: %w", err)
	}

	return nil
}

// removeCollaboratorUser removes a collaborator user from the container
func (cm *CollaboratorManager) removeCollaboratorUser(containerName, accountName string) error {
	// Remove sudoers file
	sudoersPath := fmt.Sprintf("/etc/sudoers.d/%s", accountName)
	_ = cm.manager.incus.Exec(containerName, []string{"rm", "-f", sudoersPath})

	// Delete user and home directory
	if err := cm.manager.incus.Exec(containerName, []string{"userdel", "-r", accountName}); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// ListCollaborators returns all collaborators for a container
func (cm *CollaboratorManager) ListCollaborators(ownerUsername string) ([]*collaborator.Collaborator, error) {
	containerName := ownerUsername + "-container"
	return cm.store.List(context.Background(), containerName)
}

// GetCollaborator returns a specific collaborator
func (cm *CollaboratorManager) GetCollaborator(ownerUsername, collaboratorUsername string) (*collaborator.Collaborator, error) {
	containerName := ownerUsername + "-container"
	return cm.store.Get(context.Background(), containerName, collaboratorUsername)
}

// RemoveAllCollaborators removes all collaborators for a container
// This is called when deleting a container
func (cm *CollaboratorManager) RemoveAllCollaborators(ownerUsername string) error {
	containerName := ownerUsername + "-container"

	// Get all collaborators first
	collaborators, err := cm.store.List(context.Background(), containerName)
	if err != nil {
		return fmt.Errorf("failed to list collaborators: %w", err)
	}

	// Remove jump server accounts for all collaborators
	for _, c := range collaborators {
		if err := DeleteJumpServerAccount(c.AccountName, true); err != nil {
			fmt.Printf("Warning: failed to remove jump server account %s: %v\n", c.AccountName, err)
		}
	}

	// Remove all collaborators from database
	_, err = cm.store.RemoveByContainer(context.Background(), containerName)
	if err != nil {
		return fmt.Errorf("failed to remove collaborators from database: %w", err)
	}

	return nil
}

// GenerateSSHCommand generates the SSH command for a collaborator
func (cm *CollaboratorManager) GenerateSSHCommand(ownerUsername, collaboratorUsername, jumpServerHost string) string {
	accountName := ownerUsername + "-container-" + collaboratorUsername
	return fmt.Sprintf("ssh -J %s@%s %s@<container-ip>", accountName, jumpServerHost, accountName)
}

// isValidCollaboratorUsername validates collaborator username format
func isValidCollaboratorUsername(username string) bool {
	if len(username) == 0 || len(username) > 32 {
		return false
	}

	for _, ch := range username {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_') {
			return false
		}
	}

	// Cannot start with digit or dash
	firstChar := rune(username[0])
	return !((firstChar >= '0' && firstChar <= '9') || firstChar == '-')
}

// SyncCollaboratorAccounts recreates jump server accounts for all collaborators.
// When force is true, accounts are recreated even if they already exist.
func (cm *CollaboratorManager) SyncCollaboratorAccounts(verbose, force bool) (restored, skipped, failed int) {
	collaborators, err := cm.store.ListAll(context.Background())
	if err != nil {
		if verbose {
			fmt.Printf("Failed to list collaborators: %v\n", err)
		}
		return 0, 0, 1
	}

	for _, c := range collaborators {
		// Check if jump server account exists
		if !force && userExists(c.AccountName) {
			if verbose {
				fmt.Printf("  ✓ Jump server account %s already exists, skipping\n", c.AccountName)
			}
			skipped++
			continue
		}

		// Create jump server account
		if err := CreateJumpServerAccount(c.AccountName, c.SSHPublicKey, verbose); err != nil {
			if verbose {
				fmt.Printf("  ✗ Failed to create jump server account for %s: %v\n", c.AccountName, err)
			}
			failed++
			continue
		}

		if verbose {
			fmt.Printf("  ✓ Jump server account restored for collaborator %s\n", c.AccountName)
		}
		restored++
	}

	return restored, skipped, failed
}

// GetStore returns the collaborator store (for server handlers)
func (cm *CollaboratorManager) GetStore() *collaborator.Store {
	return cm.store
}

