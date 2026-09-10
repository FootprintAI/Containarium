package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
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
  containarium collaborator add alice bob --ssh-key ~/.ssh/bob-laptop.pub --ssh-key ~/.ssh/bob-desktop.pub

  # Against a remote daemon
  containarium collaborator add alice bob --ssh-key ~/.ssh/bob.pub --server daemon.example.com:50051`,
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

	switch {
	case httpMode && serverAddr != "":
		return addCollaboratorRemoteHTTP(ownerUsername, collaboratorUsername, sshPublicKeys)
	case serverAddr != "":
		return addCollaboratorRemote(ownerUsername, collaboratorUsername, sshPublicKeys)
	default:
		return addCollaboratorLocal(ownerUsername, collaboratorUsername, sshPublicKeys)
	}
}

func addCollaboratorRemote(ownerUsername, collaboratorUsername string, sshPublicKeys []string) error {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to remote server: %w", err)
	}
	defer func() { _ = grpcClient.Close() }()

	resp, err := grpcClient.AddCollaborator(ownerUsername, collaboratorUsername, sshPublicKeys, collaboratorGrantSudo, collaboratorGrantRuntime)
	if err != nil {
		return fmt.Errorf("failed to add collaborator: %w", err)
	}
	printAddCollaboratorResponse(resp)
	return nil
}

func addCollaboratorRemoteHTTP(ownerUsername, collaboratorUsername string, sshPublicKeys []string) error {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer func() { _ = httpClient.Close() }()

	resp, err := httpClient.AddCollaborator(ownerUsername, collaboratorUsername, sshPublicKeys, collaboratorGrantSudo, collaboratorGrantRuntime)
	if err != nil {
		return fmt.Errorf("failed to add collaborator: %w", err)
	}
	printAddCollaboratorResponse(resp)
	return nil
}

func printAddCollaboratorResponse(resp *pb.AddCollaboratorResponse) {
	collab := resp.GetCollaborator()
	fmt.Printf("Collaborator %s added to %s\n\n", collab.GetCollaboratorUsername(), collab.GetContainerName())
	fmt.Printf("Account name: %s\n", collab.GetAccountName())
	if resp.GetSshCommand() != "" {
		fmt.Printf("SSH command:  %s\n\n", resp.GetSshCommand())
	}
	if collab.GetHasSudo() {
		fmt.Printf("Sudo access:  full (ALL commands)\n")
	} else {
		fmt.Printf("After connecting, use: sudo su - %s\n", collab.GetOwnerUsername())
	}
	if collab.GetHasContainerRuntime() {
		fmt.Printf("Container runtime: docker/podman group membership granted\n")
	}
	fmt.Printf("Sessions are logged to: /var/log/sudo-io/%s/\n", collab.GetAccountName())
}
