package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/ostype"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	sshKeyPath               string
	cpuLimit                 string
	memoryLimit              string
	diskLimit                string
	staticIP                 string
	containerImage           string
	enablePodman             bool
	labels                   []string
	forceRecreate            bool
	stackID                  string
	gpuDevice                string
	osTypeStr                string
	monitoring               bool
	createPool               string
	createBackendID          string
	createAutoRestartCompose string
	createGitSource          string
	createGitRef             string
	createGitCredentialFile  string
	createWorkspacePath      string
)

var createCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Create a new LXC container for a user",
	Long: `Create a new LXC container with Ubuntu + Podman support for the specified user.

The container will be created with:
  - Ubuntu 24.04 LTS (or specified image)
  - Podman and podman-compose installed
  - SSH server configured
  - User account with sudo privileges
  - Configurable resource limits
  - Optional software stack (nodejs, python, golang, rust, datascience, devops, database, fullstack)

Examples:
  # Create container with default settings
  containarium create alice --ssh-key ~/.ssh/id_rsa.pub

  # Create with custom resources and SSH key
  containarium create bob --ssh-key ~/.ssh/bob.pub --cpu 8 --memory 8GB --disk 100GB

  # Create with Node.js development stack
  containarium create charlie --ssh-key ~/.ssh/id_rsa.pub --stack nodejs

  # Create with full stack web development tools
  containarium create dave --ssh-key ~/.ssh/id_rsa.pub --stack fullstack

  # Create with labels
  containarium create charlie --ssh-key ~/.ssh/id_rsa.pub --labels team=dev,project=web

  # Force recreate if container already exists
  containarium create alice --ssh-key ~/.ssh/id_rsa.pub --force`,
	Args: cobra.ExactArgs(1),
	RunE: runCreate,
}

func init() {
	rootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVar(&sshKeyPath, "ssh-key", "", "Path to SSH public key file (REQUIRED for secure access)")
	createCmd.MarkFlagRequired("ssh-key") // SSH key is required for security
	createCmd.Flags().StringVar(&cpuLimit, "cpu", "4", "CPU limit (number of cores)")
	createCmd.Flags().StringVar(&memoryLimit, "memory", "4GB", "Memory limit (e.g., 4GB, 2048MB)")
	createCmd.Flags().StringVar(&diskLimit, "disk", "50GB", "Disk limit (e.g., 50GB, 100GB)")
	createCmd.Flags().StringVar(&staticIP, "static-ip", "", "Static IP address (e.g., 10.100.0.100) - empty for DHCP")
	createCmd.Flags().StringVar(&containerImage, "image", "images:ubuntu/24.04", "Container image to use")
	createCmd.Flags().BoolVar(&enablePodman, "podman", true, "Enable Podman support (nesting)")
	createCmd.Flags().StringVar(&stackID, "stack", "", "Software stack to install (nodejs, python, golang, rust, datascience, devops, database, fullstack)")
	createCmd.Flags().StringVar(&gpuDevice, "gpu", "", "GPU device ID for passthrough (e.g., '0' for first GPU, PCI address)")
	createCmd.Flags().StringSliceVar(&labels, "labels", []string{}, "Labels in key=value format (can be specified multiple times)")
	createCmd.Flags().BoolVar(&forceRecreate, "force", false, "Delete and recreate if container already exists")
	createCmd.Flags().StringVar(&osTypeStr, "os-type", "", "Container OS type: ubuntu, rocky9, rhel9 (overrides --image)")
	createCmd.Flags().BoolVar(&monitoring, "monitoring", false, "Opt into application-emitted OpenTelemetry. When set, the daemon stamps the container with OTEL_EXPORTER_OTLP_ENDPOINT etc. pointing at the platform's OTel collector, so any OTel SDK inside the container ships telemetry without app-side config. Default off.")
	createCmd.Flags().StringVar(&createPool, "pool", "", "Place the container on any healthy backend tagged with this pool (e.g., 'demo', 'lab'). Empty means the local/primary backend. Mutually exclusive with --backend-id unless the chosen backend is in the named pool.")
	createCmd.Flags().StringVar(&createBackendID, "backend-id", "", "Place the container on a specific backend by ID (e.g., 'tunnel-node-a-gpu'). Use 'containarium backends' to list available backend IDs.")
	createCmd.Flags().StringVar(&createAutoRestartCompose, "auto-restart-compose", "",
		"Path to a compose directory inside the new container; after create, "+
			"enable the systemd-user autostart unit for that stack so it "+
			"survives host reboots. Same as running "+
			"'containarium compose enable <username> --dir <path>' after "+
			"create. Requires --server (the daemon's ComposeAutostartService "+
			"backs the call). Best-effort — a failure to enable autostart "+
			"surfaces a warning but does NOT fail the overall create.")
	createCmd.Flags().StringVar(&createGitSource, "git-source", "", "Git clone URL to provision into the box's workspace at create time (e.g. https://github.com/org/repo). The daemon fetches it via incus exec — no SSH back to the box. Empty = no source provisioning.")
	createCmd.Flags().StringVar(&createGitRef, "git-ref", "", "Exact ref to check out for --git-source: full SHA (preferred), branch, tag, or refs/pull/N/merge. Empty = the remote's default branch.")
	createCmd.Flags().StringVar(&createGitCredentialFile, "git-credential-file", "", "Path to a file holding a bearer token for a private --git-source. Used daemon-side for one fetch; never written to the box's .git/config.")
	createCmd.Flags().StringVar(&createWorkspacePath, "workspace-path", "", "Where --git-source lands inside the box. Empty defaults to /workspace.")
}

func runCreate(cmd *cobra.Command, args []string) error {
	username := args[0]

	// --pool / --backend-id are placement directives that only the
	// daemon's PeerPool can act on. Local mode (no --server) doesn't
	// have a peer pool — fail fast rather than silently dropping them.
	if (createPool != "" || createBackendID != "") && serverAddr == "" {
		return fmt.Errorf("--pool and --backend-id require --server (cluster mode); they are not supported in local Incus mode")
	}

	// Parse labels from key=value format
	parsedLabels := parseLabels(labels)

	fmt.Printf("Creating container for user: %s\n", username)
	if verbose {
		fmt.Printf("  CPU: %s\n", cpuLimit)
		fmt.Printf("  Memory: %s\n", memoryLimit)
		fmt.Printf("  Disk: %s\n", diskLimit)
		if staticIP != "" {
			fmt.Printf("  Static IP: %s\n", staticIP)
		} else {
			fmt.Printf("  IP: DHCP\n")
		}
		fmt.Printf("  Image: %s\n", containerImage)
		fmt.Printf("  Podman enabled: %v\n", enablePodman)
		if stackID != "" {
			fmt.Printf("  Stack: %s\n", stackID)
		}
		if gpuDevice != "" {
			fmt.Printf("  GPU: %s\n", gpuDevice)
		}
		if len(parsedLabels) > 0 {
			fmt.Printf("  Labels:\n")
			for k, v := range parsedLabels {
				fmt.Printf("    %s=%s\n", k, v)
			}
		}
	}

	// Read SSH key (now required)
	// Expand home directory
	expandedPath := sshKeyPath
	if len(sshKeyPath) >= 2 && sshKeyPath[:2] == "~/" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		expandedPath = filepath.Join(homeDir, sshKeyPath[2:])
	}

	if verbose {
		fmt.Printf("  Reading SSH key from: %s\n", expandedPath)
	}

	keyBytes, err := os.ReadFile(expandedPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH key from %s: %w\nPlease ensure the file exists and is readable", expandedPath, err)
	}
	sshKey := string(keyBytes)
	sshKeys := []string{sshKey}

	// Handle --force flag: delete existing container if it exists
	if forceRecreate {
		if verbose {
			fmt.Println()
			fmt.Println("Checking if container already exists...")
		}

		// Check if container exists
		var containerExists bool
		if httpMode && serverAddr != "" {
			// Remote mode via HTTP
			httpClient, err := client.NewHTTPClient(serverAddr, authToken)
			if err != nil {
				return fmt.Errorf("failed to create HTTP client: %w", err)
			}
			defer httpClient.Close()

			_, err = httpClient.GetContainer(username)
			containerExists = (err == nil)
		} else if serverAddr != "" {
			// Remote mode via gRPC
			grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
			if err != nil {
				return fmt.Errorf("failed to connect to remote server: %w", err)
			}
			defer grpcClient.Close()

			_, err = grpcClient.GetContainer(username)
			containerExists = (err == nil)
		} else {
			// Local mode via Incus
			mgr, err := container.New()
			if err != nil {
				return fmt.Errorf("failed to connect to Incus: %w", err)
			}
			containerName := username + "-container"
			containerExists = mgr.ContainerExists(containerName)
		}

		if containerExists {
			fmt.Printf("Container for user '%s' already exists, deleting due to --force flag...\n", username)

			// Delete the container
			if httpMode && serverAddr != "" {
				// Remote mode via HTTP
				httpClient, err := client.NewHTTPClient(serverAddr, authToken)
				if err != nil {
					return fmt.Errorf("failed to create HTTP client: %w", err)
				}
				defer httpClient.Close()

				if err := httpClient.DeleteContainer(username, true); err != nil {
					return fmt.Errorf("failed to delete existing container: %w", err)
				}
			} else if serverAddr != "" {
				// Remote mode via gRPC
				grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
				if err != nil {
					return fmt.Errorf("failed to connect to remote server: %w", err)
				}
				defer grpcClient.Close()

				if err := grpcClient.DeleteContainer(username, true); err != nil {
					return fmt.Errorf("failed to delete existing container: %w", err)
				}
			} else {
				// Local mode via Incus
				if err := deleteLocal(username, true); err != nil {
					return fmt.Errorf("failed to delete existing container: %w", err)
				}
			}

			fmt.Println("✓ Existing container deleted")
			if verbose {
				fmt.Println()
			}
		} else if verbose {
			fmt.Println("Container does not exist, proceeding with creation...")
		}
	}

	// Create jump server account (only in local mode)
	// This creates a proxy-only user account with /usr/sbin/nologin shell
	// The account allows SSH ProxyJump but prevents direct shell access
	if serverAddr == "" {
		if verbose {
			fmt.Println()
			fmt.Println("Setting up jump server access...")
		}

		if err := container.CreateJumpServerAccount(username, sshKey, verbose); err != nil {
			return fmt.Errorf("failed to create jump server account: %w\nNote: This command must be run with sudo/root privileges", err)
		}

		if verbose {
			fmt.Println()
		}
	}

	// Create container - use remote or local mode
	var info *incus.ContainerInfo

	// Parse OS type from flag
	osType := ostype.OSTypeFromString(osTypeStr)

	// Resolve optional git-source provisioning from flags (reads the
	// credential file if one was given). Empty Source = no-op.
	gitOpts, err := resolveGitSourceOpts()
	if err != nil {
		return err
	}

	if httpMode && serverAddr != "" {
		// Remote mode via HTTP
		info, err = createRemoteHTTP(username, containerImage, cpuLimit, memoryLimit, diskLimit, sshKeys, enablePodman, stackID, gpuDevice, osType, monitoring, createPool, createBackendID, gitOpts)
		if err != nil {
			return fmt.Errorf("failed to create container via HTTP API: %w", err)
		}
	} else if serverAddr != "" {
		// Remote mode via gRPC
		info, err = createRemote(username, containerImage, cpuLimit, memoryLimit, diskLimit, sshKeys, enablePodman, stackID, gpuDevice, osType, monitoring, createPool, createBackendID, gitOpts)
		if err != nil {
			return fmt.Errorf("failed to create container via remote server: %w", err)
		}
	} else {
		// Local mode via Incus
		if verbose {
			fmt.Println("Creating container...")
		}
		info, err = createLocal(username, containerImage, cpuLimit, memoryLimit, diskLimit, staticIP, sshKeys, parsedLabels, enablePodman, stackID, gpuDevice, osType, monitoring, gitOpts)
		if err != nil {
			// Cleanup jump server account on failure
			_ = container.DeleteJumpServerAccount(username, false)
			return fmt.Errorf("failed to create container: %w", err)
		}
	}

	// Success!
	fmt.Println()
	fmt.Printf("✓ Container %s created successfully!\n", info.Name)
	if serverAddr == "" {
		fmt.Printf("✓ Jump server account: %s (proxy-only, no shell access)\n", username)
	}
	fmt.Println()
	fmt.Println("Container Information:")
	fmt.Printf("  Name:         %s\n", info.Name)
	fmt.Printf("  Username:     %s\n", username)
	fmt.Printf("  IP Address:   %s\n", info.IPAddress)
	fmt.Printf("  State:        %s\n", info.State)
	fmt.Printf("  CPU:          %s cores\n", info.CPU)
	fmt.Printf("  Memory:       %s\n", info.Memory)
	fmt.Printf("  Podman:       %v\n", enablePodman)
	if info.GPU != "" {
		fmt.Printf("  GPU:          %s\n", info.GPU)
	}
	fmt.Printf("  Auto-start:   enabled\n")
	if len(info.Labels) > 0 {
		fmt.Printf("  Labels:\n")
		for k, v := range info.Labels {
			fmt.Printf("    %s=%s\n", k, v)
		}
	}
	fmt.Println()

	if info.IPAddress != "" {
		fmt.Println("SSH Access (via ProxyJump):")
		fmt.Println()
		fmt.Println("Add to your ~/.ssh/config:")
		fmt.Println()
		fmt.Println("  Host containarium-jump")
		fmt.Println("      HostName <jump-server-ip>")
		fmt.Printf("      User %s\n", username)
		fmt.Println("      IdentityFile ~/.ssh/<your-private-key>")
		fmt.Println()
		fmt.Printf("  Host %s-dev\n", username)
		fmt.Printf("      HostName %s\n", info.IPAddress)
		fmt.Printf("      User %s\n", username)
		fmt.Println("      IdentityFile ~/.ssh/<your-private-key>")
		fmt.Println("      ProxyJump containarium-jump")
		fmt.Println()
		fmt.Printf("Then connect with: ssh %s-dev\n", username)
		fmt.Println()
		fmt.Println("Note: Your jump server account is proxy-only (no shell access).")
		fmt.Println("      This allows SSH ProxyJump while preventing direct access to the jump server.")
		fmt.Println()
	}

	// Phase D: --auto-restart-compose enables the systemd-user
	// autostart unit for a compose stack inside the new container.
	// Best-effort — print a warning on failure but do NOT fail the
	// overall create (the container is up and useful regardless).
	//
	// Requires --server: the call goes to the daemon's
	// ComposeAutostartService, which in turn execs `agent-box compose
	// enable` inside the LXC. Local mode (`createLocal`) talks to
	// Incus directly and has no such service; surface that as a
	// warning and skip rather than silently no-op.
	if createAutoRestartCompose != "" {
		if serverAddr == "" {
			fmt.Println("Warning: --auto-restart-compose is set but no --server provided; skipping (compose autostart requires the daemon RPC).")
		} else if err := enableAutoRestartCompose(username, createAutoRestartCompose); err != nil {
			fmt.Printf("Warning: container created but compose-autostart enable failed: %v\n", err)
			fmt.Printf("  Re-run later with: containarium compose enable %s --dir %s --server %s\n",
				username, createAutoRestartCompose, serverAddr)
		}
	}

	return nil
}

// enableAutoRestartCompose dials the daemon's ComposeAutostartService
// and Enables the autostart unit for the given dir inside `username`'s
// container. Returns nil on success OR on "already enabled" (which
// the daemon flags via Already=true; semantically a no-op, not a
// failure).
func enableAutoRestartCompose(username, dir string) error {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", serverAddr, err)
	}
	defer grpcClient.Close()

	c := pb.NewComposeAutostartServiceClient(grpcClient.Conn())
	resp, err := c.Enable(context.Background(), &pb.EnableRequest{
		Username: username,
		Dir:      dir,
		// Force false — first-time provision; if the unit already
		// exists (rare for a fresh box), respect it.
	})
	if err != nil {
		return err
	}
	if resp.GetAlready() {
		fmt.Printf("✓ Compose autostart: %s (already enabled)\n", resp.GetUnit())
	} else {
		fmt.Printf("✓ Compose autostart enabled: %s (compose=%s)\n", resp.GetUnit(), resp.GetComposeBin())
	}
	return nil
}

// resolveGitSourceOpts builds the git-source options from the create
// flags, reading the credential file if one was supplied. Returns the
// zero value (Source == "") when --git-source wasn't set.
func resolveGitSourceOpts() (client.GitSourceOpts, error) {
	if createGitSource == "" {
		return client.GitSourceOpts{}, nil
	}
	opts := client.GitSourceOpts{
		Source:        createGitSource,
		Ref:           createGitRef,
		WorkspacePath: createWorkspacePath,
	}
	if createGitCredentialFile != "" {
		// #nosec G304 -- operator-supplied path; reading it is the documented
		// purpose of --git-credential-file (same trust as reading an SSH key file).
		data, err := os.ReadFile(createGitCredentialFile)
		if err != nil {
			return client.GitSourceOpts{}, fmt.Errorf("failed to read --git-credential-file: %w", err)
		}
		opts.Credential = strings.TrimSpace(string(data))
	}
	return opts, nil
}

// createLocal creates a container using local Incus daemon
func createLocal(username, image, cpu, memory, disk, staticIP string, sshKeys []string, labelMap map[string]string, enablePodman bool, stack, gpu string, osType pb.OSType, monitoring bool, git client.GitSourceOpts) (*incus.ContainerInfo, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	opts := container.CreateOptions{
		Username:               username,
		Image:                  image,
		CPU:                    cpu,
		Memory:                 memory,
		Disk:                   disk,
		GPU:                    gpu,
		StaticIP:               staticIP,
		SSHKeys:                sshKeys,
		Labels:                 labelMap,
		EnablePodman:           enablePodman,
		EnablePodmanPrivileged: enablePodman, // Enable privileged mode for proper Podman-in-LXC
		AutoStart:              true,
		Verbose:                verbose,
		Stack:                  stack,
		OSType:                 osType,
		Monitoring:             monitoring,
		GitSource:              git.Source,
		GitRef:                 git.Ref,
		GitCredential:          git.Credential,
		WorkspacePath:          git.WorkspacePath,
	}

	return mgr.Create(opts)
}

// parseLabels parses labels from key=value format
func parseLabels(labelSlice []string) map[string]string {
	result := make(map[string]string)
	for _, label := range labelSlice {
		parts := strings.SplitN(label, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" {
				result[key] = value
			}
		}
	}
	return result
}

// createRemote creates a container using remote gRPC server
func createRemote(username, image, cpu, memory, disk string, sshKeys []string, enablePodman bool, stack, gpu string, osType pb.OSType, monitoring bool, pool, backendID string, git client.GitSourceOpts) (*incus.ContainerInfo, error) {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer grpcClient.Close()

	return grpcClient.CreateContainer(username, image, cpu, memory, disk, sshKeys, enablePodman, stack, gpu, osType, monitoring, pool, backendID, git)
}

// createRemoteHTTP creates a container using remote HTTP API
func createRemoteHTTP(username, image, cpu, memory, disk string, sshKeys []string, enablePodman bool, stack, gpu string, osType pb.OSType, monitoring bool, pool, backendID string, git client.GitSourceOpts) (*incus.ContainerInfo, error) {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return nil, err
	}
	defer httpClient.Close()

	return httpClient.CreateContainer(username, image, cpu, memory, disk, sshKeys, enablePodman, stack, gpu, osType, monitoring, pool, backendID, git)
}
