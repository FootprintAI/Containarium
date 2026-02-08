package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/spf13/cobra"
)

var (
	sshKeyPath     string
	cpuLimit       string
	memoryLimit    string
	diskLimit      string
	staticIP       string
	containerImage string
	enableDocker   bool
	labels         []string
	forceRecreate  bool
)

var createCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Create a new LXC container for a user",
	Long: `Create a new LXC container with Ubuntu + Docker support for the specified user.

The container will be created with:
  - Ubuntu 24.04 LTS (or specified image)
  - Docker and docker-compose installed
  - SSH server configured
  - User account with sudo privileges
  - Configurable resource limits

Examples:
  # Create container with default settings
  containarium create alice --ssh-key ~/.ssh/id_rsa.pub

  # Create with custom resources and SSH key
  containarium create bob --ssh-key ~/.ssh/bob.pub --cpu 8 --memory 8GB --disk 100GB

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
	createCmd.Flags().BoolVar(&enableDocker, "docker", true, "Enable Docker support (nesting)")
	createCmd.Flags().StringSliceVar(&labels, "labels", []string{}, "Labels in key=value format (can be specified multiple times)")
	createCmd.Flags().BoolVar(&forceRecreate, "force", false, "Delete and recreate if container already exists")
}

func runCreate(cmd *cobra.Command, args []string) error {
	username := args[0]

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
		fmt.Printf("  Docker enabled: %v\n", enableDocker)
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

	if httpMode && serverAddr != "" {
		// Remote mode via HTTP 
		info, err = createRemoteHTTP(username, containerImage, cpuLimit, memoryLimit, diskLimit, sshKeys, enableDocker)
		if err != nil {
			return fmt.Errorf("failed to create container via HTTP API: %w", err)
		}
	} else if serverAddr != "" {
		// Remote mode via gRPC 
		info, err = createRemote(username, containerImage, cpuLimit, memoryLimit, diskLimit, sshKeys, enableDocker)
		if err != nil {
			return fmt.Errorf("failed to create container via remote server: %w", err)
		}
	} else {
		// Local mode via Incus
		if verbose {
			fmt.Println("Creating container...")
		}
		info, err = createLocal(username, containerImage, cpuLimit, memoryLimit, diskLimit, staticIP, sshKeys, parsedLabels, enableDocker)
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
	fmt.Printf("  Docker:       %v\n", enableDocker)
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

	return nil
}

// createLocal creates a container using local Incus daemon
func createLocal(username, image, cpu, memory, disk, staticIP string, sshKeys []string, labelMap map[string]string, enableDocker bool) (*incus.ContainerInfo, error) {
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
		StaticIP:               staticIP,
		SSHKeys:                sshKeys,
		Labels:                 labelMap,
		EnableDocker:           enableDocker,
		EnableDockerPrivileged: enableDocker, // Enable privileged mode for proper Docker-in-Docker
		AutoStart:              true,
		Verbose:                verbose,
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
func createRemote(username, image, cpu, memory, disk string, sshKeys []string, enableDocker bool) (*incus.ContainerInfo, error) {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer grpcClient.Close()

	return grpcClient.CreateContainer(username, image, cpu, memory, disk, sshKeys, enableDocker)
}

// createRemoteHTTP creates a container using remote HTTP API 
func createRemoteHTTP(username, image, cpu, memory, disk string, sshKeys []string, enableDocker bool) (*incus.ContainerInfo, error) {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return nil, err
	}
	defer httpClient.Close()

	return httpClient.CreateContainer(username, image, cpu, memory, disk, sshKeys, enableDocker)
}
