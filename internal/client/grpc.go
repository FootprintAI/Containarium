package client

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/mtls"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCClient wraps a gRPC connection to the containarium daemon
type GRPCClient struct {
	conn   *grpc.ClientConn
	client pb.ContainerServiceClient
}

// NewGRPCClient creates a new gRPC client
func NewGRPCClient(serverAddr string, certsDir string, insecureConn bool) (*GRPCClient, error) {
	var opts []grpc.DialOption

	if insecureConn {
		// Insecure connection (not recommended)
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// Use mTLS
		if certsDir == "" {
			// Default to ~/.config/containarium/certs
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get home directory: %w", err)
			}
			certsDir = filepath.Join(homeDir, ".config", "containarium", "certs")
		}

		// Load certificates
		paths := mtls.CertPaths{
			CACert:     filepath.Join(certsDir, "ca.crt"),
			ClientCert: filepath.Join(certsDir, "client.crt"),
			ClientKey:  filepath.Join(certsDir, "client.key"),
		}

		// Check if certificates exist
		if _, err := os.Stat(paths.CACert); os.IsNotExist(err) {
			return nil, fmt.Errorf("CA certificate not found at %s\nPlease download certificates from the server:\n  gcloud compute scp SERVER:/etc/containarium/certs/ca.crt %s\n  gcloud compute scp SERVER:/etc/containarium/certs/client.crt %s\n  gcloud compute scp SERVER:/etc/containarium/certs/client.key %s",
				paths.CACert, paths.CACert, paths.ClientCert, paths.ClientKey)
		}

		// Load client dial options
		dialOpts, err := mtls.LoadClientDialOptions(paths, serverAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, dialOpts...)
	}

	// Connect to server
	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial server: %w", err)
	}

	// Create client
	client := pb.NewContainerServiceClient(conn)

	return &GRPCClient{
		conn:   conn,
		client: client,
	}, nil
}

// Close closes the gRPC connection
func (c *GRPCClient) Close() error {
	return c.conn.Close()
}

// ListContainers lists all containers via gRPC
func (c *GRPCClient) ListContainers() ([]incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.ListContainers(ctx, &pb.ListContainersRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Convert protobuf response to incus.ContainerInfo
	var containers []incus.ContainerInfo
	for _, container := range resp.Containers {
		info := incus.ContainerInfo{
			Name:  container.Name,
			State: container.State.String(),
		}

		// Get IP address from network info
		if container.Network != nil {
			info.IPAddress = container.Network.IpAddress
		}

		// Get resource limits
		if container.Resources != nil {
			info.CPU = container.Resources.Cpu
			info.Memory = container.Resources.Memory
		}

		// Convert Unix timestamp to time.Time
		if container.CreatedAt > 0 {
			info.CreatedAt = time.Unix(container.CreatedAt, 0)
		}

		containers = append(containers, info)
	}

	return containers, nil
}

// CreateContainer creates a container via gRPC
func (c *GRPCClient) CreateContainer(username, image, cpu, memory, disk string, sshKeys []string, enableDocker bool) (*incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // Container creation can take time
	defer cancel()

	req := &pb.CreateContainerRequest{
		Username: username,
		Resources: &pb.ResourceLimits{
			Cpu:    cpu,
			Memory: memory,
			Disk:   disk,
		},
		SshKeys:      sshKeys,
		Image:        image,
		EnableDocker: enableDocker,
	}

	resp, err := c.client.CreateContainer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Convert protobuf Container to incus.ContainerInfo
	container := resp.Container
	info := &incus.ContainerInfo{
		Name:  container.Name,
		State: container.State.String(),
	}

	if container.Network != nil {
		info.IPAddress = container.Network.IpAddress
	}

	if container.Resources != nil {
		info.CPU = container.Resources.Cpu
		info.Memory = container.Resources.Memory
	}

	if container.CreatedAt > 0 {
		info.CreatedAt = time.Unix(container.CreatedAt, 0)
	}

	return info, nil
}

// DeleteContainer deletes a container via gRPC
func (c *GRPCClient) DeleteContainer(username string, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &pb.DeleteContainerRequest{
		Username: username,
		Force:    force,
	}

	_, err := c.client.DeleteContainer(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}

	return nil
}

// GetContainer gets information about a specific container via gRPC
func (c *GRPCClient) GetContainer(username string) (*incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &pb.GetContainerRequest{
		Username: username,
	}

	resp, err := c.client.GetContainer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	// Convert protobuf Container to incus.ContainerInfo
	container := resp.Container
	info := &incus.ContainerInfo{
		Name:  container.Name,
		State: container.State.String(),
	}

	if container.Network != nil {
		info.IPAddress = container.Network.IpAddress
	}

	if container.Resources != nil {
		info.CPU = container.Resources.Cpu
		info.Memory = container.Resources.Memory
	}

	if container.CreatedAt > 0 {
		info.CreatedAt = time.Unix(container.CreatedAt, 0)
	}

	return info, nil
}

// GetSystemInfo gets system information via gRPC
func (c *GRPCClient) GetSystemInfo() (*incus.ServerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.GetSystemInfo(ctx, &pb.GetSystemInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}

	// Convert to incus.ServerInfo
	info := &incus.ServerInfo{
		Version:       resp.Info.IncusVersion,
		KernelVersion: resp.Info.KernelVersion,
	}

	return info, nil
}
