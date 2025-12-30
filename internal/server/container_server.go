package server

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ContainerServer implements the gRPC ContainerService
type ContainerServer struct {
	pb.UnimplementedContainerServiceServer
	manager *container.Manager
}

// NewContainerServer creates a new container server
func NewContainerServer() (*ContainerServer, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create container manager: %w", err)
	}
	return &ContainerServer{manager: mgr}, nil
}

// CreateContainer creates a new container
func (s *ContainerServer) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	// Validate request
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Build create options
	opts := container.CreateOptions{
		Username:     req.Username,
		Image:        req.Image,
		SSHKeys:      req.SshKeys,
		EnableDocker: req.EnableDocker,
		AutoStart:    true,
	}

	// Set resource limits
	if req.Resources != nil {
		opts.CPU = req.Resources.Cpu
		opts.Memory = req.Resources.Memory
		opts.Disk = req.Resources.Disk
	}

	// Use defaults if not specified
	if opts.Image == "" {
		opts.Image = "ubuntu:24.04"
	}
	if opts.CPU == "" {
		opts.CPU = "4"
	}
	if opts.Memory == "" {
		opts.Memory = "4GB"
	}
	if opts.Disk == "" {
		opts.Disk = "50GB"
	}

	// Create the container
	info, err := s.manager.Create(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Convert to protobuf
	container := toProtoContainer(info)

	return &pb.CreateContainerResponse{
		Container:  container,
		Message:    fmt.Sprintf("Container %s created successfully", info.Name),
		SshCommand: fmt.Sprintf("ssh %s@%s", req.Username, info.IPAddress),
	}, nil
}

// ListContainers lists all containers
func (s *ContainerServer) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	containers, err := s.manager.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Filter containers
	var filtered []incus.ContainerInfo
	for _, c := range containers {
		// Filter by username if specified
		if req.Username != "" {
			// Extract username from container name (format: username-container)
			username := c.Name
			if len(c.Name) > 10 && c.Name[len(c.Name)-10:] == "-container" {
				username = c.Name[:len(c.Name)-10]
			}
			if username != req.Username {
				continue
			}
		}

		// TODO: Filter by state and labels

		filtered = append(filtered, c)
	}

	// Convert to protobuf
	var protoContainers []*pb.Container
	for i := range filtered {
		protoContainers = append(protoContainers, toProtoContainer(&filtered[i]))
	}

	return &pb.ListContainersResponse{
		Containers: protoContainers,
		TotalCount: int32(len(protoContainers)),
	}, nil
}

// GetContainer gets information about a specific container
func (s *ContainerServer) GetContainer(ctx context.Context, req *pb.GetContainerRequest) (*pb.GetContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	info, err := s.manager.Get(req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	return &pb.GetContainerResponse{
		Container: toProtoContainer(info),
		// TODO: Add metrics
	}, nil
}

// DeleteContainer deletes a container
func (s *ContainerServer) DeleteContainer(ctx context.Context, req *pb.DeleteContainerRequest) (*pb.DeleteContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	err := s.manager.Delete(req.Username, req.Force)
	if err != nil {
		return nil, fmt.Errorf("failed to delete container: %w", err)
	}

	return &pb.DeleteContainerResponse{
		Message:       fmt.Sprintf("Container for user %s deleted successfully", req.Username),
		ContainerName: fmt.Sprintf("%s-container", req.Username),
	}, nil
}

// StartContainer starts a stopped container
func (s *ContainerServer) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*pb.StartContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// TODO: Implement start in container manager
	return nil, fmt.Errorf("not implemented yet")
}

// StopContainer stops a running container
func (s *ContainerServer) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*pb.StopContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// TODO: Implement stop in container manager
	return nil, fmt.Errorf("not implemented yet")
}

// AddSSHKey adds an SSH key to a container
func (s *ContainerServer) AddSSHKey(ctx context.Context, req *pb.AddSSHKeyRequest) (*pb.AddSSHKeyResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}

	// TODO: Implement SSH key management
	return nil, fmt.Errorf("not implemented yet")
}

// RemoveSSHKey removes an SSH key from a container
func (s *ContainerServer) RemoveSSHKey(ctx context.Context, req *pb.RemoveSSHKeyRequest) (*pb.RemoveSSHKeyResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.SshPublicKey == "" {
		return nil, fmt.Errorf("ssh_public_key is required")
	}

	// TODO: Implement SSH key management
	return nil, fmt.Errorf("not implemented yet")
}

// GetMetrics gets runtime metrics for containers
func (s *ContainerServer) GetMetrics(ctx context.Context, req *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	// TODO: Implement metrics collection
	return nil, fmt.Errorf("not implemented yet")
}

// GetSystemInfo gets information about the Incus host
func (s *ContainerServer) GetSystemInfo(ctx context.Context, req *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	// Get basic system info from container manager
	containers, err := s.manager.List()
	if err != nil {
		return nil, fmt.Errorf("failed to get containers: %w", err)
	}

	// Count running/stopped containers
	var running, stopped int32
	for _, c := range containers {
		if c.State == "Running" {
			running++
		} else {
			stopped++
		}
	}

	// Get Incus server info
	client, err := incus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w", err)
	}

	serverInfo, err := client.GetServerInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}

	// Build response
	info := &pb.SystemInfo{
		IncusVersion:       serverInfo.Environment.ServerVersion,
		Os:                 serverInfo.Environment.OSName,
		KernelVersion:      serverInfo.Environment.KernelVersion,
		ContainersRunning:  running,
		ContainersStopped:  stopped,
		ContainersTotal:    int32(len(containers)),
		Hostname:           serverInfo.Environment.ServerName,
		// TODO: Add more system info (CPU count, memory, disk, uptime)
	}

	return &pb.GetSystemInfoResponse{
		Info: info,
	}, nil
}

// toProtoContainer converts internal container info to protobuf
func toProtoContainer(info *incus.ContainerInfo) *pb.Container {
	// Parse state
	var state pb.ContainerState
	switch info.State {
	case "Running":
		state = pb.ContainerState_CONTAINER_STATE_RUNNING
	case "Stopped":
		state = pb.ContainerState_CONTAINER_STATE_STOPPED
	case "Frozen":
		state = pb.ContainerState_CONTAINER_STATE_FROZEN
	default:
		state = pb.ContainerState_CONTAINER_STATE_UNSPECIFIED
	}

	// Extract username from container name (format: username-container)
	username := info.Name
	if len(info.Name) > 10 && info.Name[len(info.Name)-10:] == "-container" {
		username = info.Name[:len(info.Name)-10]
	}

	return &pb.Container{
		Name:     info.Name,
		Username: username,
		State:    state,
		Resources: &pb.ResourceLimits{
			Cpu:    info.CPU,
			Memory: info.Memory,
		},
		Network: &pb.NetworkInfo{
			IpAddress: info.IPAddress,
		},
		CreatedAt:     info.CreatedAt.Unix(),
		DockerEnabled: true, // TODO: Get from container config
	}
}
